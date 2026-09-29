import unittest
import threading
from collections import Counter
from dataclasses import replace

from aak import (
    AuthorityAttestation, AuthorityBundle, DispatchCapability, DownstreamEnforcer,
    Ed25519Signer, EffectReceiptIssuer, EnforcementGateway, ExternalAuditAnchor,
    IndependentAuthority, KeyRegistry, KeyStatus, Proposal, SenderProofVerifier,
    ThresholdVerifier, ToolContract, create_sender_proof, make_authority_claim,
    ExternalPolicyIssuer, ExternalPolicyVerifier,
    WorkloadIdentityIssuer, WorkloadIdentityVerifier,
)
from aak.canonical import canonical_bytes
from aak.crypto import b64encode


class FederatedSecurityTests(unittest.TestCase):
    def setUp(self):
        self.effects = []
        self.proposal = Proposal(
            "tx-1", "glenn", "model-host", "pay invoice", "payment.transfer",
            "account/vendor", {"amount": 10}, {"money": 10, "operations": 1},
            ("invoice-1",), ("reviewer",),
        )
        self.authority_keys = [Ed25519Signer.generate() for _ in range(3)]
        evaluator = lambda proposal: (
            proposal.action == "payment.transfer"
            and proposal.resource == "account/vendor"
            and proposal.parameters.get("amount", 10_000) <= 100
            and proposal.evidence == ("invoice-1",)
        )
        self.authorities = [IndependentAuthority(key, evaluator) for key in self.authority_keys]
        self.threshold = ThresholdVerifier(self.authority_keys, 2)
        self.gateway_key = Ed25519Signer.generate()
        self.gateway = EnforcementGateway(
            self.gateway_key, self.threshold, "payments-prod",
            expected_policy_hash="policy-sha256", expected_system_version="v0.5",
            allow_test_time_override=True,
        )
        self.anchor_key = Ed25519Signer.generate()
        self.anchor = ExternalAuditAnchor(self.anchor_key)
        self.receipt_key = Ed25519Signer.generate()
        self.receipt_registry = KeyRegistry((KeyStatus(self.receipt_key, 90, 200),))
        tool = ToolContract(
            "payment.transfer",
            lambda resource, params: resource == "account/vendor" and set(params) == {"amount"},
            lambda _resource, params: {"money": float(params["amount"]), "operations": 1.0},
            lambda resource, params: self.effects.append((resource, params["amount"])) or {"settled": True},
        )
        self.downstream = DownstreamEnforcer(
            gateway_verifier=self.gateway_key, authorities=self.threshold,
            anchor=self.anchor, anchor_verifier=self.anchor_key,
            expected_workload_identity="executor-prod", audience="payments-prod",
            tools=(tool,), principal_limits={"money": 100, "operations": 20},
            global_limits={"money": 150, "operations": 10},
            expected_policy_hash="policy-sha256", expected_system_version="v0.5",
            allow_test_time_override=True,
            receipt_issuer=EffectReceiptIssuer(self.receipt_key),
        )

    def bundle(self, proposal=None, signers=(0, 1)):
        proposal = proposal or self.proposal
        claim = make_authority_claim(
            proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
        )
        attestations = tuple(
            attestation
            for index in signers
            if (attestation := self.authorities[index].attest(proposal, claim)) is not None
        )
        return AuthorityBundle(claim, attestations)

    def dispatch(self, proposal=None, bundle=None):
        proposal = proposal or self.proposal
        bundle = bundle or self.bundle(proposal)
        return self.gateway.dispatch(proposal, bundle, now=101)

    def execute(self, proposal=None, bundle=None, dispatch=None, identity="executor-prod"):
        proposal = proposal or self.proposal
        bundle = bundle or self.bundle(proposal)
        dispatch = dispatch or self.dispatch(proposal, bundle)
        return self.downstream.execute(
            proposal, bundle, dispatch, workload_identity=identity, now=101,
        )

    def test_valid_quorum_executes_once(self):
        result = self.execute()
        self.assertTrue(result.allowed)
        self.assertTrue(EffectReceiptIssuer.verify(result.receipt, self.receipt_registry, now=101))
        self.assertEqual(self.effects, [("account/vendor", 10)])

    def test_one_compromised_signer_cannot_authorize(self):
        bundle = self.bundle(signers=(0,))
        self.assertIsNone(self.gateway.dispatch(self.proposal, bundle, now=101))
        self.assertEqual(self.effects, [])

    def test_compromised_gateway_cannot_bypass_authority_quorum(self):
        bundle = self.bundle(signers=(0,))
        claim = {
            "v": 2, "bundle_hash": "forged", "proposal_hash": bundle.claim["proposal_hash"],
            "nonce": bundle.claim["nonce"], "audience": "payments-prod", "expires_at": 110,
        }
        forged = DispatchCapability(claim, self.gateway_key.key_id, b64encode(self.gateway_key.sign(canonical_bytes(claim))))
        result = self.downstream.execute(self.proposal, bundle, forged, workload_identity="executor-prod", now=101)
        self.assertEqual(result.reason, "insufficient_authority_quorum")
        self.assertEqual(self.effects, [])

    def test_compromised_executor_cannot_change_effect(self):
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        changed = replace(self.proposal, parameters={"amount": 1000}, maximum_effect={"money": 1000, "operations": 1})
        result = self.downstream.execute(changed, bundle, dispatch, workload_identity="executor-prod", now=101)
        self.assertEqual(result.reason, "authority_contract_mismatch")
        self.assertEqual(self.effects, [])

    def test_stolen_workload_identity_without_capability_is_useless(self):
        bundle = self.bundle(signers=(0,))
        fake = DispatchCapability({}, self.gateway_key.key_id, "invalid")
        result = self.downstream.execute(self.proposal, bundle, fake, workload_identity="executor-prod", now=101)
        self.assertEqual(result.reason, "insufficient_authority_quorum")
        self.assertEqual(self.effects, [])

    def test_wrong_workload_identity_denied(self):
        self.assertEqual(self.execute(identity="attacker").reason, "wrong_workload_identity")
        self.assertEqual(self.effects, [])

    def test_malformed_proposal_fails_closed_without_exception(self):
        claim = make_authority_claim(
            self.proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
        )
        bundle = AuthorityBundle(claim, ())
        self.assertIsNone(self.authorities[0].attest(object(), claim))
        self.assertIsNone(self.gateway.dispatch(object(), bundle, now=101))
        result = self.downstream.execute(
            object(), bundle, DispatchCapability({}, self.gateway_key.key_id, "invalid"),
            workload_identity="executor-prod", now=101,
        )
        self.assertFalse(result.allowed)

    def test_malformed_bundle_dispatch_and_attestation_fail_closed(self):
        dispatch = self.dispatch()
        self.assertFalse(self.threshold.verify(object()))
        malformed_attestations = AuthorityBundle(self.bundle().claim, (object(),))
        self.assertFalse(self.threshold.verify(malformed_attestations))
        self.assertEqual(
            self.downstream.execute(
                self.proposal, object(), dispatch,
                workload_identity="executor-prod", now=101,
            ).reason,
            "malformed_authority_bundle",
        )
        self.assertEqual(
            self.downstream.execute(
                self.proposal, self.bundle(), object(),
                workload_identity="executor-prod", now=101,
            ).reason,
            "malformed_dispatch_capability",
        )

    def test_authority_evaluator_and_tenant_resolver_exceptions_fail_closed(self):
        key = Ed25519Signer.generate()
        broken_evaluator = IndependentAuthority(key, lambda _proposal: 1 / 0)
        broken_tenant = IndependentAuthority(
            key, lambda _proposal: True,
            tenant_resolver=lambda _proposal: (_ for _ in ()).throw(RuntimeError("resolver unavailable")),
        )
        claim = make_authority_claim(
            self.proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
        )
        self.assertIsNone(broken_evaluator.attest(self.proposal, claim))
        self.assertIsNone(broken_tenant.attest(self.proposal, claim))

    def test_closed_state_store_fails_closed_without_effect(self):
        self.downstream.store.db.close()
        result = self.execute()
        self.assertEqual(result.reason, "state_store_unavailable")
        self.assertEqual(self.effects, [])

    def test_replay_is_denied_downstream(self):
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        self.assertTrue(self.execute(bundle=bundle, dispatch=dispatch).allowed)
        self.assertEqual(self.execute(bundle=bundle, dispatch=dispatch).reason, "replay")
        self.assertEqual(len(self.effects), 1)

    def test_configured_external_assurance_is_mandatory_and_executes_when_valid(self):
        policy_key = Ed25519Signer.generate()
        identity_key = Ed25519Signer.generate()
        self.downstream.external_policy_verifier = ExternalPolicyVerifier(
            policy_key, audience="payments-prod", expected_policy_hash="policy-sha256",
        )
        self.downstream.workload_identity_verifier = WorkloadIdentityVerifier(
            identity_key, expected_spiffe_id="executor-prod",
            trust_domain="example.org", audience="payments-prod",
        )
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        missing = self.downstream.execute(
            self.proposal, bundle, dispatch, workload_identity="executor-prod", now=101,
        )
        self.assertEqual(missing.reason, "workload_identity_assertion_required")
        identity = WorkloadIdentityIssuer(identity_key).issue(
            assertion_id="identity-1",
            spiffe_id="executor-prod", trust_domain="example.org", audience="payments-prod",
            certificate_fingerprint="sha256:trusted-cert", channel_binding="direct-channel-1",
            issued_at=100, expires_at=110,
        )
        policy = ExternalPolicyIssuer(policy_key).issue(
            decision_id="pdp-1", proposal=self.proposal, allowed=True,
            policy_hash="policy-sha256", policy_revision=1,
            audience="payments-prod", issued_at=100, expires_at=110,
        )
        result = self.downstream.execute(
            self.proposal, bundle, dispatch, workload_identity="executor-prod",
            policy_decision=policy, identity_assertion=identity,
            channel_binding="direct-channel-1", now=101,
        )
        self.assertTrue(result.allowed)
        self.assertEqual(len(self.effects), 1)

    def test_external_policy_cannot_be_reused_for_changed_proposal(self):
        policy_key = Ed25519Signer.generate()
        self.downstream.external_policy_verifier = ExternalPolicyVerifier(
            policy_key, audience="payments-prod", expected_policy_hash="policy-sha256",
        )
        changed = replace(self.proposal, transaction_id="tx-changed")
        policy = ExternalPolicyIssuer(policy_key).issue(
            decision_id="pdp-1", proposal=self.proposal, allowed=True,
            policy_hash="policy-sha256", policy_revision=1,
            audience="payments-prod", issued_at=100, expires_at=110,
        )
        bundle = self.bundle(changed)
        result = self.downstream.execute(
            changed, bundle, self.dispatch(changed, bundle),
            workload_identity="executor-prod", policy_decision=policy, now=101,
        )
        self.assertEqual(result.reason, "policy_input_mismatch")
        self.assertEqual(self.effects, [])

    def test_invalid_dispatch_cannot_consume_valid_external_assurance(self):
        policy_key = Ed25519Signer.generate()
        identity_key = Ed25519Signer.generate()
        self.downstream.external_policy_verifier = ExternalPolicyVerifier(
            policy_key, audience="payments-prod", expected_policy_hash="policy-sha256",
        )
        self.downstream.workload_identity_verifier = WorkloadIdentityVerifier(
            identity_key, expected_spiffe_id="executor-prod",
            trust_domain="example.org", audience="payments-prod",
        )
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        policy = ExternalPolicyIssuer(policy_key).issue(
            decision_id="pdp-unconsumed", proposal=self.proposal, allowed=True,
            policy_hash="policy-sha256", policy_revision=1,
            audience="payments-prod", issued_at=100, expires_at=110,
        )
        identity = WorkloadIdentityIssuer(identity_key).issue(
            assertion_id="identity-unconsumed", spiffe_id="executor-prod",
            trust_domain="example.org", audience="payments-prod",
            certificate_fingerprint="sha256:trusted", channel_binding="direct-a",
            issued_at=100, expires_at=110,
        )
        forged = replace(dispatch, gateway_signature="invalid")
        denied = self.downstream.execute(
            self.proposal, bundle, forged, workload_identity="executor-prod",
            policy_decision=policy, identity_assertion=identity,
            channel_binding="direct-a", now=101,
        )
        self.assertEqual(denied.reason, "invalid_gateway_signature")
        accepted = self.downstream.execute(
            self.proposal, bundle, dispatch, workload_identity="executor-prod",
            policy_decision=policy, identity_assertion=identity,
            channel_binding="direct-a", now=101,
        )
        self.assertTrue(accepted.allowed)

    def test_expired_bundle_denied_by_gateway_and_downstream(self):
        bundle = self.bundle()
        self.assertIsNone(self.gateway.dispatch(self.proposal, bundle, now=110))
        dispatch = self.dispatch(bundle=bundle)
        result = self.downstream.execute(self.proposal, bundle, dispatch, workload_identity="executor-prod", now=110)
        self.assertEqual(result.reason, "expired_or_invalid_time")

    def test_external_anchor_rollback_stops_next_effect(self):
        self.assertTrue(self.execute().allowed)
        self.anchor._events.pop()  # simulate restoration of an older anchor snapshot
        second = replace(self.proposal, transaction_id="tx-2")
        bundle = self.bundle(second)
        dispatch = self.dispatch(second, bundle)
        result = self.downstream.execute(second, bundle, dispatch, workload_identity="executor-prod", now=101)
        self.assertEqual(result.reason, "audit_anchor_rollback_or_tamper")
        self.assertEqual(len(self.effects), 1)

    def test_duplicate_attestation_does_not_form_quorum(self):
        bundle = self.bundle(signers=(0,))
        duplicated = AuthorityBundle(bundle.claim, (bundle.attestations[0], bundle.attestations[0]))
        self.assertFalse(self.threshold.verify(duplicated))

    def test_global_budget_spans_principals(self):
        first = replace(self.proposal, parameters={"amount": 100}, maximum_effect={"money": 100, "operations": 1})
        bundle1 = self.bundle(first)
        self.assertTrue(self.execute(first, bundle1, self.dispatch(first, bundle1)).allowed)
        second = replace(self.proposal, transaction_id="tx-2", principal_id="marina", parameters={"amount": 60}, maximum_effect={"money": 60, "operations": 1})
        bundle2 = self.bundle(second)
        result = self.execute(second, bundle2, self.dispatch(second, bundle2))
        self.assertEqual(result.reason, "budget_exceeded:global:money")
        self.assertEqual(len(self.effects), 1)

    def test_audit_tampering_stops_next_effect(self):
        self.assertTrue(self.execute().allowed)
        self.anchor._events[0]["event"] = {"type": "forged"}
        self.assertFalse(self.downstream.verify_full_audit_integrity())
        self.anchor._events[-1]["signature"] = "forged"
        second = replace(self.proposal, transaction_id="tx-2")
        bundle = self.bundle(second)
        dispatch = self.dispatch(second, bundle)
        result = self.downstream.execute(second, bundle, dispatch, workload_identity="executor-prod", now=101)
        self.assertEqual(result.reason, "audit_anchor_rollback_or_tamper")
        self.assertEqual(len(self.effects), 1)

    def test_unexpected_policy_or_system_version_denied(self):
        bundle = self.bundle()
        altered_claim = dict(bundle.claim, policy_hash="attacker-policy")
        altered = AuthorityBundle(
            altered_claim,
            tuple(AuthorityAttestation(key.key_id, b64encode(key.sign(canonical_bytes(altered_claim)))) for key in self.authority_keys[:2]),
        )
        self.assertIsNone(self.gateway.dispatch(self.proposal, altered, now=101))

    def test_production_services_reject_caller_time(self):
        gateway = EnforcementGateway(
            self.gateway_key, self.threshold, "payments-prod",
            expected_policy_hash="policy-sha256", expected_system_version="v0.5",
        )
        with self.assertRaisesRegex(ValueError, "caller-supplied time"):
            gateway.dispatch(self.proposal, self.bundle(), now=101)

    def test_federated_test_time_rejects_boolean_negative_and_text(self):
        for invalid in (True, -1, "101"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "invalid trusted time"):
                self.gateway.dispatch(self.proposal, self.bundle(), now=invalid)

    def test_anchor_outage_before_effect_fails_closed(self):
        self.anchor.append = lambda _event: (_ for _ in ()).throw(OSError("offline"))
        result = self.execute()
        self.assertEqual(result.reason, "audit_anchor_unavailable_workload_quarantined")
        self.assertEqual(self.effects, [])
        self.assertTrue(self.downstream.store.is_quarantined("executor-prod"))

    def test_anchor_outage_after_effect_reports_commit_and_quarantines(self):
        original_append = self.anchor.append
        calls = 0

        def fail_second(event):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("offline")
            return original_append(event)

        self.anchor.append = fail_second
        result = self.execute()
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "executed_but_anchor_incomplete_workload_quarantined")
        self.assertEqual(len(self.effects), 1)
        self.assertTrue(self.downstream.store.is_quarantined("executor-prod"))

    def test_concurrent_distinct_effects_preserve_latest_anchor(self):
        work = []
        for index in range(10):
            proposal = replace(self.proposal, transaction_id=f"tx-{index}")
            bundle = self.bundle(proposal)
            work.append((proposal, bundle, self.dispatch(proposal, bundle)))
        results = []

        def execute(item):
            proposal, bundle, dispatch = item
            results.append(self.downstream.execute(
                proposal, bundle, dispatch, workload_identity="executor-prod", now=101,
            ))

        threads = [threading.Thread(target=execute, args=(item,)) for item in work]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(result.allowed for result in results), 10, Counter(result.reason for result in results))
        self.assertTrue(self.anchor.verify_chain())
        self.assertEqual(self.downstream._last_anchor.sequence, 20)

    def test_audit_snapshot_is_atomic_under_concurrent_append(self):
        receipts, head = self.anchor.snapshot_since(0)
        self.assertEqual(receipts, ())
        self.assertIsNone(head)
        first = self.anchor.append({"type": "one"})
        receipts, head = self.anchor.snapshot_since(0)
        self.assertEqual(receipts, (first,))
        self.assertEqual(head, first)

    def test_new_nonce_cannot_repeat_same_business_transaction(self):
        first = self.bundle()
        self.assertTrue(self.execute(bundle=first, dispatch=self.dispatch(bundle=first)).allowed)
        second = self.bundle()
        result = self.execute(bundle=second, dispatch=self.dispatch(bundle=second))
        self.assertEqual(result.reason, "duplicate_transaction")
        self.assertEqual(len(self.effects), 1)

    def test_stale_resource_version_denied(self):
        first_claim = make_authority_claim(
            self.proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
            resource_state_version=0,
        )
        first = AuthorityBundle(first_claim, tuple(self.authorities[i].attest(self.proposal, first_claim) for i in (0, 1)))
        self.assertTrue(self.execute(bundle=first, dispatch=self.dispatch(bundle=first)).allowed)
        second_proposal = replace(self.proposal, transaction_id="tx-stale")
        stale_claim = make_authority_claim(
            second_proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
            resource_state_version=0,
        )
        stale = AuthorityBundle(stale_claim, tuple(self.authorities[i].attest(second_proposal, stale_claim) for i in (0, 1)))
        result = self.execute(second_proposal, stale, self.dispatch(second_proposal, stale))
        self.assertEqual(result.reason, "stale_resource_state")
        self.assertEqual(len(self.effects), 1)

    def test_secure_entrypoint_binds_sender_route_and_exact_wire_body(self):
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        body = canonical_bytes({
            "proposal": self.proposal.__dict__,
            "bundle": {"claim": bundle.claim, "attestations": [item.__dict__ for item in bundle.attestations]},
            "dispatch": dispatch.__dict__,
        })
        sender = Ed25519Signer.generate()
        registry = KeyRegistry((KeyStatus(sender, 90, 200),))
        verifier = SenderProofVerifier(
            registry, audience="payments-downstream", route="/v1/effects", method="POST",
            allow_test_time_override=True,
        )
        self.downstream.bind_sender_proof_verifier(verifier)
        proof = create_sender_proof(
            sender, method="POST", route="/v1/effects", audience="payments-downstream",
            body=body, issued_at=100, nonce="wire-1", subject="executor-prod",
        )
        result = self.downstream.execute_secure(
            self.proposal, bundle, dispatch, request_body=body, sender_proof=proof,
            proof_verifier=verifier, workload_identity="executor-prod", now=101,
        )
        self.assertTrue(result.allowed)
        self.assertEqual(len(self.effects), 1)

    def test_authorities_reject_tenant_claim_smuggling(self):
        claim = make_authority_claim(
            self.proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
            tenant_id="victim-tenant",
        )
        self.assertIsNone(self.authorities[0].attest(self.proposal, claim))

    def test_downstream_rejects_tenant_smuggling_even_with_compromised_quorum(self):
        claim = make_authority_claim(
            self.proposal, policy_hash="policy-sha256", system_version="v0.5",
            audience="payments-prod", issued_at=100, expires_at=110,
            tenant_id="victim-tenant",
        )
        bundle = AuthorityBundle(
            claim,
            tuple(AuthorityAttestation(key.key_id, b64encode(key.sign(canonical_bytes(claim)))) for key in self.authority_keys[:2]),
        )
        dispatch = self.gateway.dispatch(self.proposal, bundle, now=101)
        self.assertIsNotNone(dispatch)
        result = self.downstream.execute(
            self.proposal, bundle, dispatch, workload_identity="executor-prod", now=101,
        )
        self.assertEqual(result.reason, "downstream_tenant_mismatch")
        self.assertEqual(self.effects, [])

    def test_sender_key_cannot_assert_another_workload(self):
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        body = canonical_bytes({
            "proposal": self.proposal.__dict__,
            "bundle": {"claim": bundle.claim, "attestations": [item.__dict__ for item in bundle.attestations]},
            "dispatch": dispatch.__dict__,
        })
        sender = Ed25519Signer.generate()
        registry = KeyRegistry((KeyStatus(sender, 90, 200),))
        verifier = SenderProofVerifier(
            registry, audience="payments-downstream", route="/v1/effects", method="POST",
            expected_subject="executor-prod", allow_test_time_override=True,
        )
        self.downstream.bind_sender_proof_verifier(verifier)
        proof = create_sender_proof(
            sender, method="POST", route="/v1/effects", audience="payments-downstream",
            body=body, issued_at=100, nonce="wire-attacker", subject="admin-workload",
        )
        result = self.downstream.execute_secure(
            self.proposal, bundle, dispatch, request_body=body, sender_proof=proof,
            proof_verifier=verifier, workload_identity="executor-prod", now=101,
        )
        self.assertEqual(result.reason, "sender_subject_mismatch")
        self.assertEqual(self.effects, [])

    def test_concurrent_fresh_signed_requests_cannot_double_execute_transaction(self):
        sender = Ed25519Signer.generate()
        registry = KeyRegistry((KeyStatus(sender, 90, 200),))
        verifier = SenderProofVerifier(
            registry, audience="payments-downstream", route="/v1/effects", method="POST",
            expected_subject="executor-prod", allow_test_time_override=True,
        )
        self.downstream.bind_sender_proof_verifier(verifier)
        requests = []
        for index in range(50):
            claim = make_authority_claim(
                self.proposal, policy_hash="policy-sha256", system_version="v0.5",
                audience="payments-prod", issued_at=100, expires_at=110,
                nonce=f"authority-race-{index:04d}",
            )
            bundle = AuthorityBundle(
                claim, tuple(self.authorities[i].attest(self.proposal, claim) for i in (0, 1)),
            )
            dispatch = self.dispatch(self.proposal, bundle)
            body = canonical_bytes({
                "proposal": self.proposal.__dict__,
                "bundle": {"claim": bundle.claim, "attestations": [item.__dict__ for item in bundle.attestations]},
                "dispatch": dispatch.__dict__,
            })
            proof = create_sender_proof(
                sender, method="POST", route="/v1/effects", audience="payments-downstream",
                body=body, issued_at=100, nonce=f"transport-race-{index}", subject="executor-prod",
            )
            requests.append((bundle, dispatch, body, proof))

        results = []
        lock = threading.Lock()

        def attack(item):
            bundle, dispatch, body, proof = item
            result = self.downstream.execute_secure(
                self.proposal, bundle, dispatch, request_body=body, sender_proof=proof,
                proof_verifier=verifier, workload_identity="executor-prod", now=101,
            )
            with lock:
                results.append(result)

        threads = [threading.Thread(target=attack, args=(item,)) for item in requests]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(result.allowed for result in results), 1)
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(
            sum(result.reason == "duplicate_transaction" for result in results), 49,
            Counter(result.reason for result in results),
        )

    def test_caller_cannot_substitute_sender_proof_verifier(self):
        trusted_sender = Ed25519Signer.generate()
        trusted = SenderProofVerifier(
            KeyRegistry((KeyStatus(trusted_sender, 90, 200),)),
            audience="payments-downstream", route="/v1/effects", method="POST",
            expected_subject="executor-prod", allow_test_time_override=True,
        )
        self.downstream.bind_sender_proof_verifier(trusted)
        attacker = Ed25519Signer.generate()
        substituted = SenderProofVerifier(
            KeyRegistry((KeyStatus(attacker, 90, 200),)),
            audience="payments-downstream", route="/v1/effects", method="POST",
            expected_subject="executor-prod", allow_test_time_override=True,
        )
        bundle = self.bundle()
        dispatch = self.dispatch(bundle=bundle)
        body = canonical_bytes({
            "proposal": self.proposal.__dict__,
            "bundle": {"claim": bundle.claim, "attestations": [item.__dict__ for item in bundle.attestations]},
            "dispatch": dispatch.__dict__,
        })
        proof = create_sender_proof(
            attacker, method="POST", route="/v1/effects", audience="payments-downstream",
            body=body, issued_at=100, nonce="attacker-proof", subject="executor-prod",
        )
        result = self.downstream.execute_secure(
            self.proposal, bundle, dispatch, request_body=body, sender_proof=proof,
            proof_verifier=substituted, workload_identity="executor-prod", now=101,
        )
        self.assertEqual(result.reason, "sender_proof_verifier_substitution")
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
