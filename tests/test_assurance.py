import unittest
from dataclasses import replace
from tempfile import TemporaryDirectory
from pathlib import Path

from aak import (
    Ed25519Signer, ExternalPolicyIssuer, ExternalPolicyVerifier, Proposal,
    WorkloadIdentityIssuer, WorkloadIdentityVerifier,
)
from aak.store import StateStore
from aak.canonical import canonical_bytes
from aak.crypto import b64encode


class ExternalAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.proposal = Proposal(
            "tx-1", "glenn", "agent-1", "approved invoice", "payment.transfer",
            "account/vendor", {"amount": 10}, {"money": 10}, ("invoice-1",), ("reviewer",),
        )

    def test_external_policy_is_exact_short_lived_and_monotonic(self):
        key = Ed25519Signer.generate()
        issuer = ExternalPolicyIssuer(key)
        verifier = ExternalPolicyVerifier(key, audience="payments", expected_policy_hash="policy-a", minimum_revision=6)
        decision = issuer.issue(
            decision_id="decision-1", proposal=self.proposal, allowed=True,
            policy_hash="policy-a", policy_revision=7, audience="payments", issued_at=100, expires_at=110,
        )
        self.assertEqual(verifier.verify(decision, self.proposal, now=101), (True, "external_policy_allowed"))
        self.assertEqual(verifier.verify(decision, self.proposal, now=101)[1], "policy_decision_replay")
        changed = replace(self.proposal, transaction_id="tx-2")
        old = issuer.issue(
            decision_id="decision-2", proposal=changed, allowed=True,
            policy_hash="policy-a", policy_revision=6, audience="payments", issued_at=100, expires_at=110,
        )
        self.assertEqual(verifier.verify(old, changed, now=101)[1], "policy_revision_rollback")

    def test_policy_tamper_deny_expiry_and_unknown_schema_fail_closed(self):
        key = Ed25519Signer.generate()
        issuer = ExternalPolicyIssuer(key)
        verifier = ExternalPolicyVerifier(key, audience="payments", expected_policy_hash="policy-a")
        decision = issuer.issue(
            decision_id="decision-1", proposal=self.proposal, allowed=False,
            policy_hash="policy-a", policy_revision=1, audience="payments", issued_at=100, expires_at=110,
        )
        self.assertEqual(verifier.verify(decision, self.proposal, now=101)[1], "external_policy_denied")
        self.assertEqual(verifier.verify(replace(decision, allowed=True), self.proposal, now=101)[1], "invalid_policy_signature")
        self.assertEqual(verifier.verify(replace(decision, schema_version=2), self.proposal, now=101)[1], "unsupported_policy_schema")
        self.assertEqual(verifier.verify(decision, self.proposal, now=111)[1], "policy_expired_or_invalid")

    def test_workload_identity_binding_and_tamper_rejection(self):
        key = Ed25519Signer.generate()
        assertion = WorkloadIdentityIssuer(key).issue(
            assertion_id="identity-1",
            spiffe_id="spiffe://example.org/executor", trust_domain="example.org", audience="payments",
            certificate_fingerprint="sha256:abc", channel_binding="request-hash-a",
            issued_at=100, expires_at=110,
        )
        verifier = WorkloadIdentityVerifier(
            key, expected_spiffe_id="spiffe://example.org/executor", trust_domain="example.org", audience="payments",
        )
        self.assertEqual(verifier.verify(assertion, now=101, expected_channel_binding="request-hash-a"), (True, "workload_identity_verified"))
        self.assertEqual(
            verifier.verify(assertion, now=101, expected_channel_binding="request-hash-a")[1],
            "workload_identity_replay",
        )
        self.assertEqual(verifier.verify(replace(assertion, audience="admin"), now=101)[1], "invalid_workload_identity_signature")
        foreign = WorkloadIdentityVerifier(
            key, expected_spiffe_id="spiffe://evil.example/executor", trust_domain="example.org", audience="payments",
        )
        self.assertEqual(foreign.verify(assertion, now=101)[1], "workload_identity_binding_mismatch")

    def test_assurance_replay_and_revision_survive_verifier_restart(self):
        policy_key = Ed25519Signer.generate()
        identity_key = Ed25519Signer.generate()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "shared.db"
            first_store = StateStore(path)
            first_policy = ExternalPolicyVerifier(
                policy_key, audience="payments", expected_policy_hash="policy-a", store=first_store,
            )
            decision = ExternalPolicyIssuer(policy_key).issue(
                decision_id="persistent-policy", proposal=self.proposal, allowed=True,
                policy_hash="policy-a", policy_revision=8, audience="payments",
                issued_at=100, expires_at=110,
            )
            self.assertTrue(first_policy.verify(decision, self.proposal, now=101)[0])
            assertion = WorkloadIdentityIssuer(identity_key).issue(
                assertion_id="persistent-identity", spiffe_id="spiffe://example.org/executor",
                trust_domain="example.org", audience="payments", certificate_fingerprint="sha256:abc",
                channel_binding="request-a", issued_at=100, expires_at=110,
            )
            first_identity = WorkloadIdentityVerifier(
                identity_key, expected_spiffe_id="spiffe://example.org/executor",
                trust_domain="example.org", audience="payments", store=first_store,
            )
            self.assertTrue(first_identity.verify(assertion, now=101, expected_channel_binding="request-a")[0])
            first_store.close()

            restarted_store = StateStore(path)
            restarted_policy = ExternalPolicyVerifier(
                policy_key, audience="payments", expected_policy_hash="policy-a", store=restarted_store,
            )
            self.assertEqual(restarted_policy.verify(decision, self.proposal, now=101)[1], "policy_decision_replay")
            older = ExternalPolicyIssuer(policy_key).issue(
                decision_id="older-policy", proposal=self.proposal, allowed=True,
                policy_hash="policy-a", policy_revision=7, audience="payments",
                issued_at=100, expires_at=110,
            )
            self.assertEqual(restarted_policy.verify(older, self.proposal, now=101)[1], "policy_revision_rollback")
            restarted_identity = WorkloadIdentityVerifier(
                identity_key, expected_spiffe_id="spiffe://example.org/executor",
                trust_domain="example.org", audience="payments", store=restarted_store,
            )
            self.assertEqual(
                restarted_identity.verify(assertion, now=101, expected_channel_binding="request-a")[1],
                "workload_identity_replay",
            )
            restarted_store.close()

    def test_workload_assertion_wrong_channel_is_denied_without_consuming_it(self):
        key = Ed25519Signer.generate()
        assertion = WorkloadIdentityIssuer(key).issue(
            assertion_id="identity-channel", spiffe_id="spiffe://example.org/executor",
            trust_domain="example.org", audience="payments", certificate_fingerprint="sha256:abc",
            channel_binding="request-a", issued_at=100, expires_at=110,
        )
        verifier = WorkloadIdentityVerifier(
            key, expected_spiffe_id="spiffe://example.org/executor",
            trust_domain="example.org", audience="payments",
        )
        self.assertEqual(
            verifier.verify(assertion, now=101, expected_channel_binding="request-b")[1],
            "workload_channel_binding_mismatch",
        )
        self.assertTrue(verifier.verify(assertion, now=101, expected_channel_binding="request-a")[0])

    def test_policy_consistency_namespaces_do_not_interfere(self):
        key = Ed25519Signer.generate()
        store = StateStore()
        first = ExternalPolicyVerifier(
            key, audience="payments", expected_policy_hash="policy-a", minimum_revision=100, store=store,
        )
        second = ExternalPolicyVerifier(
            key, audience="messages", expected_policy_hash="policy-b", minimum_revision=1, store=store,
        )
        self.assertEqual(first.minimum_revision, 100)
        self.assertEqual(second.minimum_revision, 1)

    def test_signed_non_boolean_policy_result_is_malformed(self):
        key = Ed25519Signer.generate()
        decision = ExternalPolicyIssuer(key).issue(
            decision_id="typed-policy", proposal=self.proposal, allowed=True,
            policy_hash="policy-a", policy_revision=1, audience="payments",
            issued_at=100, expires_at=110,
        )
        malformed = replace(decision, allowed=1)
        # Re-sign to model a faulty or compromised PDP, not mere wire tampering.
        claim = malformed.claim()
        malformed = replace(malformed, signature=b64encode(key.sign(canonical_bytes(claim))))
        verifier = ExternalPolicyVerifier(key, audience="payments", expected_policy_hash="policy-a")
        self.assertEqual(verifier.verify(malformed, self.proposal, now=101)[1], "malformed_policy_decision")

    def test_effect_journal_prevents_duplicates_and_reconciles_ambiguity(self):
        store = StateStore()
        self.assertEqual(store.begin_effect("op-1", "request-a", 100), (True, "effect_prepared"))
        self.assertEqual(store.begin_effect("op-1", "request-a", 100)[1], "effect_already_prepared")
        self.assertEqual(store.begin_effect("op-1", "request-b", 100)[1], "effect_idempotency_conflict")
        self.assertTrue(store.transition_effect("op-1", "request-a", from_state="prepared", to_state="submitted", now=101, provider_reference="bank-123")[0])
        self.assertTrue(store.transition_effect("op-1", "request-a", from_state="submitted", to_state="ambiguous", now=102)[0])
        self.assertTrue(store.transition_effect("op-1", "request-a", from_state="ambiguous", to_state="succeeded", now=103, result_hash="result-a")[0])
        status = store.effect_status("op-1")
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(status["provider_reference"], "bank-123")
        self.assertFalse(store.transition_effect("op-1", "request-a", from_state="succeeded", to_state="submitted", now=104)[0])


if __name__ == "__main__":
    unittest.main()
