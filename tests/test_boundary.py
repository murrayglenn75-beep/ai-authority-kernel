import json
import random
import secrets
import threading
import unittest
from dataclasses import replace

from aak import (
    BoundaryError, CompoundAttackGuard, Ed25519Signer, EffectReceiptIssuer, IdempotencyLedger,
    KeyRegistry, KeyStatus, PolicyDeploymentGate, SenderProofVerifier,
    SignedPolicyRelease, StrictJSONGate, approve_policy, canonical_route,
    create_sender_proof,
)
from aak.canonical import canonical_bytes
from aak.store import StateStore


class InteractionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519Signer.generate()
        self.registry = KeyRegistry((KeyStatus(self.signer, 90, 200),))
        self.verifier = SenderProofVerifier(
            self.registry, audience="payments", route="/v1/effects", method="POST",
            allow_test_time_override=True,
        )
        self.body = canonical_bytes({"amount_minor": 1000, "transaction_id": "tx-1"})
        self.proof = create_sender_proof(
            self.signer, method="POST", route="/v1/effects", audience="payments",
            body=self.body, issued_at=100, nonce="request-1",
        )

    def test_valid_sender_proof(self):
        self.assertEqual(self.verifier.verify(self.proof, self.body, now=101), (True, "verified"))

    def test_sender_proof_replay_denied(self):
        self.assertTrue(self.verifier.verify(self.proof, self.body, now=101)[0])
        self.assertEqual(self.verifier.verify(self.proof, self.body, now=101)[1], "sender_proof_replay")

    def test_body_substitution_denied(self):
        changed = canonical_bytes({"amount_minor": 9999, "transaction_id": "tx-1"})
        self.assertEqual(self.verifier.verify(self.proof, changed, now=101)[1], "request_binding_mismatch")

    def test_method_route_and_audience_substitution_denied(self):
        for field, value, reason in (
            ("method", "GET", "request_target_mismatch"),
            ("route", "/v1/admin", "request_target_mismatch"),
            ("audience", "admin", "request_binding_mismatch"),
        ):
            with self.subTest(field=field):
                self.assertEqual(self.verifier.verify(replace(self.proof, **{field: value}), self.body, now=101)[1], reason)

    def test_stolen_proof_signature_cannot_be_rebound(self):
        rebound = replace(self.proof, nonce="attacker-nonce")
        self.assertEqual(self.verifier.verify(rebound, self.body, now=101)[1], "invalid_sender_signature")

    def test_stale_and_future_proofs_denied(self):
        self.assertEqual(self.verifier.verify(self.proof, self.body, now=131)[1], "stale_or_future_proof")
        future = create_sender_proof(
            self.signer, method="POST", route="/v1/effects", audience="payments",
            body=self.body, issued_at=110, nonce="future",
        )
        self.assertEqual(self.verifier.verify(future, self.body, now=100)[1], "stale_or_future_proof")

    def test_revoked_and_unknown_keys_denied(self):
        self.registry.revoke(self.signer.key_id, 101)
        self.assertEqual(self.verifier.verify(self.proof, self.body, now=101)[1], "unknown_expired_or_revoked_key")
        attacker = Ed25519Signer.generate()
        proof = create_sender_proof(
            attacker, method="POST", route="/v1/effects", audience="payments",
            body=self.body, issued_at=100, nonce="unknown",
        )
        self.assertEqual(self.verifier.verify(proof, self.body, now=101)[1], "unknown_expired_or_revoked_key")

    def test_production_time_override_denied(self):
        verifier = SenderProofVerifier(self.registry, audience="payments", route="/v1/effects", method="POST")
        with self.assertRaisesRegex(ValueError, "caller-supplied time"):
            verifier.verify(self.proof, self.body, now=101)

    def test_test_time_override_rejects_boolean_negative_and_text(self):
        for invalid in (True, -1, "101"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "invalid trusted time"):
                self.verifier.verify(self.proof, self.body, now=invalid)

    def test_route_confusion_forms_denied(self):
        for route in ("v1/effects", "//v1/effects", "/v1/../admin", "/v1/%2e%2e/admin", "/v1\\admin", "/v1/effects?admin=1"):
            with self.subTest(route=route), self.assertRaises(BoundaryError):
                canonical_route(route)

    def test_strict_json_accepts_only_canonical_exact_schema(self):
        gate = StrictJSONGate(required_fields=("amount_minor", "transaction_id"))
        self.assertEqual(gate.parse(self.body)["amount_minor"], 1000)
        invalid = (
            b'{"amount_minor":1000,"amount_minor":1,"transaction_id":"tx-1"}',
            b'{"amount_minor":1000,"extra":true,"transaction_id":"tx-1"}',
            b'{"amount_minor":1.5,"transaction_id":"tx-1"}',
            b'{"amount_minor":NaN,"transaction_id":"tx-1"}',
            b'{ "amount_minor":1000,"transaction_id":"tx-1"}',
            '{"amount_minor":1000,"transaction_id":"e\u0301"}'.encode(),
            b'\xff',
        )
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(BoundaryError):
                gate.parse(raw)

    def test_size_and_depth_limits(self):
        gate = StrictJSONGate(required_fields=("payload",), max_bytes=50, max_depth=2)
        with self.assertRaisesRegex(BoundaryError, "invalid_message_size"):
            gate.parse(canonical_bytes({"payload": "x" * 100}))
        with self.assertRaisesRegex(BoundaryError, "maximum_depth"):
            StrictJSONGate(required_fields=("payload",), max_depth=2).parse(canonical_bytes({"payload": [[[1]]]}))

    def test_idempotency_duplicate_conflict_and_tenant_scope(self):
        ledger = IdempotencyLedger()
        args = dict(tenant="tenant-a", action="pay", resource="vendor", transaction_id="tx-1")
        self.assertEqual(ledger.reserve(**args, request_hash="hash-a"), (True, "reserved"))
        self.assertEqual(ledger.reserve(**args, request_hash="hash-a")[1], "duplicate_transaction")
        self.assertEqual(ledger.reserve(**args, request_hash="hash-b")[1], "idempotency_conflict")
        self.assertTrue(ledger.reserve(**dict(args, tenant="tenant-b"), request_hash="hash-a")[0])

    def test_concurrent_idempotency_allows_one_reservation(self):
        ledger = IdempotencyLedger()
        results = []
        args = dict(tenant="tenant", action="pay", resource="vendor", transaction_id="tx")
        threads = [threading.Thread(target=lambda: results.append(ledger.reserve(**args, request_hash="same"))) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(allowed for allowed, _ in results), 1)
        self.assertEqual(sum(reason == "duplicate_transaction" for _, reason in results), 19)

    def test_signed_effect_receipt_detects_tampering_and_revocation(self):
        issuer = EffectReceiptIssuer(self.signer)
        receipt = issuer.issue(
            transaction_id="tx-1", capability_hash="cap", request_hash="req",
            exact_effect={"money_minor": 1000}, previous_state_version=7,
            resulting_state_version=8, downstream_identity="payments-db", completed_at=101,
        )
        self.assertTrue(issuer.verify(receipt, self.registry, now=101))
        tampered = replace(receipt, claim=dict(receipt.claim, resulting_state_version=9))
        self.assertFalse(issuer.verify(tampered, self.registry, now=101))
        self.registry.revoke(self.signer.key_id, 102)
        self.assertFalse(issuer.verify(receipt, self.registry, now=102))

    def test_key_identifier_uses_full_sha256(self):
        self.assertEqual(len(self.signer.key_id.split(":", 1)[1]), 64)

    def test_replay_cache_is_bounded_and_expires_entries(self):
        verifier = SenderProofVerifier(
            self.registry, audience="payments", route="/v1/effects", method="POST",
            max_replay_entries=2, max_age_seconds=30, allow_test_time_override=True,
        )
        for index in range(2):
            proof = create_sender_proof(
                self.signer, method="POST", route="/v1/effects", audience="payments",
                body=self.body, issued_at=100, nonce=f"bounded-{index}",
            )
            self.assertTrue(verifier.verify(proof, self.body, now=101)[0])
        full = create_sender_proof(
            self.signer, method="POST", route="/v1/effects", audience="payments",
            body=self.body, issued_at=100, nonce="bounded-full",
        )
        self.assertEqual(verifier.verify(full, self.body, now=101)[1], "replay_cache_capacity_reached")
        fresh = create_sender_proof(
            self.signer, method="POST", route="/v1/effects", audience="payments",
            body=self.body, issued_at=132, nonce="bounded-fresh",
        )
        self.assertTrue(verifier.verify(fresh, self.body, now=132)[0])

    def test_random_wire_bytes_fail_closed_without_crashing(self):
        gate = StrictJSONGate(required_fields=("amount_minor", "transaction_id"), max_bytes=256)
        rng = random.Random(20260914)
        for _ in range(5_000):
            raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
            try:
                value = gate.parse(raw)
            except BoundaryError:
                continue
            self.assertEqual(canonical_bytes(value), raw)

    def test_sender_signature_mutation_fuzz_never_authorizes(self):
        rng = random.Random(20260915)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for index in range(2_000):
            chars = list(self.proof.signature)
            position = rng.randrange(len(chars))
            chars[position] = rng.choice(alphabet.replace(chars[position], ""))
            mutated = replace(self.proof, signature="".join(chars), nonce=f"mutation-{index}")
            self.assertFalse(self.verifier.verify(mutated, self.body, now=101)[0])

    def test_policy_deployment_requires_distinct_quorum_and_blocks_rollback(self):
        keys = [Ed25519Signer.generate() for _ in range(3)]
        registry = KeyRegistry(KeyStatus(key, 90, 200) for key in keys)
        gate = PolicyDeploymentGate(registry, threshold=2, environment="production")
        claim = {"policy_hash": "sha256:policy", "version": "p6", "generation": 6, "environment": "production", "issued_at": 100}
        one = SignedPolicyRelease(claim, (approve_policy(keys[0], claim),))
        self.assertEqual(gate.activate(one, now=101)[1], "insufficient_policy_quorum")
        duplicate = SignedPolicyRelease(claim, (approve_policy(keys[0], claim), approve_policy(keys[0], claim)))
        self.assertEqual(gate.activate(duplicate, now=101)[1], "insufficient_policy_quorum")
        valid = SignedPolicyRelease(claim, tuple(approve_policy(key, claim) for key in keys[:2]))
        self.assertEqual(gate.activate(valid, now=101), (True, "policy_activated"))
        rollback_claim = dict(claim, generation=5)
        rollback = SignedPolicyRelease(rollback_claim, tuple(approve_policy(key, rollback_claim) for key in keys[:2]))
        self.assertEqual(gate.activate(rollback, now=101)[1], "policy_rollback_or_replay")

    def test_policy_deployment_rejects_cross_environment_release(self):
        keys = [Ed25519Signer.generate() for _ in range(2)]
        registry = KeyRegistry(KeyStatus(key, 90, 200) for key in keys)
        gate = PolicyDeploymentGate(registry, threshold=2, environment="production")
        claim = {"policy_hash": "sha256:policy", "version": "p6", "generation": 6, "environment": "staging", "issued_at": 100}
        release = SignedPolicyRelease(claim, tuple(approve_policy(key, claim) for key in keys))
        self.assertEqual(gate.activate(release, now=101)[1], "wrong_policy_environment")

    def test_policy_deployment_rejects_stale_future_and_malformed_releases(self):
        keys = [Ed25519Signer.generate() for _ in range(2)]
        registry = KeyRegistry(KeyStatus(key, 90, 200) for key in keys)
        gate = PolicyDeploymentGate(
            registry, threshold=2, environment="production",
            max_release_age_seconds=10, max_future_skew_seconds=5,
        )
        base = {"policy_hash": "sha256:policy", "version": "p7", "generation": 7,
                "environment": "production", "issued_at": 100}
        for issued_at in (100, 156, "150", True):
            with self.subTest(issued_at=issued_at):
                claim = dict(base, issued_at=issued_at)
                release = SignedPolicyRelease(claim, tuple(approve_policy(key, claim) for key in keys))
                expected = "invalid_policy_time" if issued_at in ("150", True) else "stale_or_future_policy_release"
                self.assertEqual(gate.activate(release, now=150)[1], expected)

    def test_integer_budget_accounting_is_exact_above_float_precision(self):
        store = StateStore()
        limit = 2**53 + 1
        self.assertTrue(store.consume("n1", {"money": 2**53}, {"money": limit}, 100, strict_integer=True)[0])
        self.assertTrue(store.consume("n2", {"money": 1}, {"money": limit}, 101, strict_integer=True)[0])
        self.assertEqual(
            store.consume("n3", {"money": 1}, {"money": limit}, 102, strict_integer=True)[1],
            "budget_exceeded:money",
        )
        self.assertEqual(store.consume("n4", {"money": 1.0}, {"money": limit}, 103, strict_integer=True)[1], "non_integer_budget")

    def test_compound_guard_correlates_boundaries_and_blocks_source(self):
        guard = CompoundAttackGuard(threshold=12, window_seconds=60, block_seconds=300)
        source = "spiffe://prod/ns/app/sa/executor"
        first = guard.record(source, boundary="transport", signal="binding_mismatch", now=100, externally_authenticated=True)
        self.assertTrue(first.allowed)
        second = guard.record(source, boundary="authority", signal="quorum_bypass", now=101, externally_authenticated=True)
        self.assertTrue(second.allowed)
        blocked = guard.record(source, boundary="tenant", signal="tenant_substitution", now=102, externally_authenticated=True)
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.reason, "compound_attack_source_blocked")
        self.assertEqual(blocked.boundaries, ("authority", "tenant", "transport"))
        self.assertFalse(guard.check(source, now=200).allowed)
        self.assertTrue(guard.check(source, now=403).allowed)

    def test_compound_guard_ignores_spoofable_identity_signal(self):
        guard = CompoundAttackGuard(threshold=1)
        result = guard.record(
            "victim-workload", boundary="identity", signal="identity_mismatch",
            now=100, externally_authenticated=False,
        )
        self.assertEqual(result.reason, "untrusted_attack_signal_ignored")
        self.assertTrue(guard.check("victim-workload", now=100).allowed)

    def test_compound_guard_storage_is_bounded_and_fails_closed(self):
        guard = CompoundAttackGuard(threshold=100, max_sources=1)
        self.assertTrue(guard.record("source-a", boundary="wire", signal="malformed", now=100, externally_authenticated=True).allowed)
        result = guard.record("source-b", boundary="wire", signal="malformed", now=100, externally_authenticated=True)
        self.assertEqual(result.reason, "compound_guard_capacity_fail_closed")

    def test_compound_guard_bounds_events_and_rejects_invalid_dimensions(self):
        guard = CompoundAttackGuard(threshold=100, max_events_per_source=2, max_identity_length=16)
        for now in (100, 101):
            self.assertTrue(guard.record("source", boundary="wire", signal="malformed", now=now, externally_authenticated=True).allowed)
        self.assertFalse(guard.record("source", boundary="wire", signal="malformed", now=102, externally_authenticated=True).allowed)
        self.assertEqual(guard.check("x" * 17, now=100).reason, "missing_trusted_source_identity")
        self.assertEqual(guard.check("source", now=True).reason, "invalid_defense_time")
        self.assertEqual(
            CompoundAttackGuard(threshold=100).record(
                "source", boundary="attacker-created-boundary", signal="malformed",
                now=100, externally_authenticated=True,
            ).reason,
            "invalid_defense_signal",
        )

    def test_compound_guard_check_reports_accumulated_score(self):
        guard = CompoundAttackGuard(threshold=100)
        guard.record("source", boundary="wire", signal="malformed", now=100, externally_authenticated=True)
        decision = guard.check("source", now=101)
        self.assertEqual(decision.score, 1)
        self.assertEqual(decision.boundaries, ("wire",))


if __name__ == "__main__":
    unittest.main()
