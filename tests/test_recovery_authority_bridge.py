"""Integration regression: real AAK policy verification gates the recovery model.

This exercises AAK's actual ExternalPolicyVerifier; the downstream recovery
journal remains the SQLite mock in recovery_harness, NOT the production broker.
"""
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recovery_harness import setup, submit, row
from aak import Ed25519Signer, ExternalPolicyIssuer, ExternalPolicyVerifier, Proposal


class RecoveryAuthorityBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "effects.sqlite")
        setup(self.db)
        self.proposal = Proposal(
            "tx-integrated", "reviewer", "agent-1", "approved test action",
            "payment.transfer", "account/vendor", {"amount": 10},
            {"money": 10}, ("invoice-test",), ("reviewer",),
        )
        signer = Ed25519Signer.generate()
        self.issuer = ExternalPolicyIssuer(signer)
        self.verifier = ExternalPolicyVerifier(
            signer, audience="payments", expected_policy_hash="test-policy",
        )

    def decision(self, allowed=True):
        return self.issuer.issue(
            decision_id="one-time-decision", proposal=self.proposal,
            allowed=allowed, policy_hash="test-policy",
            policy_revision=1, audience="payments",
            issued_at=100, expires_at=110,
        )

    def guarded_prepare(self, decision, proposed):
        accepted, reason = self.verifier.verify(decision, proposed, now=101)
        if not accepted:
            return False, reason
        submit(self.db, proposed.transaction_id, "amount=10")
        return True, reason

    def test_authorized_proposal_prepares_once(self):
        decision = self.decision()
        self.assertTrue(self.guarded_prepare(decision, self.proposal)[0])
        self.assertEqual(row(self.db, "SELECT count(*) FROM commands")[0], 1)
        self.assertFalse(self.guarded_prepare(decision, self.proposal)[0])
        self.assertEqual(row(self.db, "SELECT count(*) FROM commands")[0], 1)

    def test_tampered_proposal_cannot_prepare_effect(self):
        decision = self.decision()
        tampered = replace(self.proposal, transaction_id="tx-forged")
        self.assertFalse(self.guarded_prepare(decision, tampered)[0])
        self.assertEqual(row(self.db, "SELECT count(*) FROM commands")[0], 0)

    def test_explicit_policy_deny_cannot_prepare_effect(self):
        self.assertFalse(self.guarded_prepare(self.decision(False), self.proposal)[0])
        self.assertEqual(row(self.db, "SELECT count(*) FROM commands")[0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
