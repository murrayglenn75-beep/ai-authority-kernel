import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from dataclasses import replace
from pathlib import Path
from aak.canonical import canonical_bytes
from aak.crypto import Ed25519Signer, b64encode
from aak.harness_repair_loop import RepairState, Phase, plan, request_approval
from aak.harness_verified_receipt import VerificationReceipt, VerifiedReceiptLedger
from aak.harness_eval_gate import Evaluation


class VerifiedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = VerifiedReceiptLedger(str(Path(self.tmp.name) / "receipts.sqlite"))
        self.signer = Ed25519Signer.generate()
        self.verifier = Ed25519Signer.verifier(self.signer.public_key_bytes)
        self.state = request_approval(plan(RepairState()))
        self.receipt = VerificationReceipt("receipt1", "task1", "alice", 1, "test-run1",
                                           True, 100, 200, self.signer.key_id, "")
        self.receipt = self.sign(self.receipt)

    def sign(self, receipt):
        return replace(receipt, signature=b64encode(self.signer.sign(canonical_bytes(receipt.claim()))))

    def accept(self, receipt=None, **kw):
        args=dict(state=self.state, receipt=receipt or self.receipt,
                  verifier=self.verifier, task_id="task1", principal_id="alice", now=150)
        args.update(kw)
        return self.ledger.accept(**args)

    def test_valid(self):
        self.assertEqual(self.accept().phase, Phase.VERIFY)

    def test_replay_rejected_after_restart(self):
        self.accept()
        fresh = VerifiedReceiptLedger(self.ledger.path)
        with self.assertRaises(PermissionError):
            fresh.accept(state=self.state, receipt=self.receipt, verifier=self.verifier,
                         task_id="task1", principal_id="alice", now=150)

    def test_forged_signature(self):
        with self.assertRaises(PermissionError):
            self.accept(receipt=replace(self.receipt, signature="fake"))

    def test_changed_scope(self):
        with self.assertRaises(PermissionError):
            self.accept(receipt=replace(self.receipt, task_id="other"))

    def test_cross_principal(self):
        with self.assertRaises(PermissionError):
            self.accept(principal_id="bob")

    def test_expired(self):
        with self.assertRaises(PermissionError):
            self.accept(now=200)

    def test_future_issued(self):
        with self.assertRaises(PermissionError):
            self.accept(now=99)

    def test_unapproved_signed(self):
        with self.assertRaises(PermissionError):
            self.accept(receipt=self.sign(replace(self.receipt, approved=False, signature="")))

    def test_wrong_attempt_signed(self):
        with self.assertRaises(PermissionError):
            self.accept(receipt=self.sign(replace(self.receipt, attempt=2, signature="")))

    def test_wrong_signer(self):
        other = Ed25519Signer.generate()
        with self.assertRaises(PermissionError):
            self.accept(verifier=Ed25519Signer.verifier(other.public_key_bytes))

    def test_unapproved_phase(self):
        with self.assertRaises(PermissionError):
            self.accept(state=RepairState())

    def test_no_memory_ledger(self):
        with self.assertRaises(ValueError):
            VerifiedReceiptLedger(":memory:")


    def test_verified_decision_accepts_measured_improvement(self):
        baseline = Evaluation({"known": True, "new": False}, 0, 100, 100)
        candidate = Evaluation({"known": True, "new": True}, 0, 100, 100)
        state, decision = self.ledger.verify_and_decide(
            state=self.state, receipt=self.receipt, verifier=self.verifier,
            task_id="task1", principal_id="alice", now=150,
            baseline=baseline, candidate=candidate)
        self.assertTrue(decision.accepted)
        self.assertEqual(state.phase, Phase.ACCEPT)

    def test_verified_decision_rejects_regression(self):
        baseline = Evaluation({"known": True, "new": False}, 0, 100, 100)
        candidate = Evaluation({"known": False, "new": True}, 0, 100, 100)
        state, decision = self.ledger.verify_and_decide(
            state=self.state, receipt=self.receipt, verifier=self.verifier,
            task_id="task1", principal_id="alice", now=150,
            baseline=baseline, candidate=candidate)
        self.assertFalse(decision.accepted)
        self.assertEqual(state.phase, Phase.REJECT)

    def test_concurrent_receipt_consumption_single_winner(self):
        def consume(_):
            try:
                self.accept()
                return True
            except PermissionError:
                return False
        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(consume, range(6)))
        self.assertEqual(sum(outcomes), 1)

    def test_invalid_evaluation_does_not_issue_decision(self):
        baseline = Evaluation({"known": True, "new": False}, 0, 100, 100)
        with self.assertRaises(ValueError):
            self.ledger.verify_and_decide(
                state=self.state, receipt=self.receipt, verifier=self.verifier,
                task_id="task1", principal_id="alice", now=150,
                baseline=baseline, candidate=None)


if __name__ == "__main__":
    unittest.main()
