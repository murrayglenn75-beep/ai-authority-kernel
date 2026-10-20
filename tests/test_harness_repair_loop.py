import unittest
from aak.harness_repair_loop import (
    RepairState, Phase, plan, request_approval,
    record_external_verification, decide, retry)
from aak.harness_eval_gate import Evaluation


class RepairLoopTests(unittest.TestCase):
    def setUp(self):
        self.baseline = Evaluation({"old": True, "new": False}, 0, 100, 100)
        self.better = Evaluation({"old": True, "new": True}, 0, 100, 100)

    def approved(self, state=None):
        s = request_approval(plan(state or RepairState()))
        return record_external_verification(s, approved=True, evidence_id="trusted-run-1")

    def test_accept_verified_improvement(self):
        result, gate = decide(self.approved(), baseline=self.baseline, candidate=self.better)
        self.assertTrue(gate.accepted)
        self.assertEqual(result.phase, Phase.ACCEPT)

    def test_denies_unapproved(self):
        with self.assertRaises(PermissionError):
            record_external_verification(request_approval(plan(RepairState())),
                                         approved=False, evidence_id="run")

    def test_denies_missing_evidence(self):
        with self.assertRaises(ValueError):
            record_external_verification(request_approval(plan(RepairState())),
                                         approved=True, evidence_id="")

    def test_denies_skipped_inspection(self):
        with self.assertRaises(ValueError):
            request_approval(RepairState())

    def test_denies_unverified_decision(self):
        with self.assertRaises(ValueError):
            decide(RepairState(), baseline=self.baseline, candidate=self.better)

    def test_regression_rejected(self):
        s, gate = decide(self.approved(), baseline=self.baseline,
                         candidate=Evaluation({"old": False, "new": True}, 0, 100, 100))
        self.assertFalse(gate.accepted)
        self.assertEqual(s.phase, Phase.REJECT)

    def test_bounded_retry(self):
        first, _ = decide(self.approved(RepairState(max_attempts=1)),
                          baseline=self.baseline, candidate=self.baseline)
        with self.assertRaises(ValueError):
            retry(first)

    def test_retry_after_rejection(self):
        first, _ = decide(self.approved(), baseline=self.baseline, candidate=self.baseline)
        second = retry(first)
        self.assertEqual((second.phase, second.attempts), (Phase.INSPECT, 1))

    def test_no_execution_methods(self):
        self.assertFalse(hasattr(RepairState, "execute"))
        self.assertFalse(hasattr(RepairState, "issue_grant"))


if __name__ == "__main__":
    unittest.main()
