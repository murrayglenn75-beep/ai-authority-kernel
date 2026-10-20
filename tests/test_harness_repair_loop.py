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
        previous = state or RepairState()
        return RepairState(Phase.VERIFY, previous.attempts + 1, previous.max_attempts, 'unit-test-fixture')

    def test_legacy_verified_state_is_not_authority(self):
        with self.assertRaises(PermissionError):
            decide(self.approved(), baseline=self.baseline, candidate=self.better)

    def test_denies_unapproved(self):
        with self.assertRaises(PermissionError):
            record_external_verification(request_approval(plan(RepairState())),
                                         approved=False, evidence_id="run")

    def test_denies_missing_evidence(self):
        with self.assertRaises(PermissionError):
            record_external_verification(request_approval(plan(RepairState())),
                                         approved=True, evidence_id="")

    def test_denies_skipped_inspection(self):
        with self.assertRaises(ValueError):
            request_approval(RepairState())

    def test_denies_unverified_decision(self):
        with self.assertRaises(PermissionError):
            decide(RepairState(), baseline=self.baseline, candidate=self.better)

    def test_forged_state_denied(self):
        with self.assertRaises(PermissionError):
            decide(RepairState(Phase.VERIFY, 1, 3, "forged"),
                   baseline=self.baseline, candidate=self.better)

    def test_retry_requires_reject_state(self):
        with self.assertRaises(ValueError):
            retry(self.approved())

    def test_retry_after_rejection(self):
        second = retry(RepairState(Phase.REJECT, 1, 3, "fixture"))
        self.assertEqual((second.phase, second.attempts), (Phase.INSPECT, 1))

    def test_bounded_retry(self):
        with self.assertRaises(ValueError):
            retry(RepairState(Phase.REJECT, 1, 1, "fixture"))

    def test_no_execution_methods(self):
        self.assertFalse(hasattr(RepairState, "execute"))
        self.assertFalse(hasattr(RepairState, "issue_grant"))


if __name__ == "__main__":
    unittest.main()
