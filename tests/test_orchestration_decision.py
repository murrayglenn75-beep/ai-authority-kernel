import unittest

from aak.orchestration_decision import Decision, ProgressSnapshot, decide


class OrchestrationDecisionTests(unittest.TestCase):
    def test_missing_authority_denied(self):
        self.assertEqual(decide(ProgressSnapshot(0, 0)).decision, Decision.STOP)

    def test_approval_is_requested(self):
        self.assertEqual(decide(ProgressSnapshot(0, 0, True, False, True)).decision, Decision.ASK)

    def test_authorized_request_only(self):
        self.assertEqual(decide(ProgressSnapshot(0, 0, True, True, True)).decision, Decision.ACT)

    def test_stall_prevents_action(self):
        self.assertEqual(decide(ProgressSnapshot(3, 5, authorization_valid=True)).decision, Decision.STOP)

    def test_step_budget_prevents_action(self):
        self.assertEqual(decide(ProgressSnapshot(100, 0, authorization_valid=True)).decision, Decision.STOP)

    def test_ambiguous_state_denied(self):
        self.assertEqual(decide(ProgressSnapshot(0, 0, authorization_valid=True, state_ambiguous=True)).decision, Decision.STOP)

    def test_bad_counters_denied(self):
        self.assertEqual(decide(ProgressSnapshot(-1, 0, authorization_valid=True)).decision, Decision.STOP)

    def test_invalid_limits_rejected(self):
        with self.assertRaises(ValueError):
            decide(ProgressSnapshot(0, 0, authorization_valid=True), max_steps=0)


if __name__ == '__main__':
    unittest.main()
