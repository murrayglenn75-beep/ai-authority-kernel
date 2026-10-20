import unittest
from aak.harness_eval_gate import Evaluation, compare


class HarnessEvalGateTests(unittest.TestCase):
    def setUp(self):
        self.base = Evaluation({"known": True, "new": False}, 0, 100, 100)

    def check(self, cases, security=0, latency=100, tokens=100):
        return compare(self.base, Evaluation(cases, security, latency, tokens))

    def test_improvement(self):
        self.assertTrue(self.check({"known": True, "new": True}).accepted)

    def test_regression_denied(self):
        self.assertFalse(self.check({"known": False, "new": True}).accepted)

    def test_same_score_denied(self):
        self.assertFalse(self.check({"known": True, "new": False}).accepted)

    def test_missing_case_denied(self):
        self.assertFalse(self.check({"known": True}).accepted)

    def test_extra_case_denied(self):
        self.assertFalse(self.check({"known": True, "new": True, "other": True}).accepted)

    def test_security_failure_denied(self):
        self.assertFalse(self.check({"known": True, "new": True}, security=1).accepted)

    def test_latency_budget_denied(self):
        self.assertFalse(self.check({"known": True, "new": True}, latency=121).accepted)

    def test_token_budget_denied(self):
        self.assertFalse(self.check({"known": True, "new": True}, tokens=121).accepted)

    def test_negative_measurement_denied(self):
        with self.assertRaises(ValueError):
            Evaluation({"known": True}, 0, -1, 1)

    def test_invalid_boolean_denied(self):
        with self.assertRaises(ValueError):
            Evaluation({"known": 1}, 0, 1, 1)

    def test_negative_limits_denied(self):
        with self.assertRaises(ValueError):
            compare(self.base, self.base, max_latency_growth_percent=-1)


    def test_evaluation_snapshots_input_cases(self):
        source = {"known": True, "new": False}
        evidence = Evaluation(source, 0, 100, 100)
        source["known"] = False
        self.assertTrue(evidence.cases["known"])

    def test_evaluation_cases_are_read_only(self):
        evidence = Evaluation({"known": True, "new": False}, 0, 100, 100)
        with self.assertRaises(TypeError):
            evidence.cases["known"] = False

    def test_input_mutation_cannot_change_gate_result(self):
        source = {"known": True, "new": True}
        candidate = Evaluation(source, 0, 100, 100)
        source["known"] = False
        self.assertTrue(compare(self.base, candidate).accepted)


if __name__ == "__main__":
    unittest.main()
