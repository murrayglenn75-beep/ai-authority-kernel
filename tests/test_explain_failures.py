import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "explain_failures.py"
spec = importlib.util.spec_from_file_location("failure_explainer", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class FailureExplainerTests(unittest.TestCase):
    def run_report(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "junit.xml"
            p.write_text(text, encoding="utf-8")
            return module.analyze(p)

    def test_failure_has_evidence_but_not_invented_cause(self):
        out = self.run_report('<testsuite><testcase classname="a" name="b"><failure message="expected 1">actual 0</failure></testcase></testsuite>')
        self.assertEqual(out["status"], "fail")
        self.assertEqual(out["failures"][0]["root_cause"], "unverified")
        self.assertIn("actual 0", out["failures"][0]["evidence"])

    def test_clean_suite(self):
        self.assertEqual(self.run_report('<testsuite><testcase name="ok"/></testsuite>')["status"], "pass")

    def test_dtd_rejected(self):
        with self.assertRaisesRegex(ValueError, "DTD"):
            self.run_report("<!DOCTYPE testsuite><testsuite/>")

    def test_invalid_root_rejected(self):
        with self.assertRaisesRegex(ValueError, "Expected JUnit"):
            self.run_report("<other/>")

    def test_malformed_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid JUnit"):
            self.run_report("<testsuite>")

    def test_bounded_evidence(self):
        out = self.run_report("<testsuite><testcase><error>" + "x" * 5000 + "</error></testcase></testsuite>")
        self.assertEqual(len(out["failures"][0]["evidence"]), 1200)

if __name__ == "__main__":
    unittest.main()
