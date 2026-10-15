import os
import unittest

from authorization_evidence import run


class EvidenceHarnessTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "campaign SQLite cleanup is not yet Windows-safe; Linux CI enforces")
    def test_real_local_boundary_campaigns_fail_closed(self):
        report = run(12)
        self.assertFalse(report["independent_remote_deployment_verified"])
        self.assertEqual(len(report["campaigns"]), 2)
        self.assertEqual(sum(row["attempts"] for row in report["campaigns"]), 24)

    def test_unbounded_or_invalid_attempts_rejected(self):
        for bad in (0, -1, 10001, True):
            with self.assertRaises(ValueError):
                run(bad)


if __name__ == "__main__":
    unittest.main()
