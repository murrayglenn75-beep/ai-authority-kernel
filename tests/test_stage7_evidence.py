import unittest
from scripts.verify_stage7_evidence import REQUIRED, validate

class Stage7GateTests(unittest.TestCase):
    def test_missing_evidence_denied(self):
        with self.assertRaisesRegex(ValueError,"missing_or_unknown_release_evidence"):
            validate({"commit":"a"*40,"artifacts":{}})

    def test_unverified_gate_denied(self):
        records={key:{"status":"verified","evidence_uri":"https://evidence.invalid/"+key,
                      "reviewer":"Independent reviewer"} for key in REQUIRED}
        records["provider_reconciliation"]["status"]="pending"
        with self.assertRaisesRegex(ValueError,"unverified_gate"):
            validate({"commit":"a"*40,"artifacts":records})

    def test_duplicate_evidence_denied(self):
        records={key:{"status":"verified","evidence_uri":"https://evidence.invalid/"+key,
                      "reviewer":"Independent reviewer"} for key in REQUIRED}
        records["security_review"]["evidence_uri"]=records["partition_tests"]["evidence_uri"]
        with self.assertRaisesRegex(ValueError,"invalid_or_reused"):
            validate({"commit":"a"*40,"artifacts":records})

    def test_complete_shape_is_only_structural_validation(self):
        records={key:{"status":"verified","evidence_uri":"https://evidence.invalid/"+key,
                      "reviewer":"Independent reviewer"} for key in REQUIRED}
        self.assertTrue(validate({"commit":"a"*40,"artifacts":records}))

if __name__=="__main__":
    unittest.main()
