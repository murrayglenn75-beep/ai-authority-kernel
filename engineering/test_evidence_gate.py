import unittest
from engineering.evidence_gate import STAGES, validate

def valid():
    record = {stage: {"status": "passed", "evidence": "ci://sample"} for stage in STAGES}
    record.update(commit_sha="abc", approved=True, approval_evidence="review://sample")
    return record

class EvidenceGateTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(validate(valid()), [])
    def test_missing_every_stage(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                record=valid()
                del record[stage]
                self.assertTrue(validate(record))
    def test_failed_verify(self):
        record=valid()
        record["verify"]["status"]="failed"
        self.assertTrue(validate(record))
    def test_missing_reference(self):
        record=valid()
        record["test_first"]["evidence"]=""
        self.assertTrue(validate(record))
    def test_missing_approval(self):
        record=valid()
        record["approved"]=False
        self.assertTrue(validate(record))
    def test_invalid_record(self):
        self.assertTrue(validate([]))
    def test_missing_commit(self):
        record=valid()
        del record["commit_sha"]
        self.assertTrue(validate(record))

if __name__ == "__main__":
    unittest.main()
