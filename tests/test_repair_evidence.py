import unittest
from aak.repair_evidence import RepairProposal, Verification, reuse_decision

HEX = "a" * 64

def proposal():
    return RepairProposal("incident-1", "example/repo", "abcdef", HEX, ("test-1",), "assertion failed")

def verified(p):
    return Verification(p.proposal_id, True, True, HEX, "independent-ci")

class RepairEvidenceTests(unittest.TestCase):
    def test_verified_and_confirmed_record_can_be_published(self):
        p = proposal()
        result = reuse_decision(p, verified(p), approval_proposal_id=p.proposal_id, authority_consumed=True)
        self.assertTrue(result["publishable"])
        self.assertEqual(result["authorization"], "metadata_only_never_execute")

    def test_missing_approval_fails(self):
        p = proposal()
        self.assertFalse(reuse_decision(p, verified(p), approval_proposal_id=None, authority_consumed=True)["publishable"])

    def test_authority_not_consumed_fails(self):
        p = proposal()
        self.assertFalse(reuse_decision(p, verified(p), approval_proposal_id=p.proposal_id, authority_consumed=False)["publishable"])

    def test_missing_verification_fails(self):
        p = proposal()
        self.assertFalse(reuse_decision(p, None, approval_proposal_id=p.proposal_id, authority_consumed=True)["publishable"])

    def test_different_proposal_fails(self):
        p = proposal()
        q = RepairProposal("incident-2", "example/repo", "abcdef", HEX, ("test-1",), "assertion failed")
        self.assertFalse(reuse_decision(p, verified(q), approval_proposal_id=p.proposal_id, authority_consumed=True)["publishable"])

    def test_incomplete_regression_fails(self):
        p = proposal()
        v = Verification(p.proposal_id, True, False, HEX, "ci")
        self.assertFalse(reuse_decision(p, v, approval_proposal_id=p.proposal_id, authority_consumed=True)["publishable"])

    def test_duplicate_evidence_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate_evidence"):
            RepairProposal("id", "repo", "sha", HEX, ("same", "same"), "reason")

    def test_invalid_patch_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid_patch"):
            RepairProposal("id", "repo", "sha", "not-a-digest", ("test",), "reason")

    def test_bool_string_rejected(self):
        p = proposal()
        with self.assertRaisesRegex(ValueError, "invalid_verification_flags"):
            Verification(p.proposal_id, "true", True, HEX, "ci")

    def test_proposal_change_changes_id(self):
        p = proposal()
        q = RepairProposal("incident-1", "example/repo", "new-base", HEX, ("test-1",), "assertion failed")
        self.assertNotEqual(p.proposal_id, q.proposal_id)

if __name__ == "__main__":
    unittest.main()
