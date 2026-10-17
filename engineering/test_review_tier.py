import unittest
from engineering.review_tier import tier

class ReviewTierTests(unittest.TestCase):
    def test_docs(self): self.assertEqual(tier(["README.md","docs/guide.md"]),"DOCS")
    def test_source(self): self.assertEqual(tier(["src/main.py"]),"STANDARD")
    def test_api(self): self.assertEqual(tier(["app/api/route.ts"]),"HIGH")
    def test_workflow(self): self.assertEqual(tier([".github/workflows/ci.yml"]),"HIGH")
    def test_payment(self): self.assertEqual(tier(["lib/payments/ledger.ts"]),"CRITICAL")
    def test_auth(self): self.assertEqual(tier(["app/auth/login.ts"]),"CRITICAL")
    def test_no_paths(self): self.assertEqual(tier([]),"BLOCKED")
    def test_invalid_path(self): self.assertEqual(tier(["../secret"]),"BLOCKED")
    def test_mixed(self): self.assertEqual(tier(["README.md","lib/security/policy.py"]),"CRITICAL")

if __name__ == "__main__": unittest.main()
