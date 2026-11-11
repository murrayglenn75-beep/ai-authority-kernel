import unittest
from action_preflight import strict_json, preflight, DuplicateKeyError, InvalidPolicy
GOOD = {"approval_id":"verified-id","principal":"u1","action":"read","resource":"doc-1",
        "expires_at":"2030-01-01T00:00:00Z","max_cost":"5.00","max_uses":2,"used":0}
REQ = {"principal":"u1","action":"read","resource":"doc-1","estimated_cost":"1.00"}
def check(a=None, r=None, ids=None):
    return preflight(GOOD if a is None else a, REQ if r is None else r,
                     verified_approval_ids={"verified-id"} if ids is None else ids,
                     now="2026-11-11T12:00:00Z")
class PreflightTests(unittest.TestCase):
    def test_valid(self): self.assertEqual(check(), (True, []))
    def test_duplicate(self):
        with self.assertRaises(DuplicateKeyError): strict_json('{"a":1,"a":2}')
    def test_nonstandard(self):
        with self.assertRaises(InvalidPolicy): strict_json('{"a":NaN}')
    def test_expiry(self): self.assertFalse(check({**GOOD,"expires_at":"2026-01-01T00:00:00Z"})[0])
    def test_unverified(self): self.assertFalse(check(ids=set())[0])
    def test_action_binding(self): self.assertFalse(check(r={**REQ,"action":"write"})[0])
    def test_resource_binding(self): self.assertFalse(check(r={**REQ,"resource":"doc-2"})[0])
    def test_use_budget(self): self.assertFalse(check({**GOOD,"used":2})[0])
    def test_cost_budget(self): self.assertFalse(check(r={**REQ,"estimated_cost":"6.00"})[0])
    def test_publication(self): self.assertFalse(check(r={**REQ,"is_publication":True})[0])
    def test_invalid_cost(self): self.assertFalse(check(r={**REQ,"estimated_cost":"NaN"})[0])
    def test_no_timezone(self): self.assertFalse(check({**GOOD,"expires_at":"2030-01-01"})[0])
    def test_unknown_fields(self): self.assertFalse(check({**GOOD,"bypass":True})[0])
    def test_boolean_use_budget(self): self.assertFalse(check({**GOOD,"max_uses":True})[0])
if __name__ == "__main__": unittest.main()
