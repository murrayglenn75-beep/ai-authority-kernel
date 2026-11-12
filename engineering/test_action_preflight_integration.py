"""Contract tests: a denied preflight must not dispatch a simulated action.

These tests deliberately do not represent trusted identity or atomic capability
consumption. They verify the adapter's no-side-effect-on-deny invariant only.
"""
import unittest
from datetime import datetime, timezone
from action_preflight import preflight

class SimulatedDispatcher:
    def __init__(self):
        self.effects = []

    def dispatch(self, approval, request, verified_ids, now):
        allowed, reasons = preflight(
            approval, request, verified_approval_ids=verified_ids, now=now
        )
        if not allowed:
            return {"status": "denied", "reasons": reasons}
        self.effects.append((request["action"], request["resource"]))
        return {"status": "executed"}

class PreflightIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.dispatcher = SimulatedDispatcher()
        self.approval = {
            "approval_id": "approval-123", "principal": "user-1",
            "action": "write", "resource": "record-84",
            "expires_at": "2030-01-01T00:00:00Z",
            "max_cost": "2.00", "max_uses": 1, "used": 0
        }
        self.request = {
            "principal": "user-1", "action": "write",
            "resource": "record-84", "estimated_cost": "1.00"
        }
        self.now = datetime(2026, 11, 12, tzinfo=timezone.utc)

    def run_case(self, approval=None, request=None, ids=None):
        return self.dispatcher.dispatch(
            self.approval if approval is None else approval,
            self.request if request is None else request,
            {"approval-123"} if ids is None else ids,
            self.now
        )

    def test_unverified_approval_no_effect(self):
        self.assertEqual(self.run_case(ids=set())["status"], "denied")
        self.assertEqual(self.dispatcher.effects, [])

    def test_wrong_resource_no_effect(self):
        self.assertEqual(self.run_case(request={**self.request, "resource": "record-83"})["status"], "denied")
        self.assertEqual(self.dispatcher.effects, [])

    def test_expired_approval_no_effect(self):
        self.assertEqual(self.run_case(approval={**self.approval, "expires_at": "2025-01-01T00:00:00Z"})["status"], "denied")
        self.assertEqual(self.dispatcher.effects, [])

    def test_exhausted_approval_no_effect(self):
        self.assertEqual(self.run_case(approval={**self.approval, "used": 1})["status"], "denied")
        self.assertEqual(self.dispatcher.effects, [])

    def test_publication_no_effect(self):
        self.assertEqual(self.run_case(request={**self.request, "is_publication": True})["status"], "denied")
        self.assertEqual(self.dispatcher.effects, [])

    def test_nominal_case_reaches_simulated_tool(self):
        self.assertEqual(self.run_case()["status"], "executed")
        self.assertEqual(self.dispatcher.effects, [("write", "record-84")])

    def test_reading_another_approval_does_not_authorize_this_one(self):
        self.assertEqual(self.run_case(ids={"approval-83"})["status"], "denied")
        self.assertEqual(self.dispatcher.effects, [])

if __name__ == "__main__":
    unittest.main()
