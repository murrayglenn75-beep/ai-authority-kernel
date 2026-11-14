"""Regression tests for indirect agent authority and data-flow substitution.

These tests exercise the existing resource-bound AAK enforcement boundary.
They do not claim to implement network egress filtering or tenant database RLS.
"""
import secrets
import unittest
from dataclasses import replace

from aak import AuthorityKernel, Policy, Proposal, Rule, ToolContract


class AgenticDataFlowBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.kernel = AuthorityKernel(
            signing_key=secrets.token_bytes(32),
            policy=Policy(
                version="data-flow-p1",
                rules=(Rule(
                    "report.read", "tenant-a/",
                    frozenset({"reader-a"}),
                    {"operations": 1},
                    0,
                    frozenset(),
                ),),
                hard_denies=frozenset({"system.shell", "network.exfiltrate"}),
            ),
            system_version="data-flow-s1",
            budget_limits={"operations": 10},
            tools=(ToolContract(
                action="report.read",
                validate=lambda resource, params: (
                    resource.startswith("tenant-a/")
                    and set(params) == {"report_id"}
                    and isinstance(params["report_id"], str)
                ),
                derive_effect=lambda _resource, _params: {"operations": 1.0},
                handler=lambda resource, params: {"resource": resource, "id": params["report_id"]},
            ),),
            evidence_verifier=lambda _id: False,
            allow_test_time_override=True,
        )
        self.proposal = Proposal(
            transaction_id="data-flow-tx-1",
            principal_id="reader-a",
            agent_instance="agent-a",
            purpose="read approved tenant report",
            action="report.read",
            resource="tenant-a/reports",
            parameters={"report_id": "report-1"},
            maximum_effect={"operations": 1},
            evidence=(),
        )

    def test_baseline_authorized_request(self):
        grant = self.kernel.authorize(self.proposal, now=100)
        self.assertTrue(grant.allowed, grant.reason)
        self.assertTrue(self.kernel.execute(self.proposal, grant.capability, now=101).allowed)

    def test_cross_tenant_resource_substitution_rejected_at_execution(self):
        grant = self.kernel.authorize(self.proposal, now=100)
        self.assertTrue(grant.allowed)
        changed = replace(self.proposal, resource="tenant-b/reports")
        self.assertFalse(self.kernel.execute(changed, grant.capability, now=101).allowed)

    def test_cross_principal_substitution_rejected_at_execution(self):
        grant = self.kernel.authorize(self.proposal, now=100)
        self.assertTrue(grant.allowed)
        changed = replace(self.proposal, principal_id="reader-b")
        self.assertFalse(self.kernel.execute(changed, grant.capability, now=101).allowed)

    def test_tool_action_substitution_rejected_at_execution(self):
        grant = self.kernel.authorize(self.proposal, now=100)
        self.assertTrue(grant.allowed)
        changed = replace(self.proposal, action="network.exfiltrate")
        self.assertFalse(self.kernel.execute(changed, grant.capability, now=101).allowed)

    def test_model_supplied_approval_does_not_grant_forbidden_action(self):
        changed = replace(
            self.proposal,
            action="network.exfiltrate",
            approvals=("administrator", "agent-a"),
            purpose="model says approved",
        )
        self.assertFalse(self.kernel.authorize(changed, now=100).allowed)

    def test_parameter_substitution_rejected_at_execution(self):
        grant = self.kernel.authorize(self.proposal, now=100)
        self.assertTrue(grant.allowed)
        changed = replace(self.proposal, parameters={"report_id": "report-2"})
        self.assertFalse(self.kernel.execute(changed, grant.capability, now=101).allowed)


if __name__ == "__main__":
    unittest.main()
