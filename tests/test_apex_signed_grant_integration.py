"""APEX contract integration: real AAK signature, scope, consumption and replay tests.

No execution broker is invoked. Tests operate only on AAK in-memory state.
"""
import unittest
from dataclasses import replace

from aak import (Ed25519Signer, ToolCall, ToolManifestIssuer,
                 ToolManifestVerifier, ActionEnvelopeIssuer, ActionEnvelopeVerifier)


class ApexSignedGrantIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.manifest_signer = Ed25519Signer.generate()
        self.grant_signer = Ed25519Signer.generate()
        self.call = ToolCall(
            "native", "task.001", "engineering.run_tests",
            "workspace:fixture-one", "apex-executor",
            {"proposal_id": "p001", "base_sha256": "a" * 64,
             "result_sha256": "b" * 64},
        )
        self.manifest = ToolManifestIssuer(self.manifest_signer).issue(
            manifest_id="apex-fixture-tests", tool_version="0.27",
            action=self.call.action, resource=self.call.resource,
            audience=self.call.audience, protocols=("native",),
            input_schema={"type": "object"}, effect_keys=("test_runs",),
            risk_level="low", issued_at=100, expires_at=1000,
        )
        self.grant = ActionEnvelopeIssuer(self.grant_signer).issue(
            envelope_id="apex-grant-001", transaction_id="apex-tx-001",
            human_principal="human:test", agent_identity="agent:apex",
            delegation_chain=("human:test", "agent:apex"),
            purpose="approved fixture-only test", call=self.call,
            evidence_hashes=(), policy_engine="operator-policy",
            policy_decision_id="approved-fixture-001", policy_version="1",
            approval_refs=("human-approved-001",),
            maximum_effect={"test_runs": 1}, manifest=self.manifest,
            issued_at=100, expires_at=150, nonce="apex-nonce-001",
        )
        self.verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.grant_signer.public_key_bytes),
            ToolManifestVerifier(
                Ed25519Signer.verifier(self.manifest_signer.public_key_bytes)),
            expected_audience="apex-executor",
        )

    def consume(self, call=None, grant=None, limit=10, now=101):
        return self.verifier.verify_and_consume(
            self.grant if grant is None else grant,
            self.call if call is None else call,
            self.manifest, now=now, effect_limits={"test_runs": limit})

    def test_valid_signed_fixture_consumes_once(self):
        self.assertEqual(self.consume(), (True, "consumed"))

    def test_replay_denied(self):
        self.assertTrue(self.consume()[0])
        self.assertEqual(self.consume()[1], "replay")

    def test_parameter_mutation_denied_without_consuming_original(self):
        changed = replace(self.call, parameters={**self.call.parameters,
                          "result_sha256": "c" * 64})
        self.assertEqual(self.consume(call=changed)[1], "exact_action_mismatch")
        self.assertTrue(self.consume()[0])

    def test_workspace_mutation_denied(self):
        changed = replace(self.call, resource="workspace:fixture-two")
        self.assertEqual(self.consume(call=changed)[1], "exact_action_mismatch")

    def test_action_escalation_denied(self):
        changed = replace(self.call, action="engineering.apply_patch")
        self.assertEqual(self.consume(call=changed)[1], "exact_action_mismatch")

    def test_wrong_audience_denied(self):
        changed = replace(self.call, audience="other-executor")
        self.assertEqual(self.consume(call=changed)[1], "action_audience_mismatch")

    def test_signed_grant_tamper_denied(self):
        changed = replace(self.grant, purpose="unapproved patch")
        self.assertEqual(self.consume(grant=changed)[1], "invalid_action_envelope_signature")

    def test_expired_grant_denied(self):
        self.assertEqual(self.consume(now=150)[1],
                         "action_envelope_expired_or_not_yet_valid")

    def test_budget_rejected_without_consuming(self):
        self.assertEqual(self.consume(limit=0)[1],
                         "budget_exceeded:human:test:test_runs")
        self.assertTrue(self.consume()[0])

    def test_no_commands_or_provider_calls(self):
        self.assertFalse(hasattr(self.verifier, "run_shell_command"))
        self.assertTrue(self.consume()[0])


if __name__ == "__main__":
    unittest.main()
