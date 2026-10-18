"""Non-effecting APEX adapter contract tests.

The true signature/consumption properties are covered in AAK's own tests;
these specifically check adapter fail-closed routing. No shell/provider calls.
"""
import unittest
from unittest.mock import patch

from aak.action_gateway import ActionEnvelopeVerifier
from integrations.apex_dry_run import inspect_proposal

CALL = {"protocol": "native", "call_id": "task-1", "action": "run_tests",
        "resource": "fixture-repo", "audience": "test-resource",
        "parameters": {"suite": "unit"}}


class ApexDryRunContractTests(unittest.TestCase):
    def setUp(self):
        self.verifier = object.__new__(ActionEnvelopeVerifier)

    def inspect(self, call=None, verifier=None, now=100):
        return inspect_proposal(CALL if call is None else call, object(), object(),
                                self.verifier if verifier is None else verifier, now=now)

    def test_signed_envelope_verification_is_called(self):
        with patch.object(ActionEnvelopeVerifier, "verify", return_value=(True, "verified")) as check:
            outcome = self.inspect()
            self.assertTrue(outcome.allowed_for_review)
            self.assertEqual(outcome.reason, "verified")
            check.assert_called_once()

    def test_verifier_denial_fails_closed(self):
        with patch.object(ActionEnvelopeVerifier, "verify", return_value=(False, "invalid_signature")):
            self.assertFalse(self.inspect().allowed_for_review)

    def test_unknown_action_rejected_before_verification(self):
        with patch.object(ActionEnvelopeVerifier, "verify") as check:
            self.assertEqual(self.inspect({**CALL, "action": "shell_exec"}).reason, "action_not_allowlisted")
            check.assert_not_called()

    def test_parameters_change_request_hash(self):
        from aak.action_gateway import ToolCall
        self.assertNotEqual(ToolCall.from_wire(CALL).request_hash,
                            ToolCall.from_wire({**CALL, "parameters": {"suite": "all"}}).request_hash)

    def test_nan_parameters_rejected(self):
        self.assertFalse(self.inspect({**CALL, "parameters": {"x": float("nan")}}).allowed_for_review)

    def test_invalid_time_rejected(self):
        self.assertEqual(self.inspect(now=True).reason, "invalid_time")

    def test_verifier_must_be_aak_instance(self):
        self.assertEqual(self.inspect(verifier=object()).reason, "untrusted_verifier")

    def test_unexpected_verifier_failure_not_promoted_to_allow(self):
        with patch.object(ActionEnvelopeVerifier, "verify", side_effect=ValueError("invalid")):
            self.assertFalse(self.inspect().allowed_for_review)


if __name__ == "__main__":
    unittest.main()
