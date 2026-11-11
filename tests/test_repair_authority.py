import unittest
from dataclasses import replace
from aak import Ed25519Signer
from aak.action_gateway import ActionEnvelopeIssuer, ActionEnvelopeVerifier, ToolManifestIssuer, ToolManifestVerifier, ToolCall
from aak.repair_evidence import RepairProposal, Verification
from aak.repair_authority import authorized_repair_record

H = "a" * 64

class RepairAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.p = RepairProposal("incident-1", "example/repo", "abc123", H, ("log-1",), "failed assertion")
        self.v = Verification(self.p.proposal_id, True, True, H, "ci:independent")
        self.manifest_signer = Ed25519Signer.generate()
        self.action_signer = Ed25519Signer.generate()
        self.manifest = ToolManifestIssuer(self.manifest_signer).issue(
            manifest_id="repair-record-v1", tool_version="1", action="engineering.repair_record.publish",
            resource="engineering/reuse-registry", audience="repair-registry", protocols=("native",),
            input_schema={"type":"object"}, effect_keys=("records_written",), risk_level="medium",
            issued_at=100, expires_at=1000)
        self.call = ToolCall("native", "record-1", "engineering.repair_record.publish",
                             "engineering/reuse-registry", "repair-registry",
                             {"proposal_id":self.p.proposal_id, "artifact_sha256":H})
        self.envelope = ActionEnvelopeIssuer(self.action_signer).issue(
            envelope_id="env-1", transaction_id="tx-1", human_principal="operator",
            agent_identity="agent:repair", delegation_chain=("operator","agent:repair"),
            purpose="publish independently verified repair record", call=self.call,
            evidence_hashes=("sha256:log1",), policy_engine="local", policy_decision_id="decision1",
            policy_version="v1", approval_refs=("approval-1",), maximum_effect={"records_written":1},
            manifest=self.manifest, issued_at=100, expires_at=130, nonce="nonce-1")
        self.verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.action_signer.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_signer.public_key_bytes)),
            expected_audience="repair-registry")
    def attempt(self, **kwargs):
        args=dict(proposal=self.p,verification=self.v,envelope=self.envelope,
                  call=self.call,manifest=self.manifest,verifier=self.verifier,
                  now=101,effect_limits={"records_written":5})
        args.update(kwargs)
        return authorized_repair_record(**args)

    def test_authorized_once(self):
        self.assertTrue(self.attempt()["publishable"])
        self.assertEqual(self.attempt()["reason"], "replay")

    def test_wrong_call_parameters(self):
        call=replace(self.call, parameters={"proposal_id":"other","artifact_sha256":H})
        self.assertEqual(self.attempt(call=call)["reason"],"evidence_binding_mismatch")

    def test_unverified_result_denied(self):
        v=replace(self.v,regression_passed=False)
        self.assertEqual(self.attempt(verification=v)["reason"],"verification_incomplete")

    def test_missing_approval_denied(self):
        self.assertEqual(self.attempt(envelope=replace(self.envelope,approval_refs=()))["reason"],"missing_approval_refs")

    def test_wrong_action_denied(self):
        self.assertEqual(self.attempt(call=replace(self.call,action="engineering.patch.apply"))["reason"],"wrong_publication_action")

    def test_manifest_substitution_denied(self):
        wrong=replace(self.manifest,action="engineering.patch.apply")
        self.assertFalse(self.attempt(manifest=wrong)["publishable"])

    def test_expired_denied(self):
        self.assertFalse(self.attempt(now=131)["publishable"])

    def test_effect_limit_denied(self):
        self.assertFalse(self.attempt(effect_limits={"records_written":0})["publishable"])

if __name__=="__main__":
    unittest.main()
