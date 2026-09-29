import unittest
from dataclasses import replace

from aak import (
    ActionEnvelopeIssuer,
    ActionEnvelopeVerifier,
    ActionGatewayError,
    Ed25519Signer,
    MCPToolAdapter,
    MCPToolBinding,
    RESTToolAdapter,
    RESTToolBinding,
    ToolCall,
    ToolManifestIssuer,
    ToolManifestVerifier,
    KeyRegistry, KeyStatus,
)
from aak.crypto import b64encode
from aak.canonical import canonical_bytes


class ActionGatewayTests(unittest.TestCase):
    def setUp(self):
        self.manifest_key = Ed25519Signer.generate()
        self.envelope_key = Ed25519Signer.generate()
        self.manifest_issuer = ToolManifestIssuer(self.manifest_key)
        self.manifest = self.manifest_issuer.issue(
            manifest_id="manifest.crm.ticket.update.v3",
            tool_version="3.1.0",
            action="crm.ticket.update",
            resource="tenant/acme/ticket",
            audience="crm-api",
            protocols=("mcp", "rest"),
            input_schema={"type": "object", "required": ["ticket_id", "status"]},
            effect_keys=("records_written",),
            risk_level="medium",
            allowed_origins=("https://crm.example",),
            issued_at=100,
            expires_at=1000,
        )
        self.call = ToolCall(
            protocol="mcp",
            call_id="call-1",
            action="crm.ticket.update",
            resource="tenant/acme/ticket",
            audience="crm-api",
            parameters={"ticket_id": "T-19", "status": "closed"},
        )
        self.envelope_issuer = ActionEnvelopeIssuer(self.envelope_key)
        self.envelope = self.envelope_issuer.issue(
            envelope_id="env-1",
            transaction_id="tx-1",
            human_principal="user:glenn",
            agent_identity="spiffe://example/agent/support",
            delegation_chain=("user:glenn", "spiffe://example/agent/support"),
            purpose="close resolved support ticket",
            call=self.call,
            evidence_hashes=("sha256:evidence",),
            policy_engine="cedar",
            policy_decision_id="decision-55",
            policy_version="policy-7",
            approval_refs=("approval-1",),
            maximum_effect={"records_written": 1},
            manifest=self.manifest,
            issued_at=100,
            expires_at=130,
            nonce="nonce-1",
        )

    def verifier(self):
        return ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
            expected_audience="crm-api",
        )

    def test_exact_action_is_verified_and_consumed_once(self):
        verifier = self.verifier()
        self.assertEqual(
            verifier.verify_and_consume(
                self.envelope, self.call, self.manifest, now=101,
                effect_limits={"records_written": 10},
            ),
            (True, "consumed"),
        )
        self.assertEqual(
            verifier.verify_and_consume(
                self.envelope, self.call, self.manifest, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "replay",
        )

    def test_parameter_substitution_is_denied(self):
        changed = replace(self.call, parameters={"ticket_id": "T-20", "status": "closed"})
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, changed, self.manifest, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "exact_action_mismatch",
        )

    def test_protocol_substitution_is_denied(self):
        changed = replace(self.call, protocol="rest")
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, changed, self.manifest, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "exact_action_mismatch",
        )

    def test_manifest_substitution_is_denied_even_when_validly_signed(self):
        other = self.manifest_issuer.issue(
            manifest_id="other", tool_version="3.1.1", action="crm.ticket.update",
            resource="tenant/acme/ticket", audience="crm-api", protocols=("mcp",),
            input_schema={"type": "object"}, effect_keys=("records_written",),
            risk_level="low", issued_at=100, expires_at=1000,
        )
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, self.call, other, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "exact_action_mismatch",
        )

    def test_envelope_signature_tamper_is_denied(self):
        changed = replace(self.envelope, purpose="export every customer")
        self.assertEqual(
            self.verifier().verify_and_consume(
                changed, self.call, self.manifest, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "invalid_action_envelope_signature",
        )

    def test_manifest_signature_tamper_is_denied(self):
        changed = replace(self.manifest, risk_level="low")
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, self.call, changed, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "invalid_tool_manifest_signature",
        )

    def test_expired_envelope_and_manifest_are_denied(self):
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, self.call, self.manifest, now=130,
                effect_limits={"records_written": 10},
            )[1],
            "action_envelope_expired_or_not_yet_valid",
        )
        expired_manifest = replace(self.manifest, expires_at=101)
        expired_manifest = replace(
            expired_manifest,
            signature=b64encode(self.manifest_key.sign(canonical_bytes(expired_manifest.claim()))),
        )
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, self.call, expired_manifest, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "tool_manifest_expired_or_not_yet_valid",
        )

    def test_budget_is_checked_atomically(self):
        self.assertEqual(
            self.verifier().verify_and_consume(
                self.envelope, self.call, self.manifest, now=101,
                effect_limits={"records_written": 0},
            )[1],
            "budget_exceeded:user:glenn:records_written",
        )

    def test_terminal_delegation_must_be_executing_agent(self):
        with self.assertRaisesRegex(ActionGatewayError, "delegation_terminal_mismatch"):
            self.envelope_issuer.issue(
                envelope_id="env-x", transaction_id="tx-x", human_principal="user:glenn",
                agent_identity="agent:executor", delegation_chain=("user:glenn", "agent:other"),
                purpose="test", call=self.call, evidence_hashes=(), policy_engine="opa",
                policy_decision_id="d", policy_version="1", approval_refs=(),
                maximum_effect={"records_written": 1}, manifest=self.manifest,
                issued_at=100, expires_at=110, nonce="nonce-x",
            )

    def test_delegation_must_start_with_human_principal(self):
        with self.assertRaisesRegex(ActionGatewayError, "delegation_principal_mismatch"):
            self.envelope_issuer.issue(
                envelope_id="env-x", transaction_id="tx-x", human_principal="user:glenn",
                agent_identity="agent:executor", delegation_chain=("user:other", "agent:executor"),
                purpose="test", call=self.call, evidence_hashes=(), policy_engine="opa",
                policy_decision_id="d", policy_version="1", approval_refs=(),
                maximum_effect={"records_written": 1}, manifest=self.manifest,
                issued_at=100, expires_at=110, nonce="nonce-x",
            )

    def test_manifest_origins_must_be_https_origins_not_paths(self):
        for origin in ("http://api.example", "https://user@api.example", "https://api.example/path"):
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(ActionGatewayError, "invalid_allowed_origin"):
                    self.manifest_issuer.issue(
                        manifest_id="bad", tool_version="1", action="a", resource="r", audience="aud",
                        protocols=("mcp",), input_schema={"type": "object"}, effect_keys=("calls",),
                        risk_level="low", allowed_origins=(origin,), issued_at=1, expires_at=2,
                    )

    def test_fractional_boolean_and_empty_effects_are_rejected(self):
        for effect in ({"records_written": 0.5}, {"records_written": True}, {}):
            with self.subTest(effect=effect):
                with self.assertRaises(ActionGatewayError):
                    self.envelope_issuer.issue(
                        envelope_id="env-x", transaction_id="tx-x", human_principal="user:glenn",
                        agent_identity="agent:executor", delegation_chain=("agent:executor",),
                        purpose="test", call=self.call, evidence_hashes=(), policy_engine="opa",
                        policy_decision_id="d", policy_version="1", approval_refs=(),
                        maximum_effect=effect, manifest=self.manifest,
                        issued_at=100, expires_at=110, nonce="nonce-x",
                    )

    def test_unknown_schema_versions_fail_closed(self):
        changed = replace(self.envelope, schema_version=2)
        self.assertEqual(
            self.verifier().verify_and_consume(
                changed, self.call, self.manifest, now=101,
                effect_limits={"records_written": 10},
            )[1],
            "unsupported_action_envelope_schema",
        )

    def test_signed_contracts_round_trip_through_json_wire_shape(self):
        manifest_wire = self.manifest.to_wire()
        envelope_wire = self.envelope.to_wire()
        decoded_manifest = type(self.manifest).from_wire(manifest_wire)
        decoded_envelope = type(self.envelope).from_wire(envelope_wire)
        self.assertEqual(decoded_manifest, self.manifest)
        self.assertEqual(decoded_envelope, self.envelope)
        self.assertTrue(self.verifier().verify_and_consume(
            decoded_envelope, self.call, decoded_manifest, now=101,
            effect_limits={"records_written": 10},
        )[0])

    def test_overlapping_key_rotation_accepts_new_key_and_revocation_denies_old_key(self):
        new_manifest_key = Ed25519Signer.generate()
        new_envelope_key = Ed25519Signer.generate()
        new_manifest = ToolManifestIssuer(new_manifest_key).issue(
            manifest_id="manifest.crm.ticket.update.v4", tool_version="4.0.0",
            action="crm.ticket.update", resource="tenant/acme/ticket", audience="crm-api",
            protocols=("mcp",), input_schema={"type": "object"},
            effect_keys=("records_written",), risk_level="medium",
            allowed_origins=("https://crm.example",), issued_at=100, expires_at=1000,
        )
        new_envelope = ActionEnvelopeIssuer(new_envelope_key).issue(
            envelope_id="env-new", transaction_id="tx-new", human_principal="user:glenn",
            agent_identity="spiffe://example/agent/support",
            delegation_chain=("user:glenn", "spiffe://example/agent/support"),
            purpose="close ticket", call=self.call, evidence_hashes=(), policy_engine="opa",
            policy_decision_id="decision-new", policy_version="8", approval_refs=(),
            maximum_effect={"records_written": 1}, manifest=new_manifest,
            issued_at=100, expires_at=130, nonce="nonce-new",
        )
        manifest_registry = KeyRegistry((
            KeyStatus(Ed25519Signer.verifier(self.manifest_key.public_key_bytes), 90, 200),
            KeyStatus(Ed25519Signer.verifier(new_manifest_key.public_key_bytes), 100, 300),
        ))
        envelope_registry = KeyRegistry((
            KeyStatus(Ed25519Signer.verifier(self.envelope_key.public_key_bytes), 90, 200),
            KeyStatus(Ed25519Signer.verifier(new_envelope_key.public_key_bytes), 100, 300),
        ))
        old_verifier = ActionEnvelopeVerifier(
            envelope_registry, ToolManifestVerifier(manifest_registry), expected_audience="crm-api",
        )
        self.assertTrue(old_verifier.verify(self.envelope, self.call, self.manifest, now=101)[0])
        self.assertTrue(old_verifier.verify(new_envelope, self.call, new_manifest, now=101)[0])
        self.assertTrue(manifest_registry.revoke(self.manifest.key_id, 102))
        self.assertTrue(envelope_registry.revoke(self.envelope.key_id, 102))
        self.assertEqual(old_verifier.verify(self.envelope, self.call, self.manifest, now=103)[1],
                         "wrong_tool_manifest_key")
        self.assertTrue(old_verifier.verify(new_envelope, self.call, new_manifest, now=103)[0])

    def test_wire_decoders_reject_extra_missing_and_wrong_collection_types(self):
        manifest_wire = self.manifest.to_wire()
        envelope_wire = self.envelope.to_wire()
        cases = (
            (type(self.manifest).from_wire, {**manifest_wire, "extra": True}),
            (type(self.envelope).from_wire, {key: value for key, value in envelope_wire.items() if key != "nonce"}),
            (type(self.envelope).from_wire, {**envelope_wire, "delegation_chain": "not-an-array"}),
        )
        for decoder, value in cases:
            with self.subTest(decoder=decoder):
                with self.assertRaises(ActionGatewayError):
                    decoder(value)

    def test_mcp_adapter_uses_operator_owned_destination(self):
        adapter = MCPToolAdapter((MCPToolBinding(
            "close_ticket", "crm.ticket.update", "tenant/acme/ticket", "crm-api",
        ),))
        call = adapter.translate({
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "close_ticket", "arguments": {"ticket_id": "T-19", "url": "https://evil"}},
        })
        self.assertEqual(call.resource, "tenant/acme/ticket")
        self.assertEqual(call.audience, "crm-api")
        self.assertEqual(call.call_id, "8")

    def test_mcp_extra_fields_unknown_tools_and_invalid_ids_fail_closed(self):
        adapter = MCPToolAdapter((MCPToolBinding("close_ticket", "a", "r", "aud"),))
        base = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "close_ticket", "arguments": {}}}
        cases = (
            {**base, "extra": True},
            {**base, "params": {"name": "unknown", "arguments": {}}},
            {**base, "id": True},
            {**base, "params": {"name": ["close_ticket"], "arguments": {}}},
        )
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ActionGatewayError):
                    adapter.translate(request)

    def test_rest_adapter_binds_method_and_route(self):
        adapter = RESTToolAdapter((RESTToolBinding(
            "POST", "/v1/tickets/close", "crm.ticket.update", "tenant/acme/ticket", "crm-api",
        ),))
        call = adapter.translate(
            method="post", route="/v1/tickets/close", request_id="req-1",
            body={"ticket_id": "T-19"},
        )
        self.assertEqual(call.protocol, "rest")
        with self.assertRaisesRegex(ActionGatewayError, "unregistered_rest_operation"):
            adapter.translate(
                method="DELETE", route="/v1/tickets/close", request_id="req-2",
                body={"ticket_id": "T-19"},
            )

    def test_oversized_parameters_fail_before_authorization(self):
        call = replace(self.call, parameters={"value": "x" * (64 * 1024)})
        with self.assertRaisesRegex(ActionGatewayError, "parameters_too_large"):
            call.validate()


if __name__ == "__main__":
    unittest.main()
