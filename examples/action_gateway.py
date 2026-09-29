"""Minimal MCP-to-resource Action Assurance Gateway flow."""

from aak import (
    ActionEnvelopeIssuer, ActionEnvelopeVerifier, Ed25519Signer,
    MCPToolAdapter, MCPToolBinding, ToolManifestIssuer, ToolManifestVerifier,
)


manifest_signer = Ed25519Signer.generate()
authority_signer = Ed25519Signer.generate()

adapter = MCPToolAdapter((MCPToolBinding(
    tool_name="close_ticket",
    action="crm.ticket.update",
    resource="tenant/acme/ticket",
    audience="crm-api",
),))
call = adapter.translate({
    "jsonrpc": "2.0",
    "id": "call-1",
    "method": "tools/call",
    "params": {"name": "close_ticket", "arguments": {"ticket_id": "T-19", "status": "closed"}},
})

manifest = ToolManifestIssuer(manifest_signer).issue(
    manifest_id="crm-close-ticket-v1", tool_version="1.0.0",
    action=call.action, resource=call.resource, audience=call.audience,
    protocols=("mcp", "rest"),
    input_schema={"type": "object", "required": ["ticket_id", "status"]},
    effect_keys=("records_written",), risk_level="medium",
    allowed_origins=("https://crm.example",), issued_at=100, expires_at=1000,
)

envelope = ActionEnvelopeIssuer(authority_signer).issue(
    envelope_id="env-1", transaction_id="tx-1", human_principal="user:glenn",
    agent_identity="spiffe://example/agent/support",
    delegation_chain=("user:glenn", "spiffe://example/agent/support"),
    purpose="close a resolved support ticket", call=call,
    evidence_hashes=("sha256:ticket-resolution-evidence",),
    policy_engine="cedar", policy_decision_id="decision-55", policy_version="7",
    approval_refs=("approval-1",), maximum_effect={"records_written": 1},
    manifest=manifest, issued_at=100, expires_at=130, nonce="single-use-nonce",
)

# This verifier belongs beside the real CRM resource, not in the model process.
verifier = ActionEnvelopeVerifier(
    Ed25519Signer.verifier(authority_signer.public_key_bytes),
    ToolManifestVerifier(Ed25519Signer.verifier(manifest_signer.public_key_bytes)),
    expected_audience="crm-api",
)
allowed, reason = verifier.verify_and_consume(
    envelope, call, manifest, now=101, effect_limits={"records_written": 10},
)
print({"allowed": allowed, "reason": reason, "request_hash": call.request_hash})
