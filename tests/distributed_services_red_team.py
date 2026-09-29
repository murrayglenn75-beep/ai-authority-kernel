"""Synthetic mutation gate for gateway-to-resource service separation."""

import json
import os
from dataclasses import replace

from aak import (
    ActionEnvelopeIssuer, ActionEnvelopeVerifier, DistributedBoundaryError,
    Ed25519Signer, GatewayGrant, MCPToolAdapter, MCPToolBinding,
    ResourceExecutionService, ToolCall, ToolManifestIssuer, ToolManifestVerifier,
)


class Audit:
    def append(self, _event):
        from aak import AuditReceipt
        return AuditReceipt("red-team-audit", 1, "GENESIS", "hash", "key", "signature")


class Broker:
    def __init__(self): self.calls = 0
    def execute(self, **_): self.calls += 1; return {"ok": True}


def main():
    attempts = int(os.getenv("AAK_DISTRIBUTED_ATTEMPTS", "100000"))
    if attempts < 1 or attempts > 2_000_000:
        raise SystemExit("AAK_DISTRIBUTED_ATTEMPTS must be 1..2000000")
    manifest_key = Ed25519Signer.generate()
    envelope_key = Ed25519Signer.generate()
    manifest = ToolManifestIssuer(manifest_key).issue(
        manifest_id="m1", tool_version="1", action="ticket.close", resource="tenant/ticket",
        audience="crm", protocols=("mcp",), input_schema={"type": "object"},
        effect_keys=("writes",), risk_level="medium", allowed_origins=("https://crm.example",),
        issued_at=100, expires_at=1000,
    )
    call = MCPToolAdapter((MCPToolBinding("close", "ticket.close", "tenant/ticket", "crm"),)).translate(
        {"jsonrpc": "2.0", "id": "1", "method": "tools/call",
         "params": {"name": "close", "arguments": {"ticket": "T-1"}}}
    )
    envelope = ActionEnvelopeIssuer(envelope_key).issue(
        envelope_id="e1", transaction_id="t1", human_principal="user:g",
        agent_identity="spiffe://aak/agent", delegation_chain=("user:g", "spiffe://aak/agent"),
        purpose="close ticket", call=call, evidence_hashes=(), policy_engine="opa",
        policy_decision_id="d1", policy_version="v1", approval_refs=(),
        maximum_effect={"writes": 1}, manifest=manifest, issued_at=100, expires_at=130, nonce="n1",
    )
    verifier = ActionEnvelopeVerifier(
        Ed25519Signer.verifier(envelope_key.public_key_bytes),
        ToolManifestVerifier(Ed25519Signer.verifier(manifest_key.public_key_bytes)),
        expected_audience="crm",
    )
    broker = Broker()
    service = ResourceExecutionService(verifier=verifier, audit=Audit(), broker=broker, quarantine=lambda *_: None)
    mutations = (
        GatewayGrant(call, manifest, replace(envelope, purpose="export all records")),
        GatewayGrant(replace(call, parameters={"ticket": "T-2"}), manifest, envelope),
        GatewayGrant(call, replace(manifest, allowed_origins=("https://evil.invalid",)), envelope),
        GatewayGrant(call, manifest, replace(envelope, audience="other")),
        GatewayGrant(replace(call, protocol="rest"), manifest, envelope),
    )
    unauthorized = crashes = 0
    for index in range(attempts):
        try:
            service.execute(mutations[index % len(mutations)], destination="https://crm.example",
                            now=101, effect_limits={"writes": 10})
            unauthorized += 1
        except DistributedBoundaryError:
            pass
        except Exception:
            crashes += 1
    if broker.calls:
        unauthorized += broker.calls
    print(json.dumps({"attempts": attempts, "unauthorized_acceptances": unauthorized,
                      "broker_calls": broker.calls, "crashes": crashes}, sort_keys=True))
    if unauthorized or crashes:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
