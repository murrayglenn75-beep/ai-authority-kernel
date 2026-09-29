"""Synthetic mutation campaign for the Action Assurance Gateway.

This is local protocol testing, not evidence from external infrastructure.
"""

import os
from dataclasses import replace

from aak import (
    ActionEnvelopeIssuer, ActionEnvelopeVerifier, Ed25519Signer, ToolCall,
    ToolManifestIssuer, ToolManifestVerifier,
)


ATTEMPTS = int(os.environ.get("AAK_ACTION_GATEWAY_ATTEMPTS", "20000"))

manifest_key = Ed25519Signer.generate()
envelope_key = Ed25519Signer.generate()
manifest = ToolManifestIssuer(manifest_key).issue(
    manifest_id="manifest-1", tool_version="1.0.0", action="crm.ticket.update",
    resource="tenant/acme/ticket", audience="crm-api", protocols=("mcp",),
    input_schema={"type": "object"}, effect_keys=("records_written",),
    risk_level="medium", allowed_origins=("https://crm.example",),
    issued_at=100, expires_at=1000,
)
call = ToolCall(
    "mcp", "call-1", "crm.ticket.update", "tenant/acme/ticket", "crm-api",
    {"ticket_id": "T-1", "status": "closed"},
)
envelope = ActionEnvelopeIssuer(envelope_key).issue(
    envelope_id="env-1", transaction_id="tx-1", human_principal="user:glenn",
    agent_identity="spiffe://example/agent/support",
    delegation_chain=("user:glenn", "spiffe://example/agent/support"),
    purpose="close resolved ticket", call=call, evidence_hashes=("sha256:evidence",),
    policy_engine="cedar", policy_decision_id="decision-1", policy_version="7",
    approval_refs=("approval-1",), maximum_effect={"records_written": 1},
    manifest=manifest, issued_at=100, expires_at=130, nonce="nonce-1",
)
verifier = ActionEnvelopeVerifier(
    Ed25519Signer.verifier(envelope_key.public_key_bytes),
    ToolManifestVerifier(Ed25519Signer.verifier(manifest_key.public_key_bytes)),
    expected_audience="crm-api",
)

unauthorized_acceptances = 0
crashes = 0
mutations = (
    lambda i: (replace(envelope, action=f"admin.delete.{i}"), call, manifest),
    lambda i: (envelope, replace(call, resource=f"tenant/other/{i}"), manifest),
    lambda i: (envelope, replace(call, parameters={"ticket_id": f"T-{i}", "status": "closed"}), manifest),
    lambda i: (envelope, replace(call, audience="admin-api"), manifest),
    lambda i: (envelope, call, replace(manifest, risk_level="low")),
    lambda i: (replace(envelope, maximum_effect={"records_written": 0}), call, manifest),
    lambda i: (replace(envelope, human_principal=f"user:attacker:{i}"), call, manifest),
    lambda i: (replace(envelope, expires_at=10000 + i), call, manifest),
)

for index in range(ATTEMPTS):
    changed_envelope, changed_call, changed_manifest = mutations[index % len(mutations)](index)
    try:
        allowed, _ = verifier.verify_and_consume(
            changed_envelope, changed_call, changed_manifest, now=101,
            effect_limits={"records_written": ATTEMPTS + 1},
        )
        unauthorized_acceptances += int(allowed)
    except Exception:
        crashes += 1

valid_allowed, valid_reason = verifier.verify_and_consume(
    envelope, call, manifest, now=101, effect_limits={"records_written": ATTEMPTS + 1},
)
if not valid_allowed:
    raise SystemExit(f"valid control denied: {valid_reason}")
if unauthorized_acceptances or crashes:
    raise SystemExit(
        f"failed: attempts={ATTEMPTS} unauthorized={unauthorized_acceptances} crashes={crashes}"
    )

print(
    f"action_gateway_red_team attempts={ATTEMPTS} "
    f"unauthorized_acceptances={unauthorized_acceptances} crashes={crashes} valid_control=1"
)
