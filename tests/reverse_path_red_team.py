"""Reverse-path attack campaign from provider boundary back toward the model."""

import json
import os
import tempfile
from collections import Counter
from dataclasses import replace
from pathlib import Path

from aak import (
    ActionEnvelopeVerifier, DistributedBoundaryError, DurableAuditAnchor,
    Ed25519Signer, InputPolicy, SQLiteBrokerReplayStore, ToolManifestVerifier,
    VerifyingEffectBroker,
)
from aak.canonical import digest
from test_distributed import DistributedServiceTests, valid_close


def main():
    attempts = int(os.getenv("AAK_REVERSE_ATTEMPTS", "100000"))
    if attempts < 1 or attempts > 2_000_000:
        raise SystemExit("AAK_REVERSE_ATTEMPTS must be 1..2000000")
    fixture = DistributedServiceTests(
        methodName="test_exact_grant_executes_once_without_exposing_credential",
    )
    fixture.setUp()
    action_hash = digest(fixture.grant.envelope.claim())
    event = {
        "type": "action_authorized", "envelope_id": fixture.grant.envelope.envelope_id,
        "transaction_id": fixture.grant.envelope.transaction_id,
        "request_hash": fixture.grant.call.request_hash,
        "agent_identity": fixture.grant.envelope.agent_identity,
        "policy_decision_id": fixture.grant.envelope.policy_decision_id,
        "action_hash": action_hash,
    }
    provider_calls = []
    unauthorized = crashes = 0
    unexpected = Counter()
    with tempfile.TemporaryDirectory() as directory:
        audit = DurableAuditAnchor(
            Path(directory) / "audit.db", fixture.audit_key, anchor_id=fixture.audit_id,
        )
        receipt = audit.append(event)
        broker = VerifyingEffectBroker(
            verifier=ActionEnvelopeVerifier(
                Ed25519Signer.verifier(fixture.envelope_key.public_key_bytes),
                ToolManifestVerifier(Ed25519Signer.verifier(fixture.manifest_key.public_key_bytes)),
                expected_audience="crm-api",
            ),
            provider=lambda **values: provider_calls.append(values) or {"ok": True},
            allowed_origins=("https://crm.example",), audit_anchor_id=fixture.audit_id,
            audit_verifiers={
                fixture.audit_key.key_id: Ed25519Signer.verifier(fixture.audit_key.public_key_bytes),
            },
            replay_store=SQLiteBrokerReplayStore(Path(directory) / "broker.db"),
            input_policies={
                "crm.ticket.update": InputPolicy(fixture.manifest.input_schema_hash, valid_close),
            },
        )
        base = {
            "origin": "https://crm.example", "audience": "crm-api",
            "action_hash": action_hash, "call": fixture.grant.call,
            "grant": fixture.grant, "now": 102,
            "authorization_event": event, "authorization_receipt": receipt,
        }
        cases = (
            {**base, "origin": "https://crm.example.evil.invalid"},
            {**base, "audience": "admin-api"},
            {**base, "action_hash": "0" * 64},
            {**base, "now": fixture.grant.envelope.expires_at},
            {**base, "authorization_event": {**event, "debug": True}},
            {**base, "authorization_event": {**event, "action_hash": "0" * 64}},
            {**base, "authorization_receipt": replace(receipt, anchor_id="other-environment")},
            {**base, "authorization_receipt": replace(receipt, key_id="unknown-key")},
            {**base, "authorization_receipt": replace(receipt, signature="bad")},
        )
        for index in range(attempts):
            try:
                broker.execute(**cases[index % len(cases)])
                unauthorized += 1
            except DistributedBoundaryError:
                pass
            except Exception as exc:
                crashes += 1
                unexpected[f"{type(exc).__name__}:{exc}"] += 1
    unauthorized += len(provider_calls)
    result = {
        "attempts": attempts, "provider_calls": len(provider_calls),
        "unauthorized_acceptances": unauthorized, "crashes": crashes,
        "unexpected": dict(unexpected),
    }
    print(json.dumps(result, sort_keys=True))
    if unauthorized or crashes:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
