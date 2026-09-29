"""Malformed remote-service request campaign; no provider call is permitted."""

import json
import os
import tempfile
from pathlib import Path

from aak import (
    ActionEnvelopeVerifier, DistributedBoundaryError, Ed25519Signer,
    EffectBrokerEndpoint, InputPolicy, SQLiteBrokerReplayStore, ToolManifestVerifier,
    VerifyingEffectBroker,
)
from test_distributed import DistributedServiceTests, valid_close


def main():
    attempts = int(os.getenv("AAK_SERVICE_ATTEMPTS", "100000"))
    if attempts < 1 or attempts > 2_000_000:
        raise SystemExit("AAK_SERVICE_ATTEMPTS must be 1..2000000")
    fixture = DistributedServiceTests(methodName="test_exact_grant_executes_once_without_exposing_credential")
    fixture.setUp()
    provider_calls = []
    with tempfile.TemporaryDirectory() as directory:
        endpoint = EffectBrokerEndpoint(
            VerifyingEffectBroker(
                verifier=ActionEnvelopeVerifier(
                    Ed25519Signer.verifier(fixture.envelope_key.public_key_bytes),
                    ToolManifestVerifier(Ed25519Signer.verifier(fixture.manifest_key.public_key_bytes)),
                    expected_audience="crm-api",
                ),
                provider=lambda **values: provider_calls.append(values) or {"ok": True},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=fixture.audit_id,
                audit_verifiers={
                    fixture.audit_key.key_id: Ed25519Signer.verifier(fixture.audit_key.public_key_bytes),
                },
                replay_store=SQLiteBrokerReplayStore(Path(directory) / "broker.db"),
                input_policies={
                    "crm.ticket.update": InputPolicy(fixture.manifest.input_schema_hash, valid_close),
                },
            ),
            allowed_peers=frozenset({"spiffe://aak/resource"}),
            clock=lambda: 102,
        )
        valid = {
            "origin": "https://crm.example", "audience": "crm-api", "action_hash": "wrong",
            "call": fixture.grant.call.to_wire(), "grant": fixture.grant.to_wire(),
            "authorization_event": {},
            "authorization_receipt": {
                "anchor_id": fixture.audit_id, "sequence": 1,
                "previous_hash": "GENESIS", "event_hash": "fake",
                "key_id": fixture.audit_key.key_id, "signature": "bad",
            },
        }
        cases = (
            ("/v1/effects/execute", {**valid, "debug": True}, "spiffe://aak/resource"),
            ("/v1/effects/execute", {key: value for key, value in valid.items() if key != "grant"}, "spiffe://aak/resource"),
            ("/v1/effects/execute", {**valid, "now": 1}, "spiffe://aak/resource"),
            ("/v1/effects/execute", valid, "spiffe://aak/evil"),
            ("/v1/admin", valid, "spiffe://aak/resource"),
            ("/v1/effects/execute", {**valid, "grant": {"bad": True}}, "spiffe://aak/resource"),
        )
        unauthorized = crashes = 0
        for index in range(attempts):
            path, body, peer = cases[index % len(cases)]
            try:
                endpoint.handle(path, body, peer_identity=peer)
                unauthorized += 1
            except DistributedBoundaryError:
                pass
            except Exception:
                crashes += 1
    unauthorized += len(provider_calls)
    print(json.dumps({"attempts": attempts, "provider_calls": len(provider_calls),
                      "unauthorized_acceptances": unauthorized, "crashes": crashes}, sort_keys=True))
    if unauthorized or crashes:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
