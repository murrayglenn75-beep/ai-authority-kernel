import json
from contextlib import contextmanager
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aak import (
    ActionEnvelopeIssuer, ActionEnvelopeVerifier, AuthenticatedGatewayContext,
    DistributedBoundaryError, DurableAuditAnchor, Ed25519Signer, GatewayService,
    InputPolicy, MCPToolAdapter, MCPToolBinding, OIDCWorkloadVerifier, OPAClient,
    ProviderRejectedError,
    ResourceExecutionService, ToolManifestIssuer, ToolManifestVerifier,
    SQLiteBrokerReplayStore, VerifyingEffectBroker,
)
from aak.crypto import b64encode
from aak.canonical import digest


def jwt(key, payload):
    header = b64encode(b'{"alg":"EdDSA","kid":"identity-1","typ":"JWT"}')
    body = b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    message = f"{header}.{body}".encode()
    return f"{header}.{body}.{b64encode(key.sign(message))}"


def valid_close(parameters):
    return (
        isinstance(parameters, dict)
        and set(parameters) == {"ticket_id", "status"}
        and isinstance(parameters["ticket_id"], str)
        and parameters["status"] == "closed"
    )


class Broker:
    def __init__(self, fail=False): self.calls = 0; self.fail = fail
    def execute(self, **values):
        self.calls += 1
        if self.fail: raise RuntimeError("provider down")
        self.last = values
        return {"provider_reference": "ref-1", "status": "closed"}


class FailingAudit:
    def __init__(self, fail_on): self.calls = 0; self.fail_on = fail_on
    def append(self, _event):
        self.calls += 1
        if self.calls >= self.fail_on: raise RuntimeError("audit down")
        from aak import AuditReceipt
        return AuditReceipt("aak-test-audit", self.calls, "GENESIS", "hash", "key", "sig")


class DistributedServiceTests(unittest.TestCase):
    @contextmanager
    def temporary_directory(self):
        # Close owned SQLite connections before Windows removes temporary files.
        self._owned_sqlite = []
        try:
            with tempfile.TemporaryDirectory() as directory:
                try:
                    yield directory
                finally:
                    for resource in reversed(self._owned_sqlite):
                        resource.close()
        finally:
            self._owned_sqlite = []

    def audit_anchor(self, *args, **kwargs):
        resource = DurableAuditAnchor(*args, **kwargs)
        self._owned_sqlite.append(resource)
        return resource

    def replay_store(self, *args, **kwargs):
        resource = SQLiteBrokerReplayStore(*args, **kwargs)
        self._owned_sqlite.append(resource)
        return resource

    def setUp(self):
        self.identity_key = Ed25519PrivateKey.generate()
        self.manifest_key = Ed25519Signer.generate()
        self.envelope_key = Ed25519Signer.generate()
        self.audit_key = Ed25519Signer.generate()
        self.audit_id = "aak-test-audit"
        self.manifest = ToolManifestIssuer(self.manifest_key).issue(
            manifest_id="crm-close-v1", tool_version="1.0.0", action="crm.ticket.update",
            resource="tenant/acme/ticket", audience="crm-api", protocols=("mcp",),
            input_schema={"type": "object"}, effect_keys=("records_written",),
            risk_level="medium", allowed_origins=("https://crm.example",),
            issued_at=100, expires_at=1000,
        )
        response = {"result": {"allow": True, "decision_id": "opa-1", "policy_version": "v1",
                               "maximum_effect": {"records_written": 1}, "approval_refs": []}}
        counter = iter(f"id-{number}" for number in range(1000))
        self.gateway = GatewayService(
            adapter=MCPToolAdapter((MCPToolBinding(
                "close_ticket", "crm.ticket.update", "tenant/acme/ticket", "crm-api",
            ),)),
            identity=OIDCWorkloadVerifier(
                issuer="https://identity.internal", audience="resource-verifier",
                public_keys={"identity-1": self.identity_key.public_key().public_bytes_raw()},
                maximum_lifetime=60,
            ),
            policy=OPAClient("https://opa.internal/v1/data/aak/authority/decision", lambda *_: response),
            issuer=ActionEnvelopeIssuer(self.envelope_key),
            manifests={"crm.ticket.update": self.manifest}, maximum_ttl=20,
            id_factory=lambda: next(counter),
            input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
        )
        payload = {"iss": "https://identity.internal", "sub": "spiffe://aak/agent/support",
                   "aud": "resource-verifier", "iat": 100, "nbf": 100, "exp": 130,
                   "jti": "identity-token-1", "cnf": {"x5t#S256": "cert-1"}}
        self.context = AuthenticatedGatewayContext("user:glenn", "close resolved ticket", jwt(self.identity_key, payload), "cert-1")
        self.request = {"jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
                        "params": {"name": "close_ticket", "arguments": {"ticket_id": "T-1", "status": "closed"}}}
        self.grant = self.gateway.authorize_mcp(self.request, self.context, now=101)

    def resource(self, audit, broker, quarantine):
        verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
            expected_audience="crm-api",
        )
        return ResourceExecutionService(verifier=verifier, audit=audit, broker=broker, quarantine=quarantine)

    def test_exact_grant_executes_once_without_exposing_credential(self):
        with self.temporary_directory() as directory:
            audit = self.audit_anchor(Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id)
            broker = Broker()
            quarantined = []
            service = self.resource(audit, broker, lambda *value: quarantined.append(value))
            outcome = service.execute(self.grant, destination="https://crm.example/v1/tickets", now=102,
                                      effect_limits={"records_written": 10})
            self.assertTrue(outcome.committed)
            self.assertFalse(outcome.quarantined)
            self.assertEqual(broker.calls, 1)
            self.assertNotIn("credential", broker.last)
            self.assertTrue(audit.verify_chain())
            with self.assertRaisesRegex(DistributedBoundaryError, "replay"):
                service.execute(self.grant, destination="https://crm.example/v1/tickets", now=102,
                                effect_limits={"records_written": 10})
            self.assertEqual(broker.calls, 1)

    def test_gateway_grant_round_trip_and_unknown_fields_fail_closed(self):
        from aak import GatewayGrant
        wire = self.grant.to_wire()
        self.assertEqual(GatewayGrant.from_wire(wire), self.grant)
        with self.assertRaisesRegex(DistributedBoundaryError, "malformed_gateway_grant"):
            GatewayGrant.from_wire({**wire, "debug": True})

    def test_audit_outage_before_effect_denies_and_quarantines(self):
        broker = Broker()
        quarantined = []
        service = self.resource(FailingAudit(1), broker, lambda *value: quarantined.append(value))
        with self.assertRaisesRegex(DistributedBoundaryError, "authorization_audit_unavailable"):
            service.execute(self.grant, destination="https://crm.example", now=102,
                            effect_limits={"records_written": 10})
        self.assertEqual(broker.calls, 0)
        self.assertEqual(quarantined[0][1], "authorization_audit_unavailable")

    def test_audit_and_quarantine_outage_is_reported_without_effect(self):
        broker = Broker()
        service = self.resource(FailingAudit(1), broker, lambda *_: (_ for _ in ()).throw(RuntimeError()))
        with self.assertRaisesRegex(DistributedBoundaryError, "authorization_audit_and_quarantine_unavailable"):
            service.execute(self.grant, destination="https://crm.example", now=102,
                            effect_limits={"records_written": 10})
        self.assertEqual(broker.calls, 0)

    def test_audit_outage_after_effect_reports_committed_and_quarantines(self):
        broker = Broker()
        quarantined = []
        service = self.resource(FailingAudit(2), broker, lambda *value: quarantined.append(value))
        outcome = service.execute(self.grant, destination="https://crm.example", now=102,
                                  effect_limits={"records_written": 10})
        self.assertTrue(outcome.committed)
        self.assertTrue(outcome.quarantined)
        self.assertEqual(outcome.reason, "committed_audit_unavailable")
        self.assertEqual(broker.calls, 1)

    def test_unknown_provider_failure_is_ambiguous_and_quarantined(self):
        with self.temporary_directory() as directory:
            audit = self.audit_anchor(Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id)
            quarantined = []
            outcome = self.resource(
                audit, Broker(fail=True), lambda *value: quarantined.append(value),
            ).execute(
                self.grant, destination="https://crm.example", now=102,
                effect_limits={"records_written": 10},
            )
            self.assertFalse(outcome.committed)
            self.assertTrue(outcome.quarantined)
            self.assertEqual(outcome.reason, "provider_outcome_ambiguous")
            self.assertEqual(quarantined[0][1], "provider_outcome_ambiguous")
            self.assertTrue(audit.verify_chain())

    def test_definitive_provider_rejection_is_retry_safe_and_not_quarantined(self):
        class RejectedBroker:
            def execute(self, **_values):
                raise ProviderRejectedError("rejected_before_effect")

        with self.temporary_directory() as directory:
            audit = self.audit_anchor(Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id)
            outcome = self.resource(audit, RejectedBroker(), lambda *_: None).execute(
                self.grant, destination="https://crm.example", now=102,
                effect_limits={"records_written": 10},
            )
            self.assertFalse(outcome.committed)
            self.assertFalse(outcome.quarantined)
            self.assertEqual(outcome.reason, "provider_rejected")
            self.assertTrue(audit.verify_chain())

    def test_broker_boundary_denial_is_quarantined_and_not_mislabeled_provider_failure(self):
        class DenyingBroker:
            def execute(self, **_values):
                raise DistributedBoundaryError("broker_replay_store_unavailable")

        with self.temporary_directory() as directory:
            audit = self.audit_anchor(
                Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
            )
            quarantined = []
            outcome = self.resource(
                audit, DenyingBroker(), lambda *value: quarantined.append(value),
            ).execute(
                self.grant, destination="https://crm.example", now=102,
                effect_limits={"records_written": 10},
            )
            self.assertFalse(outcome.committed)
            self.assertTrue(outcome.quarantined)
            self.assertEqual(outcome.reason, "broker_denied")
            self.assertEqual(quarantined[0][1], "broker_boundary_denied")
            self.assertTrue(audit.verify_chain())

    def test_credential_broker_independently_verifies_signed_grant(self):
        verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
            expected_audience="crm-api",
        )
        calls = []
        with self.temporary_directory() as directory:
            action_hash = digest(self.grant.envelope.claim())
            event = {
                "type": "action_authorized", "envelope_id": self.grant.envelope.envelope_id,
                "transaction_id": self.grant.envelope.transaction_id,
                "request_hash": self.grant.call.request_hash,
                "agent_identity": self.grant.envelope.agent_identity,
                "policy_decision_id": self.grant.envelope.policy_decision_id,
                "action_hash": action_hash,
            }
            receipt = self.audit_anchor(
                Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
            ).append(event)
            broker = VerifyingEffectBroker(
                verifier=verifier,
                provider=lambda **values: calls.append(values) or {"provider_reference": "p-1"},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=self.replay_store(Path(directory) / "broker.db"),
                input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            result = broker.execute(
                origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                call=self.grant.call, grant=self.grant, now=102,
                authorization_event=event, authorization_receipt=receipt,
            )
            self.assertEqual(result["provider_reference"], "p-1")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["operation_id"], self.grant.envelope.transaction_id)
            with self.assertRaisesRegex(DistributedBoundaryError, "broker_replay_denied"):
                broker.execute(
                    origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                    call=self.grant.call, grant=self.grant, now=102,
                    authorization_event=event, authorization_receipt=receipt,
                )
            from dataclasses import replace
            changed = replace(self.grant, envelope=replace(self.grant.envelope, purpose="tampered"))
            with self.assertRaisesRegex(DistributedBoundaryError, "broker_invalid_action_envelope_signature"):
                broker.execute(
                    origin="https://crm.example", audience="crm-api", action_hash="wrong",
                    call=changed.call, grant=changed, now=102,
                    authorization_event=event, authorization_receipt=receipt,
                )
            self.assertEqual(len(calls), 1)

    def test_broker_denies_forged_authorization_receipt_before_provider(self):
        verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
            expected_audience="crm-api",
        )
        with self.temporary_directory() as directory:
            calls = []
            broker = VerifyingEffectBroker(
                verifier=verifier, provider=lambda **values: calls.append(values) or {},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=self.replay_store(Path(directory) / "broker.db"),
                input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            action_hash = digest(self.grant.envelope.claim())
            event = {
                "type": "action_authorized", "envelope_id": self.grant.envelope.envelope_id,
                "transaction_id": self.grant.envelope.transaction_id,
                "request_hash": self.grant.call.request_hash,
                "agent_identity": self.grant.envelope.agent_identity,
                "policy_decision_id": self.grant.envelope.policy_decision_id,
                "action_hash": action_hash,
            }
            fake = __import__("aak").AuditReceipt(
                self.audit_id, 1, "GENESIS", "forged", self.audit_key.key_id, "bad",
            )
            with self.assertRaisesRegex(DistributedBoundaryError, "broker_invalid_authorization_proof"):
                broker.execute(
                    origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                    call=self.grant.call, grant=self.grant, now=102,
                    authorization_event=event, authorization_receipt=fake,
                )
            self.assertEqual(calls, [])

    def test_broker_replay_ledger_is_atomic_under_concurrency_and_restart(self):
        verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
            expected_audience="crm-api",
        )
        with self.temporary_directory() as directory:
            action_hash = digest(self.grant.envelope.claim())
            event = {
                "type": "action_authorized", "envelope_id": self.grant.envelope.envelope_id,
                "transaction_id": self.grant.envelope.transaction_id,
                "request_hash": self.grant.call.request_hash,
                "agent_identity": self.grant.envelope.agent_identity,
                "policy_decision_id": self.grant.envelope.policy_decision_id,
                "action_hash": action_hash,
            }
            anchor = self.audit_anchor(
                Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
            )
            receipt = anchor.append(event)
            calls = []
            ledger_path = Path(directory) / "broker.db"
            ledger = self.replay_store(ledger_path)
            broker = VerifyingEffectBroker(
                verifier=verifier, provider=lambda **values: calls.append(values) or {"ok": True},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=ledger,
                input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            accepted = []

            def attempt():
                try:
                    broker.execute(
                        origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                        call=self.grant.call, grant=self.grant, now=102,
                        authorization_event=event, authorization_receipt=receipt,
                    )
                    accepted.append(True)
                except DistributedBoundaryError:
                    pass

            threads = [threading.Thread(target=attempt) for _ in range(50)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(accepted), 1)
            self.assertEqual(len(calls), 1)
            ledger.close()
            restarted = VerifyingEffectBroker(
                verifier=verifier, provider=lambda **values: calls.append(values) or {"ok": True},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=self.replay_store(ledger_path),
                input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            with self.assertRaisesRegex(DistributedBoundaryError, "broker_replay_denied"):
                restarted.execute(
                    origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                    call=self.grant.call, grant=self.grant, now=102,
                    authorization_event=event, authorization_receipt=receipt,
                )
            self.assertEqual(len(calls), 1)

    def test_gateway_denies_parameter_field_smuggling_before_policy(self):
        request = {
            **self.request,
            "params": {
                **self.request["params"],
                "arguments": {
                    **self.request["params"]["arguments"],
                    "admin_override": True,
                },
            },
        }
        payload = {
            "iss": "https://identity.internal", "sub": "spiffe://aak/agent/support",
            "aud": "resource-verifier", "iat": 100, "nbf": 100, "exp": 130,
            "jti": "identity-token-smuggling", "cnf": {"x5t#S256": "cert-1"},
        }
        context = AuthenticatedGatewayContext(
            "user:glenn", "purpose", jwt(self.identity_key, payload), "cert-1",
        )
        with self.assertRaisesRegex(DistributedBoundaryError, "input_schema_denied"):
            self.gateway.authorize_mcp(request, context, now=101)

    def test_broker_independently_denies_validly_signed_smuggled_parameters(self):
        from dataclasses import replace
        from aak import GatewayGrant

        call = replace(
            self.grant.call,
            parameters={**self.grant.call.parameters, "admin_override": True},
        )
        envelope = ActionEnvelopeIssuer(self.envelope_key).issue(
            envelope_id="smuggled-envelope", transaction_id="smuggled-transaction",
            human_principal="user:glenn", agent_identity="spiffe://aak/agent/support",
            delegation_chain=("user:glenn", "spiffe://aak/agent/support"),
            purpose="attempt field smuggling", call=call, evidence_hashes=(),
            policy_engine="opa", policy_decision_id="opa-smuggled",
            policy_version="v1", approval_refs=(), maximum_effect={"records_written": 1},
            manifest=self.manifest, issued_at=101, expires_at=121, nonce="smuggled-nonce",
        )
        grant = GatewayGrant(call, self.manifest, envelope)
        action_hash = digest(envelope.claim())
        event = {
            "type": "action_authorized", "envelope_id": envelope.envelope_id,
            "transaction_id": envelope.transaction_id, "request_hash": call.request_hash,
            "agent_identity": envelope.agent_identity,
            "policy_decision_id": envelope.policy_decision_id,
            "action_hash": action_hash,
        }
        with self.temporary_directory() as directory:
            audit = self.audit_anchor(
                Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
            )
            calls = []
            broker = VerifyingEffectBroker(
                verifier=ActionEnvelopeVerifier(
                    Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
                    ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
                    expected_audience="crm-api",
                ),
                provider=lambda **values: calls.append(values) or {"ok": True},
                allowed_origins=("https://crm.example",), audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=self.replay_store(Path(directory) / "broker.db"),
                input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            with self.assertRaisesRegex(DistributedBoundaryError, "broker_input_schema_denied"):
                broker.execute(
                    origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                    call=call, grant=grant, now=102, authorization_event=event,
                    authorization_receipt=audit.append(event),
                )
            self.assertEqual(calls, [])

    def test_disallowed_egress_never_reaches_broker(self):
        with self.temporary_directory() as directory:
            broker = Broker()
            service = self.resource(
                self.audit_anchor(Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id),
                broker, lambda *_: None,
            )
            with self.assertRaisesRegex(Exception, "egress_denied"):
                service.execute(self.grant, destination="https://crm.example.evil.invalid", now=102,
                                effect_limits={"records_written": 10})
            self.assertEqual(broker.calls, 0)

    def test_policy_effect_contract_substitution_is_denied_at_gateway(self):
        bad = {"result": {"allow": True, "decision_id": "d", "policy_version": "v",
                          "maximum_effect": {"money_cents": 1}, "approval_refs": []}}
        self.gateway.policy = OPAClient("https://opa.internal/v1/data/aak/authority/decision", lambda *_: bad)
        payload = {"iss": "https://identity.internal", "sub": "spiffe://aak/agent/support",
                   "aud": "resource-verifier", "iat": 100, "nbf": 100, "exp": 130,
                   "jti": "identity-token-2", "cnf": {"x5t#S256": "cert-1"}}
        context = AuthenticatedGatewayContext("user:glenn", "purpose", jwt(self.identity_key, payload), "cert-1")
        with self.assertRaisesRegex(DistributedBoundaryError, "policy_effect_contract_mismatch"):
            self.gateway.authorize_mcp(self.request, context, now=101)

    def test_durable_audit_anchor_is_thread_safe_and_monotonic(self):
        with self.temporary_directory() as directory:
            audit = self.audit_anchor(Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id)
            receipts = []
            threads = [threading.Thread(target=lambda i=i: receipts.append(audit.append({"i": i}))) for i in range(100)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(item.sequence for item in receipts), list(range(1, 101)))
            self.assertTrue(audit.verify_chain())

    def test_off_host_checkpoint_detects_valid_prefix_rollback(self):
        with self.temporary_directory() as directory:
            path = Path(directory) / "audit.db"
            audit = self.audit_anchor(path, self.audit_key, anchor_id=self.audit_id)
            audit.append({"event": 1})
            audit.append({"event": 2})
            checkpoint = audit.checkpoint()
            self.assertIsNotNone(checkpoint)
            audit.db.execute("DELETE FROM anchor_events WHERE sequence=2")
            self.assertTrue(audit.verify_chain())
            self.assertFalse(audit.verify_checkpoint(checkpoint))
            audit.close()
            with self.assertRaisesRegex(DistributedBoundaryError, "audit_rollback_detected"):
                self.audit_anchor(
                    path, self.audit_key, anchor_id=self.audit_id,
                    required_checkpoint=checkpoint,
                )

    def test_audit_key_rotation_preserves_historical_chain(self):
        with self.temporary_directory() as directory:
            old_key = Ed25519Signer.generate()
            new_key = Ed25519Signer.generate()
            trusted = {
                old_key.key_id: Ed25519Signer.verifier(old_key.public_key_bytes),
                new_key.key_id: Ed25519Signer.verifier(new_key.public_key_bytes),
            }
            audit = self.audit_anchor(
                Path(directory) / "audit.db", old_key, anchor_id=self.audit_id,
                trusted_verifiers=trusted,
            )
            old_receipt = audit.append({"phase": "old"})
            audit.rotate_signer(new_key)
            new_receipt = audit.append({"phase": "new"})
            self.assertNotEqual(old_receipt.key_id, new_receipt.key_id)
            self.assertTrue(audit.verify_receipt(old_receipt))
            self.assertTrue(audit.verify_receipt(new_receipt))
            self.assertTrue(audit.verify_chain())

    def test_audit_rotation_is_atomic_with_concurrent_appends(self):
        with self.temporary_directory() as directory:
            old_key = Ed25519Signer.generate()
            new_key = Ed25519Signer.generate()
            trusted = {
                old_key.key_id: Ed25519Signer.verifier(old_key.public_key_bytes),
                new_key.key_id: Ed25519Signer.verifier(new_key.public_key_bytes),
            }
            audit = self.audit_anchor(
                Path(directory) / "audit.db", old_key, anchor_id=self.audit_id,
                trusted_verifiers=trusted,
            )
            threads = [
                threading.Thread(target=lambda i=i: audit.append({"event": i}))
                for i in range(100)
            ]
            for thread in threads[:50]:
                thread.start()
            audit.rotate_signer(new_key)
            for thread in threads[50:]:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertTrue(audit.verify_chain())
            self.assertEqual(audit.checkpoint().sequence, 100)

    def test_audit_receipts_and_checkpoints_are_anchor_domain_bound(self):
        with self.temporary_directory() as directory:
            first = self.audit_anchor(
                Path(directory) / "first.db", self.audit_key, anchor_id="environment-a",
            )
            receipt = first.append({"event": "a"})
            second = self.audit_anchor(
                Path(directory) / "second.db", self.audit_key, anchor_id="environment-b",
            )
            second.append({"event": "a"})
            self.assertFalse(second.verify_receipt(receipt))
            self.assertFalse(second.verify_checkpoint(receipt))

    def test_legacy_audit_schema_fails_explicitly_instead_of_relabeling_evidence(self):
        with self.temporary_directory() as directory:
            path = Path(directory) / "legacy.db"
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE anchor_events (sequence INTEGER PRIMARY KEY, event BLOB, "
                "previous_hash TEXT, event_hash TEXT, signature TEXT)"
            )
            db.commit()
            db.close()
            with self.assertRaisesRegex(
                DistributedBoundaryError, "legacy_audit_schema_requires_export",
            ):
                self.audit_anchor(path, self.audit_key, anchor_id=self.audit_id)


if __name__ == "__main__":
    unittest.main()
