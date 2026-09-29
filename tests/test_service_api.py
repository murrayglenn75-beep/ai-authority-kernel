import tempfile
import unittest
from pathlib import Path

from aak import (
    ActionEnvelopeVerifier, AuditServiceEndpoint, DistributedBoundaryError,
    DurableAuditAnchor, Ed25519Signer, EffectBrokerEndpoint, InputPolicy, RemoteAuditAnchor,
    RemoteEffectBroker, RemoteResourceService, ResourceExecutionService,
    ResourceServiceEndpoint, SQLiteBrokerReplayStore, ToolManifestVerifier,
    VerifyingEffectBroker, ProviderOutcomeAmbiguousError, ProviderRejectedError,
)
from aak.canonical import digest
from test_distributed import DistributedServiceTests, valid_close


class ServiceAPITests(DistributedServiceTests):
    """Reuse the full signed grant fixture across simulated process boundaries."""

    def test_remote_audit_round_trip_and_peer_isolation(self):
        with self.temporary_directory() as directory:
            anchor = self.audit_anchor(
                Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
            )
            endpoint = AuditServiceEndpoint(anchor, allowed_peers=frozenset({"spiffe://aak/resource"}))
            remote = RemoteAuditAnchor(
                lambda path, payload: endpoint.handle(
                    path, payload, peer_identity="spiffe://aak/resource",
                )
            )
            receipt = remote.append({"type": "test", "id": "1"})
            self.assertTrue(anchor.verify_receipt(receipt))
            with self.assertRaisesRegex(DistributedBoundaryError, "audit_peer_denied"):
                endpoint.handle("/v1/audit/events", {"event": {"x": 1}}, peer_identity="spiffe://evil")

    def test_remote_broker_reverifies_grant_and_denies_untrusted_peer(self):
        verifier = ActionEnvelopeVerifier(
            Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
            ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
            expected_audience="crm-api",
        )
        provider_calls = []
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
            broker = VerifyingEffectBroker(
                verifier=verifier,
                provider=lambda **values: provider_calls.append(values) or {"provider_reference": "remote-1"},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=self.replay_store(Path(directory) / "broker.db"),
                input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            endpoint = EffectBrokerEndpoint(
                broker, allowed_peers=frozenset({"spiffe://aak/resource"}), clock=lambda: 102,
            )
            remote = RemoteEffectBroker(
                lambda path, payload: endpoint.handle(
                    path, payload, peer_identity="spiffe://aak/resource",
                )
            )
            result = remote.execute(
                origin="https://crm.example", audience="crm-api", action_hash=action_hash,
                call=self.grant.call, grant=self.grant, now=102,
                authorization_event=event, authorization_receipt=receipt,
            )
            self.assertEqual(result["provider_reference"], "remote-1")
            self.assertEqual(len(provider_calls), 1)
            with self.assertRaisesRegex(DistributedBoundaryError, "broker_peer_denied"):
                endpoint.handle("/v1/effects/execute", {}, peer_identity="spiffe://evil")

    def test_remote_boundaries_reject_extra_fields(self):
        with self.temporary_directory() as directory:
            endpoint = AuditServiceEndpoint(
                self.audit_anchor(
                    Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
                ),
                allowed_peers=frozenset({"resource"}),
            )
            with self.assertRaisesRegex(DistributedBoundaryError, "malformed_audit_request"):
                endpoint.handle("/v1/audit/events", {"event": {}, "debug": True}, peer_identity="resource")

    def test_remote_broker_preserves_rejected_and_ambiguous_provider_states(self):
        for status, error in (
            ("rejected", ProviderRejectedError),
            ("ambiguous", ProviderOutcomeAmbiguousError),
        ):
            with self.subTest(status=status):
                remote = RemoteEffectBroker(
                    lambda _path, _payload, status=status: {"status": status, "result": None},
                )
                with self.assertRaises(error):
                    remote.execute(
                        origin="https://crm.example", audience="crm-api",
                        action_hash=digest(self.grant.envelope.claim()), call=self.grant.call,
                        grant=self.grant, now=102, authorization_event={},
                        authorization_receipt=__import__("aak").AuditReceipt(
                            self.audit_id, 1, "GENESIS", "hash",
                            self.audit_key.key_id, "signature",
                        ),
                    )

    def test_lost_broker_response_is_conservatively_ambiguous(self):
        remote = RemoteEffectBroker(
            lambda _path, _payload: (_ for _ in ()).throw(TimeoutError("response lost")),
        )
        with self.assertRaisesRegex(ProviderOutcomeAmbiguousError, "broker_response_ambiguous"):
            remote.execute(
                origin="https://crm.example", audience="crm-api",
                action_hash=digest(self.grant.envelope.claim()), call=self.grant.call,
                grant=self.grant, now=102, authorization_event={},
                authorization_receipt=__import__("aak").AuditReceipt(
                    self.audit_id, 1, "GENESIS", "hash",
                    self.audit_key.key_id, "signature",
                ),
            )

    def test_complete_resource_audit_broker_chain_uses_strict_remote_contracts(self):
        with self.temporary_directory() as directory:
            audit_endpoint = AuditServiceEndpoint(
                self.audit_anchor(
                    Path(directory) / "audit.db", self.audit_key, anchor_id=self.audit_id,
                ),
                allowed_peers=frozenset({"spiffe://aak/resource"}),
            )
            remote_audit = RemoteAuditAnchor(
                lambda path, payload: audit_endpoint.handle(
                    path, payload, peer_identity="spiffe://aak/resource",
                )
            )
            broker_verifier = ActionEnvelopeVerifier(
                Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
                ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
                expected_audience="crm-api",
            )
            provider_calls = []
            broker_endpoint = EffectBrokerEndpoint(
                VerifyingEffectBroker(
                    verifier=broker_verifier,
                    provider=lambda **values: provider_calls.append(values) or {"reference": "p-1"},
                    allowed_origins=("https://crm.example",),
                    audit_anchor_id=self.audit_id,
                    audit_verifiers={self.audit_key.key_id: Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                    replay_store=self.replay_store(Path(directory) / "broker.db"),
                    input_policies={"crm.ticket.update": InputPolicy(self.manifest.input_schema_hash, valid_close)},
                ),
                allowed_peers=frozenset({"spiffe://aak/resource"}),
                clock=lambda: 102,
            )
            remote_broker = RemoteEffectBroker(
                lambda path, payload: broker_endpoint.handle(
                    path, payload, peer_identity="spiffe://aak/resource",
                )
            )
            resource_core = ResourceExecutionService(
                verifier=ActionEnvelopeVerifier(
                    Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
                    ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
                    expected_audience="crm-api",
                ),
                audit=remote_audit, broker=remote_broker, quarantine=lambda *_: None,
            )
            resource_endpoint = ResourceServiceEndpoint(
                resource_core, allowed_peers=frozenset({"spiffe://aak/gateway"}),
                destination="https://crm.example/v1/tickets",
                effect_limits={"records_written": 10},
                clock=lambda: 102,
            )
            remote_resource = RemoteResourceService(
                lambda path, payload: resource_endpoint.handle(
                    path, payload, peer_identity="spiffe://aak/gateway",
                )
            )
            outcome = remote_resource.execute(self.grant)
            self.assertTrue(outcome.committed)
            self.assertEqual(len(provider_calls), 1)

    def test_remote_services_reject_caller_controlled_time(self):
        class NeverCalled:
            def execute(self, **_values):
                raise AssertionError("core must not be reached")

        resource = ResourceServiceEndpoint(
            NeverCalled(), allowed_peers=frozenset({"gateway"}),
            destination="https://crm.example", effect_limits={"records_written": 1},
            clock=lambda: 102,
        )
        with self.assertRaisesRegex(DistributedBoundaryError, "malformed_resource_request"):
            resource.handle(
                "/v1/actions/execute", {"grant": self.grant.to_wire(), "now": 101},
                peer_identity="gateway",
            )


if __name__ == "__main__":
    unittest.main()
