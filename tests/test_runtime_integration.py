"""Runtime -> actual AAK signed gateway grant -> resource -> verifying broker.

Uses repository cryptographic/identity fixtures and a fake external provider.
No cloud-provider credentials or real external execution.
"""
import tempfile
import hashlib
import json
from pathlib import Path
from aak import (ActionEnvelopeVerifier, ToolManifestVerifier, Ed25519Signer,
                 AuthenticatedGatewayContext,
                 InputPolicy, VerifyingEffectBroker, DistributedBoundaryError)
from aak.agent_runtime import BoundedAgent, ModelReply, ToolRequest, Outcome
from aak.reliability_contract import ExactGrantBoundary
from aak.runtime_store import RuntimeCheckpointStore
from test_distributed import DistributedServiceTests, valid_close, jwt


class Model:
    def __init__(self, replies):
        self.items = iter(replies)
    def complete(self, history):
        return next(self.items)


class RuntimeSignedIntegrationTests(DistributedServiceTests):
    def test_actual_signed_gateway_resource_and_broker(self):
        with self.temporary_directory() as directory:
            audit = self.audit_anchor(Path(directory) / "audit.db", self.audit_key,
                                      anchor_id=self.audit_id)
            provider_calls = []
            verifier = ActionEnvelopeVerifier(
                Ed25519Signer.verifier(self.envelope_key.public_key_bytes),
                ToolManifestVerifier(Ed25519Signer.verifier(self.manifest_key.public_key_bytes)),
                expected_audience="crm-api")
            broker = VerifyingEffectBroker(
                verifier=verifier,
                provider=lambda **kwargs: provider_calls.append(kwargs) or
                    {"provider_reference": "sandbox-ref-1", "status": "closed"},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=self.audit_id,
                audit_verifiers={self.audit_key.key_id:
                    Ed25519Signer.verifier(self.audit_key.public_key_bytes)},
                replay_store=self.replay_store(Path(directory) / "broker.db"),
                input_policies={"crm.ticket.update":
                    InputPolicy(self.manifest.input_schema_hash, valid_close)},
            )
            quarantine = []
            service = self.resource(audit, broker, lambda *args: quarantine.append(args))
            calls = [ToolRequest("crm.ticket.update",
                                 {"ticket_id": "T-1", "status": "closed"})]
            expected_args = json.dumps(calls[0].arguments, sort_keys=True,
                                       separators=(",", ":"), ensure_ascii=False)
            expected_tx = hashlib.sha256(
                ("proof-1\\x00" + "1\\x00" + "0\\x00" +
                 calls[0].name + "\\x00" + expected_args).encode()
            ).hexdigest()
            self.gateway.id_factory = iter(("new-envelope", expected_tx, "new-nonce")).__next__
            token_payload = {"iss": "https://identity.internal",
                             "sub": "spiffe://aak/agent/support",
                             "aud": "resource-verifier", "iat": 100, "nbf": 100,
                             "exp": 130, "jti": "identity-token-2",
                             "cnf": {"x5t#S256": "cert-1"}}
            fresh_context = AuthenticatedGatewayContext(
                "user:glenn", "close resolved ticket",
                jwt(self.identity_key, token_payload), "cert-1")
            matching_grant = self.gateway.authorize_mcp(self.request, fresh_context, now=101)
            self.assertEqual(matching_grant.envelope.transaction_id, expected_tx)
            self.assertEqual(matching_grant.call.action, calls[0].name)
            self.assertEqual(matching_grant.manifest.action, calls[0].name)
            self.assertEqual(matching_grant.call.resource, matching_grant.manifest.resource)
            self.assertEqual(matching_grant.call.audience, matching_grant.manifest.audience)
            self.assertEqual(matching_grant.call.parameters, calls[0].arguments)
            def grant_provider(request, txid):
                return matching_grant
            boundary_failures = []
            bound = ExactGrantBoundary(
                grant_provider,
                lambda grant: service.execute(
                    grant, destination="https://crm.example/v1/tickets", now=102,
                    effect_limits={"records_written": 10}),
                allowed_actions=frozenset({"crm.ticket.update"}),
            )
            def observed_boundary(call, transaction):
                try:
                    return bound(call, transaction)
                except Exception as exc:
                    boundary_failures.append(type(exc).__name__ + ": " + str(exc))
                    raise
            journal = RuntimeCheckpointStore(str(Path(directory) / "runtime.db"))
            try:
                agent = BoundedAgent(
                    Model([ModelReply(calls=tuple(calls)),
                           ModelReply(text="ticket closed")]),
                    observed_boundary, journal,
                    allowed_tools=frozenset({"crm.ticket.update"}))
                result = agent.run("proof-1")
                self.assertEqual(result.outcome, Outcome.COMPLETE, (result, boundary_failures))
                self.assertEqual(len(provider_calls), 1)
                self.assertEqual(provider_calls[0]["operation_id"],
                                 matching_grant.envelope.transaction_id)
                self.assertTrue(audit.verify_chain())
                self.assertFalse(quarantine)
                self.assertEqual(journal.state("proof-1")[0][3], "completed")
                # The independent resource verifier rejects a consumed grant.
                with self.assertRaisesRegex(DistributedBoundaryError, "replay"):
                    bound(calls[0], expected_tx)
                self.assertEqual(len(provider_calls), 1)
            finally:
                journal.close()

    def test_mismatched_request_never_reaches_resource(self):
        with self.temporary_directory() as directory:
            observed = []
            journal = RuntimeCheckpointStore(str(Path(directory) / "runtime.db"))
            try:
                bound = ExactGrantBoundary(
                    lambda req, tx: self.grant,
                    lambda grant: observed.append(grant),
                    allowed_actions=frozenset({"crm.ticket.update"}))
                agent = BoundedAgent(
                    Model([ModelReply(calls=(ToolRequest("crm.ticket.update",
                        {"ticket_id": "DIFFERENT", "status": "closed"}),))]),
                    bound, journal,
                    allowed_tools=frozenset({"crm.ticket.update"}))
                self.assertEqual(agent.run("proof-deny").outcome, Outcome.QUARANTINED)
                self.assertFalse(observed)
            finally:
                journal.close()
