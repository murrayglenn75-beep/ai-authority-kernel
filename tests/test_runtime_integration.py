"""Runtime -> actual AAK signed gateway grant -> resource -> verifying broker.

Uses repository cryptographic/identity fixtures and a fake external provider.
No cloud-provider credentials or real external execution.
"""
import tempfile
from pathlib import Path
from aak import (ActionEnvelopeVerifier, ToolManifestVerifier, Ed25519Signer,
                 InputPolicy, SQLiteBrokerReplayStore, VerifyingEffectBroker)
from aak.agent_runtime import BoundedAgent, ModelReply, ToolRequest, Outcome
from aak.reliability_contract import ExactGrantBoundary
from aak.runtime_store import RuntimeCheckpointStore
from test_distributed import DistributedServiceTests, valid_close


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
            def grant_provider(request, txid):
                # Fixture grant was actually issued by GatewayService in setUp,
                # signed and policy/identity checked. Never issue here from model.
                return self.grant
            bound = ExactGrantBoundary(
                grant_provider,
                lambda grant: service.execute(
                    grant, destination="https://crm.example/v1/tickets", now=102,
                    effect_limits={"records_written": 10}),
                allowed_actions=frozenset({"crm.ticket.update"}),
            )
            journal = RuntimeCheckpointStore(str(Path(directory) / "runtime.db"))
            try:
                agent = BoundedAgent(
                    Model([ModelReply(calls=tuple(calls)),
                           ModelReply(text="ticket closed")]),
                    bound, journal,
                    allowed_tools=frozenset({"crm.ticket.update"}))
                result = agent.run("proof-1")
                self.assertEqual(result.outcome, Outcome.COMPLETE, result)
                self.assertEqual(len(provider_calls), 1)
                self.assertEqual(provider_calls[0]["operation_id"],
                                 self.grant.envelope.transaction_id)
                self.assertTrue(audit.verify_chain())
                self.assertFalse(quarantine)
                self.assertEqual(journal.state("proof-1")[0][3], "completed")
                # Broker and resource must reject replay even if runtime journaling
                # were bypassed, never call provider twice.
                denied = bound(calls[0], "b" * 64)
                self.fail("unexpected replay acceptance: " + repr(denied))
            except Exception as exc:
                if isinstance(exc, AssertionError):
                    raise
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
