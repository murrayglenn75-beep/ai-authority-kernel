"""Broker-side opt-in fencing proof using real AAK signed grant fixtures."""
import os
import tempfile
import unittest
from aak import (ActionEnvelopeVerifier, ToolManifestVerifier, Ed25519Signer,
                 VerifyingEffectBroker, InputPolicy, DurableAuditAnchor,
                 SQLiteBrokerReplayStore, DistributedBoundaryError)
from aak.canonical import digest
from aak.worker_fencing import SQLiteFencingStore
from test_distributed import DistributedServiceTests, valid_close


class BrokerFenceIntegration(unittest.TestCase):
    def test_stale_lease_denied_before_provider_and_current_lease_succeeds(self):
        fixture = DistributedServiceTests(methodName=
            "test_exact_grant_executes_once_without_exposing_credential")
        fixture.setUp()
        with tempfile.TemporaryDirectory() as directory:
            lease = SQLiteFencingStore(os.path.join(directory, "leases.db"))
            old = lease.acquire("run", "worker-old", 100, 5)
            current = lease.acquire("run", "worker-new", 105, 10)
            anchor = DurableAuditAnchor(os.path.join(directory, "audit.db"),
                                        fixture.audit_key, anchor_id=fixture.audit_id)
            replay = SQLiteBrokerReplayStore(os.path.join(directory, "replay.db"))
            calls = []
            active = {"owner": "worker-old", "token": old}
            def fence(grant, now):
                lease.dispatch_once("run", active["owner"], active["token"],
                                    grant.envelope.transaction_id, now)
            verifier = ActionEnvelopeVerifier(
                Ed25519Signer.verifier(fixture.envelope_key.public_key_bytes),
                ToolManifestVerifier(
                    Ed25519Signer.verifier(fixture.manifest_key.public_key_bytes)),
                expected_audience="crm-api")
            broker = VerifyingEffectBroker(
                verifier=verifier,
                provider=lambda **values: calls.append(values) or {"provider_reference": "ok"},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=fixture.audit_id,
                audit_verifiers={fixture.audit_key.key_id:
                    Ed25519Signer.verifier(fixture.audit_key.public_key_bytes)},
                replay_store=replay,
                input_policies={"crm.ticket.update": InputPolicy(
                    fixture.manifest.input_schema_hash, valid_close)},
                dispatch_fence=fence)
            action_hash = digest(fixture.grant.envelope.claim())
            event = {"type": "action_authorized",
                     "envelope_id": fixture.grant.envelope.envelope_id,
                     "transaction_id": fixture.grant.envelope.transaction_id,
                     "request_hash": fixture.grant.call.request_hash,
                     "agent_identity": fixture.grant.envelope.agent_identity,
                     "policy_decision_id": fixture.grant.envelope.policy_decision_id,
                     "action_hash": action_hash}
            receipt = anchor.append(event)
            arguments = dict(origin="https://crm.example", audience="crm-api",
                action_hash=action_hash, call=fixture.grant.call, grant=fixture.grant,
                now=106, authorization_event=event, authorization_receipt=receipt)
            try:
                with self.assertRaisesRegex(DistributedBoundaryError, "broker_dispatch_fence_denied"):
                    broker.execute(**arguments)
                self.assertEqual(calls, [])
                active.update(owner="worker-new", token=current)
                self.assertEqual(broker.execute(**arguments)["provider_reference"], "ok")
                self.assertEqual(len(calls), 1)
                with self.assertRaises(DistributedBoundaryError):
                    broker.execute(**arguments)
                self.assertEqual(len(calls), 1)
            finally:
                replay.close()
                anchor.close()
                lease.close()


if __name__ == "__main__":
    unittest.main()
