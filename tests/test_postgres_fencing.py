"""Real PostgreSQL concurrent-connection fencing integration tests.

Runs only with AAK_TEST_POSTGRES_DSN, using a dedicated disposable database.
"""
import os
import threading
import subprocess
import sys
import unittest
from aak.postgres_fencing import PostgresFencingStore
from aak.worker_fencing import LeaseDenied


@unittest.skipUnless(os.getenv("AAK_TEST_POSTGRES_DSN"), "disposable PostgreSQL DSN required")
class PostgreSQLFencingIntegration(unittest.TestCase):
    def setUp(self):
        self.dsn = os.environ["AAK_TEST_POSTGRES_DSN"]
        self.a = PostgresFencingStore(self.dsn)
        self.b = PostgresFencingStore(self.dsn)
        self.a.initialize()
        with self.a.db.transaction():
            self.a.db.execute("DELETE FROM aak_provider_outcomes")
            self.a.db.execute("DELETE FROM aak_fenced_request_bindings")
            self.a.db.execute("DELETE FROM aak_fenced_dispatch")
            self.a.db.execute("DELETE FROM aak_worker_leases")

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_stale_worker_cannot_dispatch_after_lease_takes_over(self):
        first = self.a.acquire("run", "worker-a", 1)
        self.assertEqual(first, 1)
        with self.assertRaises(LeaseDenied):
            self.b.acquire("run", "worker-b", 10)
        with self.a.db.transaction():
            self.a.db.execute("UPDATE aak_worker_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id='run'")
        second = self.b.acquire("run", "worker-b", 10)
        self.assertEqual(second, 2)
        with self.assertRaises(LeaseDenied):
            self.a.dispatch_once("run", "worker-a", first, "tx-1")
        self.b.dispatch_once("run", "worker-b", second, "tx-1")
        with self.assertRaises(Exception):
            self.b.dispatch_once("run", "worker-b", second, "tx-1")
        count = self.a.db.execute("SELECT count(*) FROM aak_fenced_dispatch").fetchone()[0]
        self.a.db.rollback()
        self.assertEqual(count, 1)

    def test_crashed_process_leaves_fenced_lease(self):
        child = (
            "import os,sys;"
            "from aak.postgres_fencing import PostgresFencingStore;"
            "s=PostgresFencingStore(sys.argv[1]);"
            "assert s.acquire('crash','old',5)==1;"
            "os._exit(0)"
        )
        subprocess.run([sys.executable, "-c", child, self.dsn], check=True, timeout=15)
        with self.assertRaises(LeaseDenied):
            self.b.acquire("crash", "new", 10)
        # Simulate passage of database time without relying on sleep.
        with self.a.db.transaction():
            self.a.db.execute(
                "UPDATE aak_worker_leases SET expires_at="
                "clock_timestamp()-interval '1 second' WHERE run_id='crash'")
        self.assertEqual(self.b.acquire("crash", "new", 10), 2)
        with self.assertRaises(LeaseDenied):
            self.a.dispatch_once("crash", "old", 1, "provider-transaction")
        self.b.dispatch_once("crash", "new", 2, "provider-transaction")

    def test_broker_hook_reserves_exact_signed_transaction(self):
        from test_distributed import DistributedServiceTests, valid_close
        from aak import (ActionEnvelopeVerifier, ToolManifestVerifier, Ed25519Signer,
                         VerifyingEffectBroker, InputPolicy, SQLiteBrokerReplayStore,
                         DurableAuditAnchor, DistributedBoundaryError)
        from aak.canonical import digest
        import tempfile
        from pathlib import Path
        fixture = DistributedServiceTests(methodName=
            "test_exact_grant_executes_once_without_exposing_credential")
        fixture.setUp()
        token = self.a.acquire("broker-run", "worker-1", 30)
        fake_calls = []
        with tempfile.TemporaryDirectory() as directory:
            audit = DurableAuditAnchor(Path(directory)/"audit.db", fixture.audit_key,
                                       anchor_id=fixture.audit_id)
            replay = SQLiteBrokerReplayStore(Path(directory)/"broker.db")
            verifier = ActionEnvelopeVerifier(
                Ed25519Signer.verifier(fixture.envelope_key.public_key_bytes),
                ToolManifestVerifier(
                    Ed25519Signer.verifier(fixture.manifest_key.public_key_bytes)),
                expected_audience="crm-api")
            active = {"token": token}
            broker = VerifyingEffectBroker(
                verifier=verifier,
                provider=lambda **kw: fake_calls.append(kw) or
                    {"provider_reference":"test-only"},
                allowed_origins=("https://crm.example",),
                audit_anchor_id=fixture.audit_id,
                audit_verifiers={fixture.audit_key.key_id:
                    Ed25519Signer.verifier(fixture.audit_key.public_key_bytes)},
                replay_store=replay,
                input_policies={"crm.ticket.update":InputPolicy(
                    fixture.manifest.input_schema_hash, valid_close)},
                dispatch_fence=self.a.broker_fence(
                    run_id="broker-run", owner="worker-1", token=token))
            action_hash = digest(fixture.grant.envelope.claim())
            event = {"type":"action_authorized",
                "envelope_id":fixture.grant.envelope.envelope_id,
                "transaction_id":fixture.grant.envelope.transaction_id,
                "request_hash":fixture.grant.call.request_hash,
                "agent_identity":fixture.grant.envelope.agent_identity,
                "policy_decision_id":fixture.grant.envelope.policy_decision_id,
                "action_hash":action_hash}
            receipt = audit.append(event)
            kwargs = dict(origin="https://crm.example", audience="crm-api",
                action_hash=action_hash,call=fixture.grant.call,grant=fixture.grant,
                now=102,authorization_event=event,authorization_receipt=receipt)
            try:
                broker.execute(**kwargs)
                self.assertEqual(len(fake_calls), 1)
                tx = fixture.grant.envelope.transaction_id
                self.assertEqual(self.a.pending(tx), ("broker-run", token, "pending"))
                from aak.provider_reconciliation import VerifiedProviderReconciliation
                from aak.reliability_contract import RecoveryDecision
                from aak.canonical import canonical_bytes
                from aak.crypto import b64encode
                provider_signer = Ed25519Signer.generate()
                trusted = VerifiedProviderReconciliation({
                    provider_signer.key_id:
                    Ed25519Signer.verifier(provider_signer.public_key_bytes)})
                proof = {"transaction_id": tx,
                         "request_hash": fixture.grant.call.request_hash,
                         "provider_reference": "test-only",
                         "state": "committed",
                         "provider_key_id": provider_signer.key_id}
                signed = {**proof, "signature": b64encode(
                    provider_signer.sign(canonical_bytes(proof)))}
                self.assertEqual(self.a.record_verified_outcome(
                    {**signed, "request_hash":"tampered"}, trusted),
                    RecoveryDecision.REQUIRE_OPERATOR)
                self.assertEqual(self.a.record_verified_outcome(signed, trusted),
                                 RecoveryDecision.RECORD_SUCCESS)
                outcome_row = self.b.db.execute(
                    "SELECT decision FROM aak_provider_outcomes WHERE transaction_id=%s",
                    (tx,)).fetchone()
                self.b.db.rollback()
                self.assertEqual(outcome_row, ("record_success",))
                with self.assertRaises(Exception):
                    self.a.record_verified_outcome(signed, trusted)
                with self.assertRaises(DistributedBoundaryError):
                    broker.execute(**kwargs)
                self.assertEqual(len(fake_calls), 1)
            finally:
                replay.close()
                audit.close()

    def test_crash_after_dispatch_keeps_pending_and_blocks_retry(self):
        token = self.a.acquire("pending-run", "worker", 30)
        child = (
            "import os,sys;"
            "from aak.postgres_fencing import PostgresFencingStore;"
            "s=PostgresFencingStore(sys.argv[1]);"
            "s.dispatch_once('pending-run','worker',"
            + str(token) + ",'tx-crash');"
            "os._exit(0)"
        )
        subprocess.run([sys.executable, "-c", child, self.dsn],
                       check=True, timeout=15)
        self.assertEqual(self.b.pending("tx-crash"), ("pending-run", token, "pending"))
        with self.assertRaises(Exception):
            self.b.dispatch_once("pending-run", "worker", token, "tx-crash")
        self.assertEqual(self.b.pending("tx-crash")[2], "pending")

    def test_database_disconnect_rolls_back_uncommitted_reservation(self):
        import psycopg
        token = self.a.acquire("disconnect-run", "worker", 30)
        interrupted = psycopg.connect(self.dsn)
        try:
            pid = interrupted.info.backend_pid
            interrupted.execute(
                "INSERT INTO aak_fenced_dispatch VALUES(%s,%s,%s,'pending')",
                ("connection-lost", "disconnect-run", token))
            # Simulate network/session loss while reservation is uncommitted.
            with self.b.db.transaction():
                self.assertTrue(self.b.db.execute(
                    "SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[0])
        finally:
            interrupted.close()
        self.assertIsNone(self.a.pending("connection-lost"))
        # The trusted broker can reserve a transaction that was never committed;
        # this does not imply a previously submitted provider request is safe.
        self.a.dispatch_once("disconnect-run", "worker", token, "connection-lost")
        self.assertEqual(self.b.pending("connection-lost")[2], "pending")

    def test_competing_independent_worker_processes(self):
        import json
        worker = (
            "import json,sys;"
            "from aak.postgres_fencing import PostgresFencingStore;"
            "from aak.worker_fencing import LeaseDenied;"
            "s=PostgresFencingStore(sys.argv[1]);"
            "import time;"
            "time.sleep(max(0,float(sys.argv[2])-time.time()));"
            "\\ntry:\\n t=s.acquire('process-race',sys.argv[3],30);"
            " print(json.dumps({'won':t}),flush=True)"
            "\\nexcept LeaseDenied:\\n print(json.dumps({'denied':True}),flush=True)"
        )
        import time
        # Two separate interpreters and database sessions start together.
        start = str(time.time() + 1.5)
        processes = [
            subprocess.Popen([sys.executable, "-c", worker, self.dsn,
                              start, name], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
            for name in ("worker-A", "worker-B")
        ]
        outputs = [p.communicate(timeout=15) for p in processes]
        self.assertEqual([p.returncode for p in processes], [0, 0], outputs)
        results = [json.loads(out.strip()) for out, _ in outputs]
        self.assertEqual(sum("won" in item for item in results), 1, results)
        self.assertEqual(sum("denied" in item for item in results), 1, results)

    def test_two_independent_connections_one_lease_winner(self):
        barrier = threading.Barrier(2)
        won, denied = [], []
        def compete(store, owner):
            try:
                barrier.wait(timeout=5)
                won.append(store.acquire("race", owner, 10))
            except LeaseDenied:
                denied.append(owner)
        threads = [threading.Thread(target=compete, args=(self.a,"a")),
                   threading.Thread(target=compete, args=(self.b,"b"))]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(won, [1])
        self.assertEqual(len(denied), 1)


if __name__ == "__main__":
    unittest.main()
