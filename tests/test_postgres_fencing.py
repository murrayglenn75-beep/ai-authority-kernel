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
