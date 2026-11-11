"""Competing workers, stale owner, crash takeover and repeated effect proof."""
import os
import tempfile
import threading
import subprocess
import sys
import unittest
from aak.worker_fencing import SQLiteFencingStore, LeaseDenied


class WorkerFencingTests(unittest.TestCase):
    def test_competition_and_fence(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "fence.db")
            a, b = SQLiteFencingStore(path), SQLiteFencingStore(path)
            token_a = a.acquire("job", "worker-A", 100, 10)
            self.assertEqual(token_a, 1)
            with self.assertRaises(LeaseDenied):
                b.acquire("job", "worker-B", 109, 10)
            # A expires, B takes over. Late A cannot dispatch.
            token_b = b.acquire("job", "worker-B", 110, 10)
            self.assertEqual(token_b, 2)
            with self.assertRaises(LeaseDenied):
                a.dispatch_once("job", "worker-A", token_a, "a" * 64, 111)
            b.dispatch_once("job", "worker-B", token_b, "b" * 64, 111)
            with self.assertRaises(Exception):
                b.dispatch_once("job", "worker-B", token_b, "b" * 64, 112)
            self.assertEqual(b.db.execute("SELECT count(*) FROM fenced_dispatch").fetchone()[0], 1)
            a.close()
            b.close()

    def test_worker_process_crash_and_fenced_takeover(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "fence.db")
            # A separate interpreter owns the initial lease and terminates
            # abruptly, deliberately omitting SQLite connection cleanup.
            worker = (
                "import os,sys;"
                "from aak.worker_fencing import SQLiteFencingStore;"
                "s=SQLiteFencingStore(sys.argv[1]);"
                "assert s.acquire('crash','worker-old',100,10)==1;"
                "os._exit(0)"
            )
            subprocess.run([sys.executable, "-c", worker, path],
                           check=True, timeout=10)
            recovered = SQLiteFencingStore(path)
            with self.assertRaises(LeaseDenied):
                recovered.acquire("crash", "worker-new", 109, 10)
            fresh_token = recovered.acquire("crash", "worker-new", 110, 10)
            self.assertEqual(fresh_token, 2)
            with self.assertRaises(LeaseDenied):
                recovered.dispatch_once("crash", "worker-old", 1, "f" * 64, 111)
            recovered.dispatch_once("crash", "worker-new", 2, "e" * 64, 111)
            recovered.close()

    def test_concurrent_acquire_single_winner_and_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "fence.db")
            a, b = SQLiteFencingStore(path), SQLiteFencingStore(path)
            barrier = threading.Barrier(2)
            success, failures = [], []
            def compete(store, worker):
                try:
                    barrier.wait(timeout=5)
                    success.append(store.acquire("shared", worker, 100, 20))
                except LeaseDenied:
                    failures.append(worker)
            threads = [threading.Thread(target=compete, args=(a,"A")),
                       threading.Thread(target=compete, args=(b,"B"))]
            for t in threads: t.start()
            for t in threads: t.join(timeout=10)
            self.assertTrue(all(not t.is_alive() for t in threads))
            self.assertEqual(success, [1])
            self.assertEqual(len(failures), 1)
            a.close()
            b.close()
            reopened = SQLiteFencingStore(path)
            with self.assertRaises(LeaseDenied):
                reopened.acquire("shared","new",119,10)
            self.assertEqual(reopened.acquire("shared","new",120,10),2)
            reopened.close()


if __name__ == "__main__":
    unittest.main()
