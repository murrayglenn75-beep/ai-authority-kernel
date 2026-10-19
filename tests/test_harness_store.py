import tempfile
import unittest
from pathlib import Path
from aak.harness_lifecycle import HarnessTask, Status
from aak.harness_store import DurableHarnessStore

class DurableHarnessStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "tasks.sqlite"
        self.store = DurableHarnessStore(self.path)
        self.store.create(HarnessTask("t1", "apex", "alice"))

    def test_restart_survives(self):
        self.store.transition("t1", principal_id="alice", expected_revision=0, next_status=Status.RUNNING, step=True)
        self.assertEqual(DurableHarnessStore(self.path).load("t1", "alice").steps, 1)

    def test_stale_revision_denied(self):
        self.store.transition("t1", principal_id="alice", expected_revision=0, next_status=Status.RUNNING)
        with self.assertRaises(ValueError):
            self.store.transition("t1", principal_id="alice", expected_revision=0, next_status=Status.COMPLETED)

    def test_principal_mismatch(self):
        with self.assertRaises(PermissionError):
            self.store.transition("t1", principal_id="bob", expected_revision=0, next_status=Status.RUNNING)

    def test_no_cross_principal_read(self):
        with self.assertRaises(PermissionError):
            self.store.load("t1", "bob")

    def test_no_duplicate_create(self):
        with self.assertRaises(Exception):
            self.store.create(HarnessTask("t1", "apex", "alice"))

    def test_waiting_approval_blocks_completion(self):
        self.store.transition("t1", principal_id="alice", expected_revision=0, next_status=Status.RUNNING)
        self.store.transition("t1", principal_id="alice", expected_revision=1, next_status=Status.WAITING_APPROVAL)
        with self.assertRaises(ValueError):
            self.store.transition("t1", principal_id="alice", expected_revision=2, next_status=Status.COMPLETED)

    def test_corrupt_state_fails_closed(self):
        import sqlite3
        db = sqlite3.connect(self.path)
        try:
            db.execute("UPDATE harness_tasks SET status = 'unknown' WHERE task_id = 't1'")
            db.commit()
        finally:
            db.close()
        with self.assertRaises(ValueError):
            self.store.load("t1", "alice")

    def test_disallow_memory_store(self):
        with self.assertRaises(ValueError):
            DurableHarnessStore(":memory:")

if __name__ == "__main__":
    unittest.main()
