"""Cross-connection replay and fault injection proof for local checkpoint store."""
import os
import tempfile
import threading
import unittest
from aak.runtime_store import RuntimeCheckpointStore


class RuntimeJournalConcurrencyTests(unittest.TestCase):
    def test_two_writers_same_effect_exactly_one_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "journal.db")
            first, second = RuntimeCheckpointStore(path), RuntimeCheckpointStore(path)
            start = threading.Barrier(2)
            accepted, rejected = [], []
            def issue(store):
                try:
                    start.wait(timeout=4)
                    store({"run_id": "collision", "step": 1, "call": 0,
                           "transaction_id": "a" * 64, "phase": "pending"})
                    accepted.append(1)
                except Exception as exc:
                    rejected.append(type(exc).__name__)
            workers = [threading.Thread(target=issue, args=(store,))
                       for store in (first, second)]
            for worker in workers: worker.start()
            for worker in workers: worker.join(timeout=8)
            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertEqual(len(accepted), 1)
            self.assertEqual(len(rejected), 1)
            self.assertEqual(first.state("collision")[0][3], "pending")
            first.close()
            second.close()

    def test_crash_after_pending_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "journal.db")
            initial = RuntimeCheckpointStore(path)
            event = {"run_id": "crashed", "step": 1, "call": 0,
                     "transaction_id": "b" * 64, "phase": "pending"}
            initial(event)
            initial.close()
            recovered = RuntimeCheckpointStore(path)
            with self.assertRaises(Exception):
                recovered(event)
            self.assertEqual(recovered.state("crashed")[0][3], "pending")
            recovered.close()

    def test_complete_requires_no_pending_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "journal.db")
            journal = RuntimeCheckpointStore(path)
            item = {"run_id": "run", "step": 1, "call": 0,
                    "transaction_id": "c" * 64}
            journal({**item, "phase": "pending"})
            with self.assertRaises(ValueError):
                journal({"run_id": "run", "step": 2, "phase": "complete"})
            journal({**item, "phase": "completed"})
            journal({"run_id": "run", "step": 2, "phase": "complete"})
            with self.assertRaises(ValueError):
                journal({**item, "phase": "pending"})
            journal.close()


if __name__ == "__main__":
    unittest.main()
