import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aak.store import StateStore


def _reserve_same_transaction(args):
    path, index = args
    with StateStore(path) as store:
        return store.consume(
            f"process-nonce-{index}", {"ops": 1}, {"ops": 10_000}, 100,
            idempotency_key="tenant:action:resource:transaction", request_hash="same",
            strict_integer=True,
        )


class ExtendedResilienceTests(unittest.TestCase):
    def test_nonce_and_idempotency_survive_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/state.sqlite"
            with StateStore(path) as first:
                self.assertTrue(first.consume(
                    "nonce-one", {"ops": 1}, {"ops": 10}, 100,
                    idempotency_key="tenant:tx", request_hash="same", strict_integer=True,
                )[0])
            with StateStore(path) as restarted:
                self.assertEqual(restarted.consume("nonce-one", {"ops": 1}, {"ops": 10}, 101, strict_integer=True)[1], "replay")
                self.assertEqual(restarted.consume(
                    "nonce-two", {"ops": 1}, {"ops": 10}, 101,
                    idempotency_key="tenant:tx", request_hash="same", strict_integer=True,
                )[1], "duplicate_transaction")

    def test_multiple_processes_allow_one_business_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/state.sqlite"
            with StateStore(path):
                pass
            context = multiprocessing.get_context("spawn")
            with context.Pool(processes=8) as pool:
                results = pool.map(_reserve_same_transaction, ((path, index) for index in range(200)))
            self.assertEqual(sum(allowed for allowed, _ in results), 1)
            self.assertEqual(sum(reason == "duplicate_transaction" for _, reason in results), 199)

    def test_corrupt_database_fails_during_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corrupt.sqlite"
            path.write_bytes(b"not a sqlite database")
            with self.assertRaises(sqlite3.DatabaseError):
                StateStore(path)

    def test_database_write_failure_rolls_back_nonce_and_transaction(self):
        store = StateStore()
        store.db.execute(
            "CREATE TRIGGER simulate_storage_failure BEFORE INSERT ON used_nonces "
            "BEGIN SELECT RAISE(FAIL, 'simulated storage failure'); END"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "simulated storage failure"):
            store.consume(
                "retryable-nonce", {"ops": 1}, {"ops": 10}, 100,
                idempotency_key="retryable-tx", request_hash="same", strict_integer=True,
            )
        store.db.execute("DROP TRIGGER simulate_storage_failure")
        self.assertTrue(store.consume(
            "retryable-nonce", {"ops": 1}, {"ops": 10}, 101,
            idempotency_key="retryable-tx", request_hash="same", strict_integer=True,
        )[0])

    def test_close_is_idempotent_and_context_manager_closes(self):
        store = StateStore()
        store.close()
        store.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            store.db.execute("SELECT 1")

        with StateStore() as managed:
            self.assertEqual(managed.db.execute("SELECT 1").fetchone(), (1,))
        with self.assertRaises(sqlite3.ProgrammingError):
            managed.db.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
