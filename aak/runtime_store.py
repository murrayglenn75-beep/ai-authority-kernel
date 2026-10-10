"""SQLite checkpoint journal for single-host agent experiments.

This is not an AAK authority store, distributed lease service, or substitute
for broker-side idempotency. Pending effects must be reconciled externally.
"""
from __future__ import annotations

import sqlite3
import threading


class RuntimeCheckpointStore:
    """Fail-closed append/state journal, safe across SQLite connections.

    Uses BEGIN IMMEDIATE for atomic transitions, FULL sync for committed writes,
    and a unique (run, step, call) identity. Re-entry of a pending or finished
    transaction is rejected, not treated as permission to dispatch again.
    """

    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise ValueError("provide a persistent, local SQLite database path")
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, timeout=5, isolation_level=None,
                                    check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_effects (
                run_id TEXT NOT NULL,
                step INTEGER NOT NULL,
                call_index INTEGER NOT NULL,
                transaction_id TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('pending', 'completed')),
                PRIMARY KEY (run_id, step, call_index),
                UNIQUE (transaction_id)
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_runs (
                run_id TEXT PRIMARY KEY,
                finished INTEGER NOT NULL DEFAULT 0
            )
        """)

    def __call__(self, event: dict) -> None:
        run_id = event["run_id"]
        phase = event["phase"]
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("invalid run")
        if phase not in ("pending", "completed", "complete"):
            raise ValueError("invalid phase")
        if phase != "complete":
            tx = event["transaction_id"]
            step = event["step"]
            index = event["call"]
            if not isinstance(tx, str) or len(tx) != 64:
                raise ValueError("invalid transaction")
            if not isinstance(step, int) or step < 1 or not isinstance(index, int) or index < 0:
                raise ValueError("invalid position")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("INSERT OR IGNORE INTO agent_runs (run_id) VALUES (?)", (run_id,))
                finished = self._conn.execute(
                    "SELECT finished FROM agent_runs WHERE run_id=?", (run_id,)
                ).fetchone()[0]
                if finished:
                    raise ValueError("run already completed")
                if phase == "pending":
                    # A crashed run can never re-enter its pending effect.
                    self._conn.execute(
                        "INSERT INTO agent_effects VALUES (?, ?, ?, ?, 'pending')",
                        (run_id, step, index, tx)
                    )
                elif phase == "completed":
                    cursor = self._conn.execute(
                        "UPDATE agent_effects SET phase='completed' "
                        "WHERE run_id=? AND step=? AND call_index=? "
                        "AND transaction_id=? AND phase='pending'",
                        (run_id, step, index, tx)
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("unknown or previously completed effect")
                else:
                    pending = self._conn.execute(
                        "SELECT COUNT(*) FROM agent_effects WHERE run_id=? AND phase='pending'",
                        (run_id,)
                    ).fetchone()[0]
                    if pending:
                        raise ValueError("cannot finish with pending effects")
                    self._conn.execute(
                        "UPDATE agent_runs SET finished=1 WHERE run_id=?", (run_id,)
                    )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def state(self, run_id: str) -> tuple[tuple[int, int, str, str], ...]:
        with self._lock:
            return tuple(self._conn.execute(
                "SELECT step, call_index, transaction_id, phase FROM agent_effects "
                "WHERE run_id=? ORDER BY step, call_index", (run_id,)
            ))

    def close(self):
        with self._lock:
            self._conn.close()
