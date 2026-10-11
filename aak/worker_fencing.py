"""Single-database worker fencing prototype; not distributed production infrastructure.

A stale worker must never authorize a new broker effect by holding an expired
lease. Downstream broker MUST check the current fencing token transactionally.
"""
from __future__ import annotations
import sqlite3
import threading


class LeaseDenied(RuntimeError):
    pass


class SQLiteFencingStore:
    def __init__(self, path: str):
        if not path or path == ":memory:":
            raise ValueError("persistent database required")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, timeout=5,
                                  check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS worker_leases(
            run_id TEXT PRIMARY KEY, owner TEXT NOT NULL,
            token INTEGER NOT NULL, expires_at INTEGER NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS fenced_dispatch(
            tx TEXT PRIMARY KEY, run_id TEXT NOT NULL,
            token INTEGER NOT NULL, state TEXT NOT NULL
            CHECK(state='pending'))""")

    def acquire(self, run_id: str, owner: str, now: int, ttl: int) -> int:
        if (not isinstance(run_id, str) or not run_id or not isinstance(owner, str)
                or not owner or type(now) is not int or type(ttl) is not int
                or ttl < 1 or ttl > 3600):
            raise ValueError("invalid lease")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT owner, token, expires_at FROM worker_leases WHERE run_id=?",
                                      (run_id,)).fetchone()
                if row and row[2] > now:
                    raise LeaseDenied("lease active")
                token = row[1] + 1 if row else 1
                if token >= 2**63:
                    raise LeaseDenied("fencing exhausted")
                self.db.execute("""INSERT INTO worker_leases(run_id,owner,token,expires_at)
                    VALUES(?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET
                    owner=excluded.owner,token=excluded.token,expires_at=excluded.expires_at""",
                    (run_id, owner, token, now + ttl))
                self.db.execute("COMMIT")
                return token
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def dispatch_once(self, run_id: str, owner: str, token: int, tx: str, now: int) -> None:
        """Broker-side atomic fence check + pending marker. Never retry uncertain tx."""
        if (not isinstance(tx, str) or len(tx) != 64 or
                any(ch not in "0123456789abcdef" for ch in tx) or
                type(token) is not int or token < 1 or type(now) is not int):
            raise ValueError("invalid dispatch")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT owner,token,expires_at FROM worker_leases WHERE run_id=?",
                                      (run_id,)).fetchone()
                if not row or row != (owner, token, row[2]) or row[2] <= now:
                    raise LeaseDenied("stale worker fence")
                self.db.execute("INSERT INTO fenced_dispatch VALUES(?,?,?,'pending')",
                                (tx, run_id, token))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        with self.lock:
            self.db.close()
