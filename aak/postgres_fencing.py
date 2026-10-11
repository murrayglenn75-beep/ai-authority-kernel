"""PostgreSQL-backed leases and effect reservations for multi-process workers.

Requires psycopg 3. Database must be trusted and shared by broker and workers.
Uses server time; no caller-supplied time can extend or revive a lease.
Provider commits remain non-atomic: pending reservations need reconciliation.
"""
from __future__ import annotations
from .worker_fencing import LeaseDenied


class PostgresFencingStore:
    def __init__(self, dsn: str):
        if not dsn:
            raise ValueError("PostgreSQL DSN required")
        import psycopg
        self.db = psycopg.connect(dsn)
        self.db.autocommit = False

    def initialize(self):
        with self.db.transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS aak_worker_leases (
                run_id text PRIMARY KEY, owner text NOT NULL,
                token bigint NOT NULL CHECK(token > 0),
                expires_at timestamptz NOT NULL
            )""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS aak_fenced_dispatch (
                transaction_id text PRIMARY KEY,
                run_id text NOT NULL, token bigint NOT NULL,
                state text NOT NULL CHECK(state='pending')
            )""")

    def acquire(self, run_id: str, owner: str, ttl: int) -> int:
        if (not isinstance(run_id, str) or not run_id or not isinstance(owner, str)
                or not owner or type(ttl) is not int or ttl < 1 or ttl > 3600):
            raise ValueError("invalid lease")
        # Advisory lock serializes even the missing-row case across connections.
        with self.db.transaction():
            self.db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (run_id,))
            row = self.db.execute(
                "SELECT owner,token,expires_at > clock_timestamp() FROM aak_worker_leases "
                "WHERE run_id=%s FOR UPDATE", (run_id,)).fetchone()
            if row and row[2]:
                raise LeaseDenied("lease active")
            token = row[1] + 1 if row else 1
            if token >= 2**63:
                raise LeaseDenied("fencing exhausted")
            self.db.execute("""INSERT INTO aak_worker_leases(run_id,owner,token,expires_at)
                VALUES(%s,%s,%s,clock_timestamp() + (%s * interval '1 second'))
                ON CONFLICT(run_id) DO UPDATE SET owner=excluded.owner,
                token=excluded.token,expires_at=excluded.expires_at""",
                (run_id, owner, token, ttl))
            return token

    def dispatch_once(self, run_id: str, owner: str, token: int, tx: str) -> None:
        if (not isinstance(run_id, str) or not run_id or not isinstance(owner, str)
                or not owner or type(token) is not int or token < 1
                or not isinstance(tx, str) or not 1 <= len(tx) <= 256):
            raise ValueError("invalid dispatch")
        with self.db.transaction():
            row = self.db.execute(
                "SELECT owner,token,expires_at > clock_timestamp() "
                "FROM aak_worker_leases WHERE run_id=%s FOR UPDATE", (run_id,)
            ).fetchone()
            if not row or row != (owner, token, True):
                raise LeaseDenied("stale worker fence")
            # Unique tx prevents re-dispatch following crash/unknown provider commit.
            self.db.execute("INSERT INTO aak_fenced_dispatch VALUES(%s,%s,%s,'pending')",
                            (tx, run_id, token))


    def broker_fence(self, *, run_id: str, owner: str, token: int):
        """Build a broker-owned hook, never using model-provided lease details.

        The deployer must securely associate this lease with the granted run.
        The grant's signed operation identity is always the reservation key.
        """
        if (not isinstance(run_id, str) or not run_id
                or not isinstance(owner, str) or not owner
                or type(token) is not int or token < 1):
            raise ValueError("invalid broker fence binding")
        def enforce(grant, now):
            from .distributed import GatewayGrant
            if not isinstance(grant, GatewayGrant):
                raise LeaseDenied("invalid grant for fence")
            self.dispatch_once(run_id, owner, token, grant.envelope.transaction_id)
        return enforce

    def pending(self, transaction_id: str):
        """Inspection only: pending effects cannot be retried automatically."""
        if not isinstance(transaction_id, str) or not transaction_id:
            raise ValueError("invalid transaction")
        with self.db.transaction():
            return self.db.execute(
                "SELECT run_id,token,state FROM aak_fenced_dispatch "
                "WHERE transaction_id=%s", (transaction_id,)).fetchone()

    def close(self):
        self.db.close()
