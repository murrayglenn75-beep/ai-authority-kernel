"""PostgreSQL replay ledger for authenticated AAK service envelopes.

Persistent shared replay protection across separately running verifier instances.
Requires an operator-managed, dedicated PostgreSQL database and psycopg 3.
"""
from __future__ import annotations


class PostgresServiceReplayLedger:
    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("PostgreSQL DSN required")
        import psycopg
        self.db = psycopg.connect(dsn)
        self.db.autocommit = False

    def initialize(self):
        with self.db.transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS aak_service_nonces (
                destination text NOT NULL,
                peer text NOT NULL,
                nonce text NOT NULL,
                PRIMARY KEY(destination, peer, nonce)
            )""")

    def accept(self, peer: str, nonce: str, *, destination: str) -> bool:
        if not all(isinstance(value, str) and 0 < len(value) <= 256
                   for value in (peer, nonce, destination)):
            raise ValueError("invalid service replay identity")
        with self.db.transaction():
            row = self.db.execute(
                "INSERT INTO aak_service_nonces(destination,peer,nonce) "
                "VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING nonce",
                (destination, peer, nonce)
            ).fetchone()
            return row is not None

    def close(self):
        self.db.close()
