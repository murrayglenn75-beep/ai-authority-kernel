"""Serializable PostgreSQL authority state for multi-replica staging.

The dependency is imported lazily so the core package remains usable without a
database driver.  Install the ``postgres`` optional extra in deployed services.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator


class _Reject(Exception):
    pass


class PostgresAuthorityStore:
    def __init__(self, dsn: str, *, connect: Callable | None = None) -> None:
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("invalid_postgres_dsn")
        if connect is None:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("install ai-authority-kernel[postgres]") from exc
            connect = psycopg.connect
        self._connection = connect(dsn)
        self._closed = False

    @contextmanager
    def _transaction(self) -> Iterator[object]:
        if self._closed:
            raise RuntimeError("authority_state_unavailable")
        with self._connection.transaction():
            with self._connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                yield cursor

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "PostgresAuthorityStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def consume(
        self, nonce: str, bucket_costs: dict[str, float], bucket_limits: dict[str, float], now: int,
        *, idempotency_key: str | None = None, request_hash: str | None = None,
        resource_key: str | None = None, expected_resource_version: int | None = None,
        strict_integer: bool = False,
    ) -> tuple[bool, str]:
        if not strict_integer:
            return False, "integer_budget_required"
        values = (*bucket_costs.values(), *bucket_limits.values())
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 9_223_372_036_854_775_807 for v in values):
            return False, "non_integer_budget"
        try:
            with self._transaction() as cur:
                cur.execute("SELECT 1 FROM aak_revoked_nonces WHERE nonce=%s", (nonce,))
                if cur.fetchone():
                    raise _Reject("revoked")
                cur.execute("INSERT INTO aak_used_nonces(nonce, used_at) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING nonce", (nonce, now))
                if cur.fetchone() is None:
                    raise _Reject("replay")
                if idempotency_key is not None:
                    if not request_hash:
                        raise _Reject("invalid_request_hash")
                    cur.execute("SELECT request_hash FROM aak_transaction_keys WHERE idempotency_key=%s FOR UPDATE", (idempotency_key,))
                    previous = cur.fetchone()
                    if previous:
                        raise _Reject("duplicate_transaction" if previous[0] == request_hash else "idempotency_conflict")
                    cur.execute("INSERT INTO aak_transaction_keys(idempotency_key, request_hash) VALUES (%s, %s)", (idempotency_key, request_hash))
                if resource_key is not None and expected_resource_version is not None:
                    cur.execute("SELECT version FROM aak_resource_versions WHERE resource_key=%s FOR UPDATE", (resource_key,))
                    row = cur.fetchone()
                    current = int(row[0]) if row else 0
                    if current != expected_resource_version:
                        raise _Reject("stale_resource_state")
                    cur.execute(
                        "INSERT INTO aak_resource_versions(resource_key, version) VALUES (%s, %s) "
                        "ON CONFLICT(resource_key) DO UPDATE SET version=EXCLUDED.version",
                        (resource_key, expected_resource_version + 1),
                    )
                for bucket, cost in bucket_costs.items():
                    cur.execute("INSERT INTO aak_integer_budgets(bucket, amount) VALUES (%s, 0) ON CONFLICT DO NOTHING", (bucket,))
                    cur.execute("SELECT amount FROM aak_integer_budgets WHERE bucket=%s FOR UPDATE", (bucket,))
                    current = int(cur.fetchone()[0])
                    if current + cost > bucket_limits.get(bucket, 0):
                        raise _Reject(f"budget_exceeded:{bucket}")
                    cur.execute("UPDATE aak_integer_budgets SET amount=amount+%s WHERE bucket=%s", (cost, bucket))
        except _Reject as exc:
            return False, str(exc)
        return True, "consumed"

    def accept_assurance_once(
        self, *, kind: str, identifier: str, expires_at: int, now: int,
        monotonic_name: str | None = None, monotonic_value: int | None = None,
    ) -> tuple[bool, str]:
        if kind not in {"policy", "identity"} or not identifier or expires_at <= now:
            return False, "invalid_assurance_state"
        try:
            with self._transaction() as cur:
                cur.execute("DELETE FROM aak_assurance_replays WHERE expires_at<=%s", (now,))
                if monotonic_name is not None:
                    cur.execute("SELECT value FROM aak_assurance_state WHERE name=%s FOR UPDATE", (monotonic_name,))
                    row = cur.fetchone()
                    if row and (monotonic_value is None or monotonic_value < int(row[0])):
                        raise _Reject("assurance_rollback")
                cur.execute(
                    "INSERT INTO aak_assurance_replays(kind, identifier, expires_at) VALUES (%s, %s, %s) "
                    "ON CONFLICT DO NOTHING RETURNING identifier", (kind, identifier, expires_at),
                )
                if cur.fetchone() is None:
                    raise _Reject("assurance_replay")
                if monotonic_name is not None:
                    cur.execute(
                        "INSERT INTO aak_assurance_state(name, value) VALUES (%s, %s) "
                        "ON CONFLICT(name) DO UPDATE SET value=GREATEST(aak_assurance_state.value, EXCLUDED.value)",
                        (monotonic_name, monotonic_value),
                    )
        except _Reject as exc:
            return False, str(exc)
        return True, "assurance_accepted"

    def raise_assurance_floor(self, name: str, value: int) -> None:
        if not name or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("invalid_assurance_floor")
        with self._transaction() as cur:
            cur.execute(
                "INSERT INTO aak_assurance_state(name, value) VALUES (%s, %s) "
                "ON CONFLICT(name) DO UPDATE SET value=GREATEST(aak_assurance_state.value, EXCLUDED.value)",
                (name, value),
            )

    def assurance_floor(self, name: str) -> int:
        if not name:
            raise ValueError("invalid_assurance_floor")
        with self._transaction() as cur:
            cur.execute("SELECT value FROM aak_assurance_state WHERE name=%s", (name,))
            row = cur.fetchone()
            return int(row[0]) if row else 0
