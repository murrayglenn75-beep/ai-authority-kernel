import sqlite3
import threading
import hashlib
from pathlib import Path


class StateStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.lock = threading.RLock()
        self._closed = False
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, used_at INTEGER NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS budgets (bucket TEXT PRIMARY KEY, amount REAL NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS integer_budgets (bucket TEXT PRIMARY KEY, amount INTEGER NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE)")
            self.db.execute("CREATE TABLE IF NOT EXISTS quarantine (agent TEXT PRIMARY KEY, reason TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS revoked_nonces (nonce TEXT PRIMARY KEY, reason TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS transaction_keys (idempotency_key TEXT PRIMARY KEY, request_hash TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS resource_versions (resource_key TEXT PRIMARY KEY, version INTEGER NOT NULL)")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS effect_journal ("
                "operation_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, state TEXT NOT NULL, "
                "provider_reference TEXT, result_hash TEXT, updated_at INTEGER NOT NULL)"
            )
            self.db.execute("CREATE TABLE IF NOT EXISTS assurance_state (name TEXT PRIMARY KEY, value INTEGER NOT NULL)")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS assurance_replays (kind TEXT NOT NULL, identifier TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, PRIMARY KEY(kind, identifier))"
            )
            self.db.execute("CREATE INDEX IF NOT EXISTS assurance_replays_expiry ON assurance_replays(expires_at)")
        except BaseException:
            self.db.close()
            self._closed = True
            raise

    def close(self) -> None:
        """Release the database deterministically, including on Windows."""
        with self.lock:
            if not self._closed:
                self.db.close()
                self._closed = True

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def is_quarantined(self, agent: str) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1 FROM quarantine WHERE agent=?", (agent,)).fetchone() is not None

    def quarantine(self, agent: str, reason: str) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO quarantine(agent, reason) VALUES (?, ?)", (agent, reason))

    def revoke_nonce(self, nonce: str, reason: str) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO revoked_nonces(nonce, reason) VALUES (?, ?)", (nonce, reason))

    def is_nonce_revoked(self, nonce: str) -> bool:
        with self.lock:
            return self.db.execute("SELECT 1 FROM revoked_nonces WHERE nonce=?", (nonce,)).fetchone() is not None

    def consume(
        self, nonce: str, bucket_costs: dict[str, float], bucket_limits: dict[str, float], now: int,
        *, idempotency_key: str | None = None, request_hash: str | None = None,
        resource_key: str | None = None, expected_resource_version: int | None = None,
        strict_integer: bool = False,
    ) -> tuple[bool, str]:
        if strict_integer:
            values = (*bucket_costs.values(), *bucket_limits.values())
            if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
                return False, "non_integer_budget"
            if any(value < 0 or value > 9_223_372_036_854_775_807 for value in values):
                return False, "integer_budget_out_of_range"
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                if self.db.execute("SELECT 1 FROM used_nonces WHERE nonce=?", (nonce,)).fetchone():
                    self.db.execute("ROLLBACK")
                    return False, "replay"
                if self.db.execute("SELECT 1 FROM revoked_nonces WHERE nonce=?", (nonce,)).fetchone():
                    self.db.execute("ROLLBACK")
                    return False, "revoked"
                if idempotency_key is not None:
                    previous = self.db.execute("SELECT request_hash FROM transaction_keys WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                    if previous:
                        self.db.execute("ROLLBACK")
                        return False, "duplicate_transaction" if previous[0] == request_hash else "idempotency_conflict"
                if resource_key is not None and expected_resource_version is not None:
                    row = self.db.execute("SELECT version FROM resource_versions WHERE resource_key=?", (resource_key,)).fetchone()
                    current_version = int(row[0]) if row else 0
                    if current_version != expected_resource_version:
                        self.db.execute("ROLLBACK")
                        return False, "stale_resource_state"
                for bucket, cost in bucket_costs.items():
                    if strict_integer:
                        current_row = self.db.execute("SELECT amount FROM integer_budgets WHERE bucket=?", (bucket,)).fetchone()
                    else:
                        current_row = self.db.execute("SELECT amount FROM budgets WHERE bucket=?", (bucket,)).fetchone()
                    current = int(current_row[0]) if strict_integer and current_row else (float(current_row[0]) if current_row else 0)
                    if current + cost > bucket_limits.get(bucket, 0.0):
                        self.db.execute("ROLLBACK")
                        return False, f"budget_exceeded:{bucket}"
                self.db.execute("INSERT INTO used_nonces(nonce, used_at) VALUES (?, ?)", (nonce, now))
                if idempotency_key is not None:
                    if not request_hash:
                        self.db.execute("ROLLBACK")
                        return False, "invalid_request_hash"
                    self.db.execute("INSERT INTO transaction_keys(idempotency_key, request_hash) VALUES (?, ?)", (idempotency_key, request_hash))
                if resource_key is not None and expected_resource_version is not None:
                    self.db.execute(
                        "INSERT INTO resource_versions(resource_key, version) VALUES (?, ?) "
                        "ON CONFLICT(resource_key) DO UPDATE SET version=excluded.version",
                        (resource_key, expected_resource_version + 1),
                    )
                for bucket, cost in bucket_costs.items():
                    if strict_integer:
                        self.db.execute(
                            "INSERT INTO integer_budgets(bucket, amount) VALUES (?, ?) ON CONFLICT(bucket) DO UPDATE SET amount=amount+excluded.amount",
                            (bucket, cost),
                        )
                    else:
                        self.db.execute(
                            "INSERT INTO budgets(bucket, amount) VALUES (?, ?) ON CONFLICT(bucket) DO UPDATE SET amount=amount+excluded.amount",
                            (bucket, cost),
                        )
                self.db.execute("COMMIT")
                return True, "consumed"
            except Exception:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def resource_version(self, resource_key: str) -> int:
        with self.lock:
            row = self.db.execute("SELECT version FROM resource_versions WHERE resource_key=?", (resource_key,)).fetchone()
            return int(row[0]) if row else 0

    def begin_effect(self, operation_id: str, request_hash: str, now: int) -> tuple[bool, str]:
        """Reserve one provider operation before calling an external system."""
        if not operation_id or not request_hash or isinstance(now, bool) or not isinstance(now, int) or now < 0:
            return False, "invalid_effect_record"
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                row = self.db.execute(
                    "SELECT request_hash, state FROM effect_journal WHERE operation_id=?", (operation_id,),
                ).fetchone()
                if row:
                    self.db.execute("ROLLBACK")
                    if row[0] != request_hash:
                        return False, "effect_idempotency_conflict"
                    return False, f"effect_already_{row[1]}"
                self.db.execute(
                    "INSERT INTO effect_journal(operation_id, request_hash, state, updated_at) VALUES (?, ?, 'prepared', ?)",
                    (operation_id, request_hash, now),
                )
                self.db.execute("COMMIT")
                return True, "effect_prepared"
            except Exception:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def transition_effect(
        self, operation_id: str, request_hash: str, *, from_state: str,
        to_state: str, now: int, provider_reference: str | None = None,
        result_hash: str | None = None,
    ) -> tuple[bool, str]:
        allowed = {
            ("prepared", "submitted"), ("prepared", "failed"),
            ("submitted", "succeeded"), ("submitted", "failed"),
            ("submitted", "ambiguous"), ("ambiguous", "succeeded"),
            ("ambiguous", "failed"),
        }
        if (not operation_id or not request_hash
                or isinstance(now, bool) or not isinstance(now, int) or now < 0
                or provider_reference is not None and (not isinstance(provider_reference, str) or len(provider_reference) > 1024)
                or result_hash is not None and (not isinstance(result_hash, str) or len(result_hash) > 1024)):
            return False, "invalid_effect_transition"
        if (from_state, to_state) not in allowed:
            return False, "invalid_effect_transition"
        with self.lock:
            cursor = self.db.execute(
                "UPDATE effect_journal SET state=?, provider_reference=COALESCE(?, provider_reference), "
                "result_hash=COALESCE(?, result_hash), updated_at=? "
                "WHERE operation_id=? AND request_hash=? AND state=?",
                (to_state, provider_reference, result_hash, now, operation_id, request_hash, from_state),
            )
            return (True, f"effect_{to_state}") if cursor.rowcount == 1 else (False, "effect_transition_conflict")

    def effect_status(self, operation_id: str) -> dict[str, object] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT request_hash, state, provider_reference, result_hash, updated_at "
                "FROM effect_journal WHERE operation_id=?", (operation_id,),
            ).fetchone()
            if row is None:
                return None
            return dict(zip(("request_hash", "state", "provider_reference", "result_hash", "updated_at"), row))

    def accept_assurance_once(
        self, *, kind: str, identifier: str, expires_at: int,
        now: int, monotonic_name: str | None = None, monotonic_value: int | None = None,
    ) -> tuple[bool, str]:
        """Atomically reject assurance replay and optional revision rollback."""
        if (kind not in {"policy", "identity"} or not identifier
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (expires_at, now))
                or expires_at <= now):
            return False, "invalid_assurance_state"
        if (monotonic_name is None) != (monotonic_value is None):
            return False, "invalid_assurance_state"
        if monotonic_value is not None and (isinstance(monotonic_value, bool) or not isinstance(monotonic_value, int) or monotonic_value < 0):
            return False, "invalid_assurance_state"
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("DELETE FROM assurance_replays WHERE expires_at<=?", (now,))
                if monotonic_name is not None:
                    row = self.db.execute("SELECT value FROM assurance_state WHERE name=?", (monotonic_name,)).fetchone()
                    if row and monotonic_value < int(row[0]):
                        self.db.execute("ROLLBACK")
                        return False, "assurance_rollback"
                if self.db.execute(
                    "SELECT 1 FROM assurance_replays WHERE kind=? AND identifier=?", (kind, identifier),
                ).fetchone():
                    self.db.execute("ROLLBACK")
                    return False, "assurance_replay"
                self.db.execute(
                    "INSERT INTO assurance_replays(kind, identifier, expires_at) VALUES (?, ?, ?)",
                    (kind, identifier, expires_at),
                )
                if monotonic_name is not None:
                    self.db.execute(
                        "INSERT INTO assurance_state(name, value) VALUES (?, ?) "
                        "ON CONFLICT(name) DO UPDATE SET value=MAX(value, excluded.value)",
                        (monotonic_name, monotonic_value),
                    )
                self.db.execute("COMMIT")
                return True, "assurance_accepted"
            except Exception:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def raise_assurance_floor(self, name: str, value: int) -> None:
        """Raise, but never lower, a durable consistency floor."""
        if not name or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("invalid_assurance_floor")
        with self.lock:
            self.db.execute(
                "INSERT INTO assurance_state(name, value) VALUES (?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value=MAX(value, excluded.value)",
                (name, value),
            )

    def assurance_floor(self, name: str) -> int:
        if not name:
            raise ValueError("invalid_assurance_floor")
        with self.lock:
            row = self.db.execute("SELECT value FROM assurance_state WHERE name=?", (name,)).fetchone()
            return int(row[0]) if row else 0

    def append_audit(self, event: str) -> str:
        with self.lock:
            previous = self.db.execute("SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = previous[0] if previous else "GENESIS"
            event_hash = hashlib.sha256((prev_hash + "\n" + event).encode("utf-8")).hexdigest()
            self.db.execute(
                "INSERT INTO audit(event, prev_hash, event_hash) VALUES (?, ?, ?)",
                (event, prev_hash, event_hash),
            )
            return event_hash

    def verify_audit_chain(self) -> bool:
        with self.lock:
            previous = "GENESIS"
            rows = self.db.execute("SELECT event, prev_hash, event_hash FROM audit ORDER BY seq").fetchall()
            for event, prev_hash, event_hash in rows:
                expected = hashlib.sha256((previous + "\n" + event).encode("utf-8")).hexdigest()
                if prev_hash != previous or not secrets_compare(expected, event_hash):
                    return False
                previous = event_hash
            return True


def secrets_compare(left: str, right: str) -> bool:
    # Kept local to avoid making audit verification depend on model-controlled code.
    import hmac

    return hmac.compare_digest(left, right)
