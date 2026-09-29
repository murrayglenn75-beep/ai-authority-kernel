"""Hardened interaction-point controls for AAK v0.9.0."""

from __future__ import annotations

import json
import threading
import time
import unicodedata
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

from .canonical import canonical_bytes, digest
from .crypto import CapabilitySigner, b64decode, b64encode


class BoundaryError(ValueError):
    pass


@dataclass(frozen=True)
class DefenseDecision:
    allowed: bool
    reason: str
    score: int
    boundaries: tuple[str, ...]
    blocked_until: int | None = None


class CompoundAttackGuard:
    """Correlate authenticated attack signals and trip an external circuit breaker.

    ``trusted_source_id`` must come from a mutually authenticated proxy or
    equivalent external identity system. Attacker-supplied claims are not safe
    identifiers and deliberately cannot contribute to blocking decisions.
    """

    DEFAULT_WEIGHTS = {
        "malformed": 1,
        "replay": 2,
        "binding_mismatch": 3,
        "identity_mismatch": 4,
        "invalid_signature": 4,
        "quorum_bypass": 5,
        "tenant_substitution": 5,
        "audit_tamper": 7,
    }
    ALLOWED_BOUNDARIES = frozenset({"transport", "authority", "tenant", "gateway", "audit", "downstream", "wire", "identity"})

    def __init__(
        self, *, threshold: int = 12, window_seconds: int = 60,
        block_seconds: int = 300, max_sources: int = 10_000,
        max_events_per_source: int = 100, max_identity_length: int = 512,
        weights: dict[str, int] | None = None,
    ) -> None:
        if min(threshold, window_seconds, block_seconds, max_sources, max_events_per_source, max_identity_length) < 1:
            raise ValueError("invalid_compound_guard_configuration")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self.max_sources = max_sources
        self.max_events_per_source = max_events_per_source
        self.max_identity_length = max_identity_length
        self.weights = dict(self.DEFAULT_WEIGHTS if weights is None else weights)
        if not self.weights or any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in self.weights.values()):
            raise ValueError("invalid_compound_guard_weights")
        self._events: dict[str, list[tuple[int, str, int]]] = {}
        self._blocked: dict[str, int] = {}
        self._next_full_prune_at = 0
        self._lock = threading.RLock()

    def _prune_source(self, source: str, now: int) -> None:
        cutoff = now - self.window_seconds
        if source in self._events:
            events = [event for event in self._events[source] if event[0] >= cutoff]
            if events:
                self._events[source] = events
            else:
                del self._events[source]
        if source in self._blocked and now >= self._blocked[source]:
            del self._blocked[source]

    def _full_prune_if_due(self, now: int) -> None:
        if now < self._next_full_prune_at:
            return
        for source in tuple(set(self._events) | set(self._blocked)):
            self._prune_source(source, now)
        self._next_full_prune_at = now + self.window_seconds

    def check(self, trusted_source_id: str, *, now: int) -> DefenseDecision:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            return DefenseDecision(False, "invalid_defense_time", 0, ())
        if not isinstance(trusted_source_id, str) or not trusted_source_id or len(trusted_source_id) > self.max_identity_length:
            return DefenseDecision(False, "missing_trusted_source_identity", 0, ())
        with self._lock:
            self._prune_source(trusted_source_id, now)
            blocked_until = self._blocked.get(trusted_source_id)
            if blocked_until is not None:
                events = self._events.get(trusted_source_id, [])
                boundaries = tuple(sorted({event[1] for event in events}))
                return DefenseDecision(False, "compound_attack_source_blocked", self._score(events), boundaries, blocked_until)
            events = self._events.get(trusted_source_id, [])
            boundaries = tuple(sorted({event[1] for event in events}))
            return DefenseDecision(True, "source_allowed", self._score(events), boundaries)

    @staticmethod
    def _score(events: list[tuple[int, str, int]]) -> int:
        distinct = len({event[1] for event in events})
        return sum(event[2] for event in events) + max(0, distinct - 1) * 2

    def record(
        self, trusted_source_id: str, *, boundary: str, signal: str,
        now: int, externally_authenticated: bool,
    ) -> DefenseDecision:
        if not externally_authenticated:
            return DefenseDecision(True, "untrusted_attack_signal_ignored", 0, ())
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            return DefenseDecision(False, "invalid_defense_time", 0, ())
        if not isinstance(trusted_source_id, str) or not trusted_source_id or len(trusted_source_id) > self.max_identity_length:
            return DefenseDecision(False, "missing_trusted_source_identity", 0, ())
        if not isinstance(boundary, str) or boundary not in self.ALLOWED_BOUNDARIES or signal not in self.weights:
            return DefenseDecision(False, "invalid_defense_signal", 0, ())
        with self._lock:
            self._prune_source(trusted_source_id, now)
            if trusted_source_id in self._blocked:
                return self.check(trusted_source_id, now=now)
            if trusted_source_id not in self._events and len(self._events) >= self.max_sources:
                self._full_prune_if_due(now)
                if len(self._events) >= self.max_sources:
                    return DefenseDecision(False, "compound_guard_capacity_fail_closed", 0, ())
            events = self._events.setdefault(trusted_source_id, [])
            if len(events) >= self.max_events_per_source:
                blocked_until = now + self.block_seconds
                self._blocked[trusted_source_id] = blocked_until
                boundaries = tuple(sorted({event[1] for event in events}))
                return DefenseDecision(False, "compound_attack_source_blocked", self._score(events), boundaries, blocked_until)
            events.append((now, boundary, self.weights[signal]))
            score = self._score(events)
            boundaries = tuple(sorted({event[1] for event in events}))
            if score >= self.threshold:
                blocked_until = now + self.block_seconds
                self._blocked[trusted_source_id] = blocked_until
                return DefenseDecision(False, "compound_attack_source_blocked", score, boundaries, blocked_until)
            return DefenseDecision(True, "attack_signal_recorded", score, boundaries)


def canonical_route(route: str) -> str:
    if not isinstance(route, str) or not route.startswith("/") or len(route) > 512:
        raise BoundaryError("invalid_route")
    parsed = urlsplit(route)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "\\" in route:
        raise BoundaryError("noncanonical_route")
    decoded = unquote(parsed.path)
    if decoded != parsed.path or "//" in decoded or any(part in (".", "..") for part in decoded.split("/")):
        raise BoundaryError("noncanonical_route")
    return decoded


class StrictJSONGate:
    def __init__(self, *, required_fields: Iterable[str], max_bytes: int = 32_768, max_depth: int = 16) -> None:
        self.required_fields = frozenset(required_fields)
        self.max_bytes = max_bytes
        self.max_depth = max_depth

    @staticmethod
    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BoundaryError("duplicate_json_key")
            result[key] = value
        return result

    def _validate(self, value: Any, depth: int = 0) -> None:
        if depth > self.max_depth:
            raise BoundaryError("maximum_depth_exceeded")
        if isinstance(value, str):
            if unicodedata.normalize("NFC", value) != value or "\x00" in value:
                raise BoundaryError("noncanonical_text")
        elif isinstance(value, bool) or value is None or isinstance(value, int):
            return
        elif isinstance(value, float):
            raise BoundaryError("floating_point_not_allowed")
        elif isinstance(value, list):
            for item in value:
                self._validate(item, depth + 1)
        elif isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise BoundaryError("invalid_json_key")
                self._validate(key, depth + 1)
                self._validate(item, depth + 1)
        else:
            raise BoundaryError("unsupported_json_type")

    def parse(self, raw: bytes) -> dict[str, Any]:
        if not isinstance(raw, bytes) or not raw or len(raw) > self.max_bytes:
            raise BoundaryError("invalid_message_size")
        try:
            text = raw.decode("utf-8", errors="strict")
            value = json.loads(text, object_pairs_hook=self._object, parse_constant=lambda _x: (_ for _ in ()).throw(BoundaryError("nonfinite_number")))
        except BoundaryError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BoundaryError("invalid_json") from exc
        if not isinstance(value, dict) or set(value) != self.required_fields:
            raise BoundaryError("schema_mismatch")
        self._validate(value)
        if canonical_bytes(value) != raw:
            raise BoundaryError("noncanonical_json")
        return value


@dataclass(frozen=True)
class KeyStatus:
    verifier: CapabilitySigner
    not_before: int
    not_after: int
    revoked_at: int | None = None


class KeyRegistry:
    def __init__(self, statuses: Iterable[KeyStatus] = ()) -> None:
        self._statuses = {status.verifier.key_id: status for status in statuses}
        self._lock = threading.RLock()

    def status(self, key_id: str, at: int) -> KeyStatus | None:
        with self._lock:
            status = self._statuses.get(key_id)
            if status is None or at < status.not_before or at >= status.not_after:
                return None
            if status.revoked_at is not None and at >= status.revoked_at:
                return None
            return status

    def revoke(self, key_id: str, at: int) -> bool:
        with self._lock:
            status = self._statuses.get(key_id)
            if status is None:
                return False
            self._statuses[key_id] = KeyStatus(status.verifier, status.not_before, status.not_after, at)
            return True


@dataclass(frozen=True)
class SenderProof:
    key_id: str
    subject: str
    method: str
    route: str
    audience: str
    body_hash: str
    issued_at: int
    nonce: str
    signature: str

    def claim(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if key != "signature"}


def create_sender_proof(
    signer: CapabilitySigner, *, method: str, route: str, audience: str,
    body: bytes, issued_at: int, nonce: str, subject: str | None = None,
) -> SenderProof:
    claim = {
        "key_id": signer.key_id, "subject": subject or signer.key_id,
        "method": method.upper(), "route": canonical_route(route),
        "audience": audience, "body_hash": digest_bytes(body), "issued_at": issued_at, "nonce": nonce,
    }
    return SenderProof(**claim, signature=b64encode(signer.sign(canonical_bytes(claim))))


def digest_bytes(value: bytes) -> str:
    import hashlib
    return hashlib.sha256(value).hexdigest()


class SenderProofVerifier:
    def __init__(
        self, registry: KeyRegistry, *, audience: str, route: str, method: str,
        max_age_seconds: int = 30, max_future_skew_seconds: int = 5,
        allow_test_time_override: bool = False,
        expected_subject: str | None = None, max_replay_entries: int = 100_000,
    ) -> None:
        self.registry = registry
        self.audience = audience
        self.route = canonical_route(route)
        self.method = method.upper()
        self.max_age_seconds = max_age_seconds
        self.max_future_skew_seconds = max_future_skew_seconds
        self.allow_test_time_override = allow_test_time_override
        self.expected_subject = expected_subject
        self.max_replay_entries = max_replay_entries
        self._seen: dict[tuple[str, str], int] = {}
        self._seen_order: deque[tuple[int, tuple[str, str]]] = deque()
        self._lock = threading.RLock()

    def verify(self, proof: SenderProof, body: bytes, *, now: int | None = None) -> tuple[bool, str]:
        if now is not None and not self.allow_test_time_override:
            raise ValueError("caller-supplied time is disabled")
        if now is not None and (isinstance(now, bool) or not isinstance(now, int) or now < 0):
            raise ValueError("invalid trusted time")
        timestamp = int(time.time()) if now is None else now
        try:
            if proof.method != self.method or canonical_route(proof.route) != self.route:
                return False, "request_target_mismatch"
        except BoundaryError:
            return False, "request_target_mismatch"
        if proof.audience != self.audience or proof.body_hash != digest_bytes(body):
            return False, "request_binding_mismatch"
        if not isinstance(proof.subject, str) or not proof.subject:
            return False, "invalid_sender_subject"
        if self.expected_subject is not None and proof.subject != self.expected_subject:
            return False, "sender_subject_mismatch"
        if proof.issued_at > timestamp + self.max_future_skew_seconds or timestamp - proof.issued_at > self.max_age_seconds:
            return False, "stale_or_future_proof"
        if not proof.nonce or len(proof.nonce) > 128:
            return False, "invalid_proof_nonce"
        status = self.registry.status(proof.key_id, timestamp)
        if status is None:
            return False, "unknown_expired_or_revoked_key"
        try:
            valid = status.verifier.verify(canonical_bytes(proof.claim()), b64decode(proof.signature))
        except (TypeError, ValueError):
            valid = False
        if not valid:
            return False, "invalid_sender_signature"
        replay_key = (proof.key_id, proof.nonce)
        with self._lock:
            cutoff = timestamp - self.max_age_seconds
            while self._seen_order and self._seen_order[0][0] < cutoff:
                seen_at, old_key = self._seen_order.popleft()
                if self._seen.get(old_key) == seen_at:
                    del self._seen[old_key]
            if replay_key in self._seen:
                return False, "sender_proof_replay"
            if len(self._seen) >= self.max_replay_entries:
                return False, "replay_cache_capacity_reached"
            self._seen[replay_key] = timestamp
            self._seen_order.append((timestamp, replay_key))
        return True, "verified"


class IdempotencyLedger:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str, str, str], str] = {}
        self._lock = threading.RLock()

    def reserve(self, *, tenant: str, action: str, resource: str, transaction_id: str, request_hash: str) -> tuple[bool, str]:
        if not all(isinstance(item, str) and item for item in (tenant, action, resource, transaction_id, request_hash)):
            return False, "invalid_idempotency_key"
        key = (tenant, action, resource, transaction_id)
        with self._lock:
            previous = self._entries.get(key)
            if previous is None:
                self._entries[key] = request_hash
                return True, "reserved"
            if previous == request_hash:
                return False, "duplicate_transaction"
            return False, "idempotency_conflict"


@dataclass(frozen=True)
class EffectReceipt:
    claim: dict[str, Any]
    key_id: str
    signature: str


class EffectReceiptIssuer:
    def __init__(self, signer: CapabilitySigner) -> None:
        self.signer = signer

    def issue(
        self, *, transaction_id: str, capability_hash: str, request_hash: str,
        exact_effect: dict[str, int], previous_state_version: int,
        resulting_state_version: int, downstream_identity: str, completed_at: int,
    ) -> EffectReceipt:
        if resulting_state_version != previous_state_version + 1:
            raise BoundaryError("invalid_state_transition")
        claim = {
            "v": 1, "transaction_id": transaction_id, "capability_hash": capability_hash,
            "request_hash": request_hash, "exact_effect": exact_effect,
            "previous_state_version": previous_state_version,
            "resulting_state_version": resulting_state_version,
            "downstream_identity": downstream_identity, "completed_at": completed_at,
        }
        return EffectReceipt(claim, self.signer.key_id, b64encode(self.signer.sign(canonical_bytes(claim))))

    @staticmethod
    def verify(receipt: EffectReceipt, registry: KeyRegistry, *, now: int) -> bool:
        status = registry.status(receipt.key_id, now)
        if status is None:
            return False
        try:
            return status.verifier.verify(canonical_bytes(receipt.claim), b64decode(receipt.signature))
        except (TypeError, ValueError):
            return False


@dataclass(frozen=True)
class PolicyApproval:
    key_id: str
    signature: str


@dataclass(frozen=True)
class SignedPolicyRelease:
    claim: dict[str, Any]
    approvals: tuple[PolicyApproval, ...]


def approve_policy(signer: CapabilitySigner, claim: dict[str, Any]) -> PolicyApproval:
    return PolicyApproval(signer.key_id, b64encode(signer.sign(canonical_bytes(claim))))


class PolicyDeploymentGate:
    """Quorum and rollback protection for the operator-to-policy boundary."""

    def __init__(
        self, registry: KeyRegistry, *, threshold: int, environment: str,
        max_release_age_seconds: int = 300, max_future_skew_seconds: int = 5,
    ) -> None:
        if threshold < 1:
            raise ValueError("invalid threshold")
        self.registry = registry
        self.threshold = threshold
        self.environment = environment
        self.max_release_age_seconds = max_release_age_seconds
        self.max_future_skew_seconds = max_future_skew_seconds
        self._generation = -1
        self._policy_hash: str | None = None
        self._lock = threading.RLock()

    def activate(self, release: SignedPolicyRelease, *, now: int) -> tuple[bool, str]:
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            return False, "invalid_trusted_time"
        claim = release.claim
        if set(claim) != {"policy_hash", "version", "generation", "environment", "issued_at"}:
            return False, "policy_schema_mismatch"
        if claim.get("environment") != self.environment:
            return False, "wrong_policy_environment"
        if not isinstance(claim.get("generation"), int) or isinstance(claim.get("generation"), bool):
            return False, "invalid_policy_generation"
        if not isinstance(claim.get("policy_hash"), str) or not claim["policy_hash"]:
            return False, "invalid_policy_hash"
        if not isinstance(claim.get("version"), str) or not claim["version"]:
            return False, "invalid_policy_version"
        issued_at = claim.get("issued_at")
        if isinstance(issued_at, bool) or not isinstance(issued_at, int):
            return False, "invalid_policy_time"
        if issued_at > now + self.max_future_skew_seconds or now - issued_at > self.max_release_age_seconds:
            return False, "stale_or_future_policy_release"
        valid: set[str] = set()
        for approval in release.approvals:
            status = self.registry.status(approval.key_id, now)
            if status is None or approval.key_id in valid:
                continue
            try:
                verified = status.verifier.verify(canonical_bytes(claim), b64decode(approval.signature))
            except (TypeError, ValueError):
                verified = False
            if verified:
                valid.add(approval.key_id)
        if len(valid) < self.threshold:
            return False, "insufficient_policy_quorum"
        with self._lock:
            if claim["generation"] <= self._generation:
                return False, "policy_rollback_or_replay"
            self._generation = claim["generation"]
            self._policy_hash = claim["policy_hash"]
        return True, "policy_activated"
