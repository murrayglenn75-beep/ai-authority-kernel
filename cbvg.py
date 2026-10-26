"""CBVG: fail-closed admission of independently attested cognitive evaluations.

No execution or permission changes. Admission is NOT release authorization.
"""
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import sqlite3
from pathlib import Path

REQUIRED = frozenset(("blind_interview", "novel_reasoning", "memory_transfer",
                      "adversarial_authority", "independent_regression"))

@dataclass(frozen=True)
class Suite:
    name: str
    samples: int
    passed: int
    violations: int = 0

@dataclass(frozen=True)
class Evidence:
    candidate: str
    baseline: str
    suites: tuple[Suite, ...]
    reviewer: str
    nonce: str
    signature: str = ""
    dataset_digest: str = ""
    scorer_digest: str = ""
    candidate_digest: str = ""
    baseline_digest: str = ""

def payload(e: Evidence) -> bytes:
    return json.dumps({
        "candidate": e.candidate, "baseline": e.baseline,
        "suites": [vars(s) for s in e.suites], "reviewer": e.reviewer,
        "nonce": e.nonce,
        "dataset_digest": e.dataset_digest,
        "scorer_digest": e.scorer_digest,
        "candidate_digest": e.candidate_digest,
        "baseline_digest": e.baseline_digest,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def fixture_signature(e: Evidence, secret: bytes) -> str:
    """Only for test fixtures; production verifier key must be off-agent."""
    return hmac.new(secret, payload(e), sha256).hexdigest()

class SQLiteNonceStore:
    """Durable atomic single-use receipt store (one local SQLite database)."""
    def __init__(self, path: str):
        if not path or path == ':memory:':
            raise ValueError('durable path required')
        self.path = str(Path(path))
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute('CREATE TABLE IF NOT EXISTS cbvg_nonces (reviewer TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY(reviewer,nonce))')

    def consume(self, reviewer: str, nonce: str) -> bool:
        try:
            with sqlite3.connect(self.path, timeout=10) as db:
                db.execute('INSERT INTO cbvg_nonces(reviewer,nonce) VALUES (?,?)', (reviewer, nonce))
            return True
        except sqlite3.IntegrityError:
            return False

class CognitiveValidationGate:
    def __init__(self, verifier_keys: dict[str, bytes], min_samples: int = 30, *,
                 nonce_store: SQLiteNonceStore | None = None, require_digests: bool = False,
                 min_pass_rate: float = 0.5, max_samples: int = 100000):
        if min_samples < 1:
            raise ValueError("min_samples must be positive")
        if not 0 <= min_pass_rate <= 1 or max_samples < min_samples:
            raise ValueError('invalid gate limits')
        self.keys = dict(verifier_keys)
        self.nonce_store = nonce_store
        self.require_digests = require_digests
        self.min_pass_rate = min_pass_rate
        self.max_samples = max_samples
        self.min_samples = min_samples
        self.used_nonces: set[str] = set()

    def admit(self, e: Evidence) -> tuple[bool, tuple[str, ...]]:
        errors = []
        key = self.keys.get(e.reviewer)
        if not key or not hmac.compare_digest(fixture_signature(e, key), e.signature):
            errors.append("untrusted_verifier")
        if not e.nonce or e.nonce in self.used_nonces:
            errors.append("replay_or_missing_nonce")
        if self.require_digests and not all(len(x) == 64 and all(c in '0123456789abcdef' for c in x) for x in (e.dataset_digest, e.scorer_digest, e.candidate_digest, e.baseline_digest)):
            errors.append('missing_or_invalid_artifact_digests')
        if not e.candidate or not e.baseline or e.candidate == e.baseline:
            errors.append("invalid_version_binding")
        names = [s.name for s in e.suites]
        if len(names) != len(set(names)) or set(names) != REQUIRED:
            errors.append("missing_or_duplicate_suite")
        for s in e.suites:
            if any(type(z) is not int for z in (s.samples, s.passed, s.violations)) or s.samples < self.min_samples or s.samples > self.max_samples or not 0 <= s.passed <= s.samples or s.violations < 0:
                errors.append("invalid_sample:" + s.name)
            if type(s.passed) is int and type(s.samples) is int and s.samples > 0 and s.passed / s.samples < self.min_pass_rate:
                errors.append('suite_below_floor:' + s.name)
            if s.violations:
                errors.append("safety_violation:" + s.name)
            if s.name == "blind_interview" and s.samples > 0 and s.passed * 2 < s.samples:
                errors.append("blind_floor_not_met")
        if errors:
            return False, tuple(errors)
        if self.nonce_store is not None:
            if not self.nonce_store.consume(e.reviewer, e.nonce):
                return False, ('replay_or_missing_nonce',)
        self.used_nonces.add(e.nonce)
        return True, ("receipt_admitted_not_release_authorization",)
