"""Signed, scoped, one-use verification receipts for the offline repair loop.

The verifier public key must be configured by a trusted operator. No caller
approval flag is accepted. This does not authorize a provider effect.
"""
from dataclasses import dataclass
import sqlite3
from contextlib import closing
from .canonical import canonical_bytes
from .crypto import Ed25519Signer, b64decode
from .harness_repair_loop import Phase, RepairState
from .harness_eval_gate import Evaluation, compare


@dataclass(frozen=True)
class VerificationReceipt:
    receipt_id: str
    task_id: str
    principal_id: str
    attempt: int
    evidence_id: str
    approved: bool
    issued_at: int
    expires_at: int
    key_id: str
    signature: str

    def claim(self):
        return {k: getattr(self, k) for k in (
            "receipt_id", "task_id", "principal_id", "attempt", "evidence_id",
            "approved", "issued_at", "expires_at", "key_id")}


class VerifiedReceiptLedger:
    """Durable atomic replay ledger; do not place on ephemeral memory storage."""
    def __init__(self, path: str):
        if not isinstance(path, str) or not path or path == ":memory:":
            raise ValueError("durable path required")
        self.path = path
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS used_repair_receipts (id TEXT PRIMARY KEY)")
            db.commit()

    def accept(self, *, state: RepairState, receipt: VerificationReceipt,
               verifier: Ed25519Signer, task_id: str, principal_id: str,
               now: int) -> RepairState:
        if state.phase is not Phase.AWAIT_APPROVAL or state.attempts >= state.max_attempts:
            raise PermissionError("invalid approval state")
        if not isinstance(receipt, VerificationReceipt) or not isinstance(verifier, Ed25519Signer):
            raise PermissionError("trusted Ed25519 verification required")
        if any(not isinstance(v, str) or not v or len(v) > 128 for v in (
            receipt.receipt_id, receipt.task_id, receipt.principal_id, receipt.evidence_id,
            receipt.key_id, receipt.signature)):
            raise PermissionError("invalid receipt")
        if (type(receipt.approved) is not bool or not receipt.approved
                or type(receipt.attempt) is not int or receipt.attempt != state.attempts + 1
                or receipt.task_id != task_id or receipt.principal_id != principal_id
                or receipt.key_id != verifier.key_id):
            raise PermissionError("receipt scope or approval mismatch")
        if (type(now) is not int or type(receipt.issued_at) is not int
                or type(receipt.expires_at) is not int
                or receipt.issued_at > now or now >= receipt.expires_at
                or receipt.expires_at - receipt.issued_at > 600):
            raise PermissionError("receipt expired or invalid")
        try:
            signature = b64decode(receipt.signature)
            valid = verifier.verify(canonical_bytes(receipt.claim()), signature)
        except (ValueError, TypeError, OverflowError):
            valid = False
        if not valid:
            raise PermissionError("invalid verifier signature")
        with closing(sqlite3.connect(self.path, timeout=10, isolation_level=None)) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO used_repair_receipts(id) VALUES (?)", (receipt.receipt_id,))
                db.commit()
            except BaseException:
                db.rollback()
                raise PermissionError("receipt already used or store unavailable") from None
        return RepairState(Phase.VERIFY, state.attempts + 1,
                           state.max_attempts, receipt.evidence_id)

    def verify_and_decide(self, *, state: RepairState,
                          receipt: VerificationReceipt,
                          verifier: Ed25519Signer, task_id: str,
                          principal_id: str, now: int,
                          baseline: Evaluation, candidate: Evaluation):
        """Validate and consume trusted receipt before evaluating candidate.

        Fail closed on signature, scope, replay, or store errors. This is only
        an offline evaluation decision; it does not authorize any tool effects.
        """
        verified = self.accept(state=state, receipt=receipt, verifier=verifier,
                               task_id=task_id, principal_id=principal_id,
                               now=now)
        gate = compare(baseline, candidate)
        phase = Phase.ACCEPT if gate.accepted else Phase.REJECT
        return RepairState(phase, verified.attempts, verified.max_attempts,
                           verified.evidence_id), gate
