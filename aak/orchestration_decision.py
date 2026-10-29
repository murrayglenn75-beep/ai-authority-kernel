"""Fail-closed, side-effect-free orchestration decisions.

This helper does NOT mint AAK capabilities or bypass gateway verification.
A returned ACT is only permission to *request* ordinary AAK authorization.
"""
from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ACT = "ACT"
    ASK = "ASK"
    STOP = "STOP"


@dataclass(frozen=True)
class ProgressSnapshot:
    steps: int
    consecutive_no_progress: int
    approvals_required: bool = False
    approval_present: bool = False
    authorization_valid: bool = False
    state_ambiguous: bool = False


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str


def decide(snapshot: ProgressSnapshot, *, max_steps: int = 100,
           max_no_progress: int = 5) -> DecisionResult:
    """Evaluate safe next-step eligibility without producing external effects.

    Counters are supplied by a trusted executor (not the model). On restart
    counters and approval status must be recovered from durable trusted state.
    """
    if max_steps <= 0 or max_no_progress <= 0:
        raise ValueError("limits must be positive")
    if snapshot.steps < 0 or snapshot.consecutive_no_progress < 0:
        return DecisionResult(Decision.STOP, "invalid_counters")
    if snapshot.state_ambiguous:
        return DecisionResult(Decision.STOP, "ambiguous_effect_state")
    if snapshot.steps >= max_steps:
        return DecisionResult(Decision.STOP, "step_limit")
    if snapshot.consecutive_no_progress >= max_no_progress:
        return DecisionResult(Decision.STOP, "no_progress_limit")
    if not snapshot.authorization_valid:
        return DecisionResult(Decision.STOP, "not_authorized")
    if snapshot.approvals_required and not snapshot.approval_present:
        return DecisionResult(Decision.ASK, "human_approval_required")
    return DecisionResult(Decision.ACT, "eligible_for_aak_verification")
