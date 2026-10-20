"""Non-executing evidence-driven engineering loop policy.

The caller runs work through the independently authorized AAK broker;
this module only decides whether a proposed repair may advance. No subprocess,
network, filesystem mutation or authorization grants are exposed.
"""
from dataclasses import dataclass
from enum import Enum
from .harness_eval_gate import Evaluation, GateDecision, compare


class Phase(str, Enum):
    INSPECT = "inspect"
    PLAN = "plan"
    AWAIT_APPROVAL = "await_approval"
    VERIFY = "verify"
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass(frozen=True)
class RepairState:
    phase: Phase = Phase.INSPECT
    attempts: int = 0
    max_attempts: int = 3
    evidence_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.phase, Phase):
            raise ValueError("invalid phase")
        if type(self.attempts) is not int or type(self.max_attempts) is not int or not (0 <= self.attempts <= self.max_attempts <= 10):
            raise ValueError("invalid retry budget")


def plan(state: RepairState) -> RepairState:
    if state.phase is not Phase.INSPECT:
        raise ValueError("inspection required")
    return RepairState(Phase.PLAN, state.attempts, state.max_attempts)


def request_approval(state: RepairState) -> RepairState:
    if state.phase is not Phase.PLAN or state.attempts >= state.max_attempts:
        raise ValueError("cannot request approval")
    return RepairState(Phase.AWAIT_APPROVAL, state.attempts, state.max_attempts)


def record_external_verification(state: RepairState, *, approved: bool,
                                 evidence_id: str) -> RepairState:
    """Record independent approval and verification result, never execute it."""
    if state.phase is not Phase.AWAIT_APPROVAL:
        raise ValueError("not awaiting approval")
    if type(approved) is not bool or not approved:
        raise PermissionError("independent approval required")
    if not isinstance(evidence_id, str) or not evidence_id.strip() or len(evidence_id) > 128:
        raise ValueError("verified evidence identifier required")
    return RepairState(Phase.VERIFY, state.attempts + 1, state.max_attempts, evidence_id)


def decide(state: RepairState, *, baseline: Evaluation,
           candidate: Evaluation) -> tuple[RepairState, GateDecision]:
    if state.phase is not Phase.VERIFY or not state.evidence_id:
        raise ValueError("verified evidence required")
    outcome = compare(baseline, candidate)
    if outcome.accepted:
        return RepairState(Phase.ACCEPT, state.attempts, state.max_attempts, state.evidence_id), outcome
    return RepairState(Phase.REJECT, state.attempts, state.max_attempts, state.evidence_id), outcome


def retry(state: RepairState) -> RepairState:
    if state.phase is not Phase.REJECT or state.attempts >= state.max_attempts:
        raise ValueError("retry not allowed")
    return RepairState(Phase.INSPECT, state.attempts, state.max_attempts)
