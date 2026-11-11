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


def record_external_verification(state: RepairState, *, approved: bool, evidence_id: str) -> RepairState:
    raise PermissionError('signed verifier receipt required; caller approval flags are not trusted')


def decide(state: RepairState, *, baseline: Evaluation,
           candidate: Evaluation) -> tuple[RepairState, GateDecision]:
    """Legacy entrypoint intentionally closed: a VERIFY state is forgeable."""
    raise PermissionError("use VerifiedReceiptLedger.verify_and_decide")



def retry(state: RepairState) -> RepairState:
    if state.phase is not Phase.REJECT or state.attempts >= state.max_attempts:
        raise ValueError("retry not allowed")
    return RepairState(Phase.INSPECT, state.attempts, state.max_attempts)
