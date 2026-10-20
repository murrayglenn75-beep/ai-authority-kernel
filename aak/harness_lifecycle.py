"""Pure, deny-by-default lifecycle tracker for external agent harnesses.

This module NEVER authorizes or executes tools. AAK's existing resource
verifier and effect broker remain the exclusive execution boundary.
"""
from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping


class Status(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


_ALLOWED: Mapping[Status, frozenset[Status]] = {
    Status.CREATED: frozenset({Status.RUNNING, Status.CANCELLED}),
    Status.RUNNING: frozenset({Status.WAITING_APPROVAL, Status.COMPLETED, Status.CANCELLED, Status.FAILED}),
    Status.WAITING_APPROVAL: frozenset({Status.RUNNING, Status.CANCELLED, Status.FAILED}),
    Status.COMPLETED: frozenset(),
    Status.CANCELLED: frozenset(),
    Status.FAILED: frozenset(),
}


@dataclass(frozen=True)
class HarnessTask:
    task_id: str
    harness_id: str
    principal_id: str
    status: Status = Status.CREATED
    revision: int = 0
    steps: int = 0
    checkpoint: str | None = None

    def __post_init__(self) -> None:
        for name in ("task_id", "harness_id", "principal_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in value):
                raise ValueError(f"invalid {name}")
        if not isinstance(self.status, Status) or type(self.revision) is not int or self.revision < 0 or type(self.steps) is not int or self.steps < 0:
            raise ValueError("invalid task state")


def advance(task: HarnessTask, *, expected_revision: int, next_status: Status,
            principal_id: str, step: bool = False, checkpoint: str | None = None,
            max_steps: int = 64) -> HarnessTask:
    """Return a new state after a validated CAS-style transition.

    Persist and compare revisions atomically in the caller's storage. This pure
    function is not a durable store and cannot provide distributed locking.
    """
    if not isinstance(next_status, Status):
        raise ValueError("unknown status")
    if principal_id != task.principal_id:
        raise PermissionError("principal mismatch")
    if type(expected_revision) is not int or expected_revision != task.revision:
        raise ValueError("stale revision")
    if next_status not in _ALLOWED[task.status]:
        raise ValueError("illegal state transition")
    if type(step) is not bool or type(max_steps) is not int or max_steps < 1:
        raise ValueError("invalid step budget")
    if step and next_status != Status.RUNNING:
        raise ValueError("steps can only occur while running")
    if task.steps + int(step) > max_steps:
        raise ValueError("step budget exceeded")
    if checkpoint is not None and (not isinstance(checkpoint, str) or not checkpoint or len(checkpoint) > 256):
        raise ValueError("invalid checkpoint")
    if checkpoint is not None and next_status not in (Status.RUNNING, Status.WAITING_APPROVAL):
        raise ValueError("checkpoint cannot be modified after stopping")
    return replace(task, status=next_status, revision=task.revision + 1,
                   steps=task.steps + int(step),
                   checkpoint=checkpoint if checkpoint is not None else task.checkpoint)
