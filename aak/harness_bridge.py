"""Non-executing connection between harness task state and AAK's ToolCall.

The output is only a validated proposal. It MUST be passed to AAK's
independent issuer, resource verifier, broker and audit boundaries before any
effect. A checkpoint or lifecycle transition is never an authorization grant.
"""
from dataclasses import dataclass
from .action_gateway import ToolCall
from .harness_lifecycle import HarnessTask, Status


@dataclass(frozen=True)
class PreparedHarnessCall:
    task_id: str
    task_revision: int
    principal_id: str
    request_hash: str
    tool_call: ToolCall


def prepare_tool_call(*, task: HarnessTask, principal_id: str,
                      expected_revision: int, call: ToolCall) -> PreparedHarnessCall:
    """Validate a running task and canonical AAK request, without executing it.

    Important: the caller MUST re-read task state atomically before submitting
    the request for independent AAK authorization. This function deliberately
    does not accept any pre-approved flag, credential or provider callback.
    """
    if not isinstance(task, HarnessTask) or type(expected_revision) is not int:
        raise ValueError("invalid task")
    if not isinstance(principal_id, str) or principal_id != task.principal_id:
        raise PermissionError("principal mismatch")
    if expected_revision != task.revision:
        raise ValueError("stale revision")
    if task.status is not Status.RUNNING:
        raise PermissionError("task not running")
    if not isinstance(call, ToolCall):
        raise ValueError("invalid tool call")
    # Canonical validation is delegated to AAK rather than reimplemented.
    request_hash = call.request_hash
    return PreparedHarnessCall(task.task_id, task.revision,
                               task.principal_id, request_hash, call)


def prepare_from_store(*, store, task_id: str, principal_id: str,
                       expected_revision: int, call: ToolCall) -> PreparedHarnessCall:
    """Re-read durable task state before preparing a non-executable proposal.

    This narrows stale-snapshot mistakes but is NOT a transactional authorization
    gate. The independent AAK issuer/resource verifier must revalidate its own
    authority and exact action at the effect boundary. No external effects here.
    """
    from .harness_store import DurableHarnessStore

    if not isinstance(store, DurableHarnessStore):
        raise ValueError("trusted durable store required")
    if not isinstance(task_id, str) or not task_id:
        raise ValueError("invalid task_id")
    if type(expected_revision) is not int:
        raise ValueError("invalid revision")
    current = store.load(task_id, principal_id)
    return prepare_tool_call(task=current, principal_id=principal_id,
                             expected_revision=expected_revision, call=call)
