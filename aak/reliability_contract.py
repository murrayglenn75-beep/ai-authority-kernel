"""Research-driven reliability contracts for execution and recovery.

This module never authorizes tools. AAK's independent resource verifier and
credential broker must still validate signed authority on every effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Any

from .agent_runtime import ToolRequest


class RecoveryState(str, Enum):
    PREPARED = "prepared"
    SUBMITTED = "submitted"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    AMBIGUOUS = "ambiguous"
    QUARANTINED = "quarantined"


class RecoveryDecision(str, Enum):
    RECORD_SUCCESS = "record_success"
    RECORD_REJECTION = "record_rejection"
    REQUIRE_OPERATOR = "require_operator"


@dataclass(frozen=True)
class ProviderEvidence:
    """Trusted results from independently authenticated provider reconciliation."""
    transaction_id: str
    provider_reference: str
    state: str
    authenticated: bool
    exact_request_match: bool


def reconcile(transaction_id: str, evidence: ProviderEvidence | None) -> RecoveryDecision:
    """Fail closed: missing, unauthenticated or mismatched evidence is inconclusive."""
    if not isinstance(transaction_id, str) or len(transaction_id) != 64:
        raise ValueError("invalid transaction identity")
    if evidence is None or not isinstance(evidence, ProviderEvidence):
        return RecoveryDecision.REQUIRE_OPERATOR
    if (not evidence.authenticated or not evidence.exact_request_match
            or evidence.transaction_id != transaction_id or not evidence.provider_reference):
        return RecoveryDecision.REQUIRE_OPERATOR
    if evidence.state == "committed":
        return RecoveryDecision.RECORD_SUCCESS
    if evidence.state == "definitively_rejected_before_effect":
        return RecoveryDecision.RECORD_REJECTION
    return RecoveryDecision.REQUIRE_OPERATOR


class VerifiedAAKExecutor:
    """Explicit adapter contract, deliberately incapable of minting approvals.

    grant_provider must obtain operator/AAK-issued signed authority. The actual
    boundary function must independently reverify it and broker the effect.
    Neither the model nor this adapter can provide a forged approval.
    """

    def __init__(
        self,
        grant_provider: Callable[[ToolRequest, str], object],
        verified_boundary: Callable[[object, ToolRequest, str], object],
    ):
        if not callable(grant_provider) or not callable(verified_boundary):
            raise ValueError("verified authorization boundary required")
        self.grant_provider = grant_provider
        self.verified_boundary = verified_boundary

    def __call__(self, call: ToolRequest, transaction_id: str) -> object:
        if not isinstance(call, ToolRequest) or not isinstance(transaction_id, str):
            raise ValueError("invalid effect request")
        # Any exception is handled by BoundedAgent as an ambiguous effect.
        grant = self.grant_provider(call, transaction_id)
        if grant is None:
            raise PermissionError("AAK authority not issued")
        return self.verified_boundary(grant, call, transaction_id)


def normalized_native_tool_call(
    name: object, arguments: object, *,
    approved_names: frozenset[str], max_argument_bytes: int = 16384,
) -> ToolRequest:
    """Strict normalization of *already parsed* provider-native tool arguments.

    This is not a provider SDK adapter. The operator decides which model API
    is in use; a failure never silently falls back to prompt JSON.
    """
    import json
    if not isinstance(name, str) or name not in approved_names:
        raise ValueError("unknown native tool")
    if not isinstance(arguments, dict) or any(not isinstance(k, str) for k in arguments):
        raise ValueError("native arguments must be a JSON object")
    try:
        payload = json.dumps(arguments, sort_keys=True, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("invalid native arguments") from None
    if len(payload) > max_argument_bytes:
        raise ValueError("native arguments too large")
    return ToolRequest(name, arguments)
