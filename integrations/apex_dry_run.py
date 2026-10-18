"""Dry-run APEX to AAK contract adapter. Never performs provider or shell effects.

This adapter invokes the actual AAK ToolCall and ActionEnvelopeVerifier.verify
interfaces. It intentionally does NOT consume an AAK grant or execute a tool.
The v2 HMAC preflight remains a separate trusted approval-side dependency;
production code must not expose its issuance key to the agent.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aak.action_gateway import ActionBoundaryError, ActionEnvelope, ActionEnvelopeVerifier, ToolCall, ToolManifest


@dataclass(frozen=True)
class DryRunDecision:
    allowed_for_review: bool
    reason: str
    request_hash: str | None = None


def inspect_proposal(
    call_wire: dict[str, Any],
    envelope: ActionEnvelope,
    manifest: ToolManifest,
    verifier: ActionEnvelopeVerifier,
    *,
    now: int,
    expected_action: str = "run_tests",
) -> DryRunDecision:
    """Validate the real AAK signed envelope without consuming or executing it.

    A positive result is **not** execution authorization. A real effect requires
    resource-owned verify_and_consume(), audit and an isolated execution broker.
    """
    try:
        if type(now) is not int or now < 0:
            return DryRunDecision(False, "invalid_time")
        call = ToolCall.from_wire(call_wire)
        if call.action != expected_action:
            return DryRunDecision(False, "action_not_allowlisted", call.request_hash)
        if not isinstance(verifier, ActionEnvelopeVerifier):
            return DryRunDecision(False, "untrusted_verifier", call.request_hash)
        allowed, reason = verifier.verify(envelope, call, manifest, now=now)
        return DryRunDecision(bool(allowed), reason, call.request_hash)
    except (ActionBoundaryError, TypeError, ValueError, OverflowError, AttributeError):
        return DryRunDecision(False, "malformed_or_unverified_request")
