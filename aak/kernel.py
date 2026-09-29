import json
import math
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .canonical import canonical_bytes, digest
from .crypto import CapabilitySigner, HMACSigner, b64decode, b64encode
from .policy import Policy
from .store import StateStore
from .tools import ToolContract


@dataclass(frozen=True)
class Proposal:
    transaction_id: str
    principal_id: str
    agent_instance: str
    purpose: str
    action: str
    resource: str
    parameters: dict[str, Any]
    maximum_effect: dict[str, float]
    evidence: tuple[str, ...]
    approvals: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    capability: str | None = None
    receipt: Any | None = None


class AuthorityKernel:
    def __init__(
        self,
        *,
        signing_key: bytes | None = None,
        signer: CapabilitySigner | None = None,
        policy: Policy,
        system_version: str,
        budget_limits: dict[str, float],
        tools: tuple[ToolContract, ...] = (),
        store: StateStore | None = None,
        token_ttl_seconds: int = 60,
        evidence_verifier=None,
        allow_test_time_override: bool = False,
    ) -> None:
        if (signing_key is None) == (signer is None):
            raise ValueError("provide exactly one of signing_key or signer")
        self.signer = signer or HMACSigner(signing_key)
        self.policy = policy
        self.system_version = system_version
        self.budget_limits = budget_limits
        self.tools = {tool.action: tool for tool in tools}
        if len(self.tools) != len(tools):
            raise ValueError("duplicate tool action")
        self.store = store or StateStore()
        self.token_ttl_seconds = token_ttl_seconds
        self.evidence_verifier = evidence_verifier or (lambda _evidence_id: False)
        self.allow_test_time_override = allow_test_time_override
        self.audit_degraded = False

    def _timestamp(self, override: int | None) -> int:
        if override is not None:
            if not self.allow_test_time_override:
                raise ValueError("caller-supplied time is disabled")
            if isinstance(override, bool) or not isinstance(override, int) or override < 0:
                raise TypeError("time override must be a non-negative integer")
            return override
        return int(time.time())

    def _sign(self, payload: dict[str, Any]) -> str:
        body = b64encode(canonical_bytes(payload))
        return body + "." + b64encode(self.signer.sign(body.encode("ascii")))

    @staticmethod
    def _proposal_error(proposal: Proposal) -> str | None:
        if not isinstance(proposal, Proposal):
            return "malformed_proposal"
        text_fields = (
            proposal.transaction_id, proposal.principal_id, proposal.agent_instance,
            proposal.purpose, proposal.action, proposal.resource,
        )
        if any(not isinstance(value, str) or not value for value in text_fields):
            return "malformed_proposal"
        if not isinstance(proposal.parameters, dict) or not isinstance(proposal.maximum_effect, dict):
            return "malformed_proposal"
        if any(
            not isinstance(key, str)
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value < 0
            for key, value in proposal.maximum_effect.items()
        ):
            return "malformed_proposal"
        if not isinstance(proposal.evidence, tuple) or not all(isinstance(value, str) and value for value in proposal.evidence):
            return "malformed_proposal"
        if not isinstance(proposal.approvals, tuple) or not all(isinstance(value, str) and value for value in proposal.approvals):
            return "malformed_proposal"
        try:
            canonical_bytes(asdict(proposal))
        except (TypeError, ValueError, OverflowError):
            return "malformed_proposal"
        return None

    def _decode(self, token: str) -> dict[str, Any] | None:
        if not isinstance(token, str):
            return None
        try:
            body_text, signature_text = token.split(".", 1)
            body = body_text.encode()
            raw_body = b64decode(body_text)
            supplied = b64decode(signature_text)
            if not self.signer.verify(body, supplied):
                return None
            value = json.loads(raw_body)
            return value if isinstance(value, dict) else None
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    def authorize(self, proposal: Proposal, *, now: int | None = None) -> Decision:
        timestamp = self._timestamp(now)
        if self.audit_degraded:
            return Decision(False, "audit_degraded")
        proposal_error = self._proposal_error(proposal)
        if proposal_error:
            return Decision(False, proposal_error)
        try:
            if self.store.is_quarantined(proposal.agent_instance):
                return Decision(False, "agent_quarantined")
        except Exception:
            return Decision(False, "state_store_unavailable")
        if not proposal.evidence:
            return Decision(False, "missing_evidence")
        if not all(self.evidence_verifier(item) for item in proposal.evidence):
            return Decision(False, "unverified_evidence")
        tool = self.tools.get(proposal.action)
        if tool is None:
            return Decision(False, "unregistered_action")
        try:
            derived_effect = tool.assessed_effect(proposal.resource, proposal.parameters)
        except ValueError as exc:
            return Decision(False, str(exc))
        if derived_effect != {key: float(value) for key, value in proposal.maximum_effect.items()}:
            return Decision(False, "declared_effect_mismatch")
        permitted, reason, _ = self.policy.evaluate(proposal)
        if not permitted:
            return Decision(False, reason)
        payload = {
            "v": 1,
            "key_id": self.signer.key_id,
            "proposal_hash": digest(asdict(proposal)),
            "transaction_id": proposal.transaction_id,
            "principal_id": proposal.principal_id,
            "agent_instance": proposal.agent_instance,
            "action": proposal.action,
            "resource": proposal.resource,
            "parameters_hash": digest(proposal.parameters),
            "maximum_effect": proposal.maximum_effect,
            "policy_version": self.policy.version,
            "system_version": self.system_version,
            "issued_at": timestamp,
            "expires_at": timestamp + self.token_ttl_seconds,
            "nonce": secrets.token_urlsafe(24),
        }
        return Decision(True, "authorized", self._sign(payload))

    def execute(self, proposal: Proposal, token: str, *, now: int | None = None) -> Decision:
        timestamp = self._timestamp(now)
        if self.audit_degraded:
            return Decision(False, "audit_degraded")
        proposal_error = self._proposal_error(proposal)
        if proposal_error:
            return Decision(False, proposal_error)
        payload = self._decode(token)
        if payload is None:
            return Decision(False, "invalid_signature")
        if payload.get("key_id") != self.signer.key_id:
            return Decision(False, "wrong_signing_key")
        expected = {
            "proposal_hash": digest(asdict(proposal)),
            "principal_id": proposal.principal_id,
            "agent_instance": proposal.agent_instance,
            "action": proposal.action,
            "resource": proposal.resource,
            "parameters_hash": digest(proposal.parameters),
            "policy_version": self.policy.version,
            "system_version": self.system_version,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            return Decision(False, "contract_mismatch")
        if timestamp < payload.get("issued_at", timestamp + 1) or timestamp >= payload.get("expires_at", 0):
            return Decision(False, "expired_or_invalid_time")
        try:
            if self.store.is_quarantined(proposal.agent_instance):
                return Decision(False, "agent_quarantined")
        except Exception:
            return Decision(False, "state_store_unavailable")
        if self.store.is_nonce_revoked(payload.get("nonce", "")):
            return Decision(False, "revoked")
        tool = self.tools.get(proposal.action)
        if tool is None:
            return Decision(False, "unregistered_action")
        try:
            derived_effect = tool.assessed_effect(proposal.resource, proposal.parameters)
        except ValueError as exc:
            return Decision(False, str(exc))
        if derived_effect != {key: float(value) for key, value in payload.get("maximum_effect", {}).items()}:
            return Decision(False, "derived_effect_changed")
        costs = {f"{proposal.principal_id}:{key}": float(value) for key, value in proposal.maximum_effect.items()}
        limits = {f"{proposal.principal_id}:{key}": float(value) for key, value in self.budget_limits.items()}
        try:
            consumed, reason = self.store.consume(payload["nonce"], costs, limits, timestamp)
        except Exception:
            return Decision(False, "state_store_unavailable")
        if not consumed:
            return Decision(False, reason)
        started_event = {"type": "execution_started", "proposal_hash": expected["proposal_hash"], "nonce": payload["nonce"]}
        started_json = canonical_bytes(started_event).decode()
        try:
            self.store.append_audit(started_json)
        except Exception:
            self.store.quarantine(proposal.agent_instance, "audit_unavailable")
            return Decision(False, "audit_unavailable_and_agent_quarantined")
        try:
            result = tool.handler(proposal.resource, dict(proposal.parameters))
        except Exception as exc:
            self.store.quarantine(proposal.agent_instance, "operation_failure")
            failed = {"type": "execution_failed", "proposal_hash": expected["proposal_hash"], "error_type": type(exc).__name__}
            try:
                self.store.append_audit(canonical_bytes(failed).decode())
            except Exception:
                self.audit_degraded = True
                return Decision(False, "operation_failed_audit_unavailable_agent_quarantined")
            return Decision(False, "operation_failed_and_agent_quarantined")
        completed = {"type": "execution_completed", "proposal_hash": expected["proposal_hash"], "result_hash": digest(result)}
        try:
            self.store.append_audit(canonical_bytes(completed).decode())
        except Exception:
            # The external effect has already happened. Report success so callers
            # do not retry, but contain the agent until an operator reconciles it.
            self.store.quarantine(proposal.agent_instance, "completion_audit_unavailable")
            return Decision(True, "executed_but_audit_incomplete_agent_quarantined")
        return Decision(True, "executed")

    def revoke(self, token: str, reason: str = "operator_revoked") -> bool:
        payload = self._decode(token)
        if payload is None or payload.get("key_id") != self.signer.key_id:
            return False
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return False
        self.store.revoke_nonce(nonce, reason)
        event = {"type": "capability_revoked", "nonce": nonce, "reason": reason}
        try:
            self.store.append_audit(canonical_bytes(event).decode())
        except Exception:
            # Revocation remains effective, but no further authorization is safe
            # until the missing audit event is reconciled by an operator.
            self.audit_degraded = True
        return True
