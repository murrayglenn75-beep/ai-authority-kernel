"""AAK v0.9.0 multi-domain authorization and downstream enforcement.

The classes are transport-independent reference components. In production each
trust domain belongs in a separate workload, identity, network policy, and
administrative boundary.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from .canonical import canonical_bytes, digest
from .crypto import CapabilitySigner, b64decode, b64encode
from .kernel import Decision, Proposal
from .store import StateStore
from .tools import ToolContract
from .boundary import EffectReceiptIssuer, SenderProof, SenderProofVerifier
from .assurance import ExternalPolicyDecision, ExternalPolicyVerifier, WorkloadIdentityAssertion, WorkloadIdentityVerifier


def _signature(signer: CapabilitySigner, value: dict[str, Any]) -> str:
    return b64encode(signer.sign(canonical_bytes(value)))


def _verify(signer: CapabilitySigner, value: dict[str, Any], signature: str) -> bool:
    try:
        return signer.verify(canonical_bytes(value), b64decode(signature))
    except (TypeError, ValueError):
        return False


def _proposal_hash(proposal: Any) -> str | None:
    if not isinstance(proposal, Proposal):
        return None
    try:
        return digest(asdict(proposal))
    except (TypeError, ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class AuthorityAttestation:
    key_id: str
    signature: str


@dataclass(frozen=True)
class AuthorityBundle:
    claim: dict[str, Any]
    attestations: tuple[AuthorityAttestation, ...]


@dataclass(frozen=True)
class DispatchCapability:
    claim: dict[str, Any]
    gateway_key_id: str
    gateway_signature: str


@dataclass(frozen=True)
class AnchorReceipt:
    sequence: int
    previous_hash: str
    event_hash: str
    signature: str


class IndependentAuthority:
    """One policy signer, operated independently from the other signers."""

    def __init__(
        self, signer: CapabilitySigner, evaluator: Callable[[Proposal], bool],
        tenant_resolver: Callable[[Proposal], str] | None = None,
    ) -> None:
        self.signer = signer
        self.evaluator = evaluator
        self.tenant_resolver = tenant_resolver or (lambda proposal: proposal.principal_id)

    def attest(self, proposal: Proposal, claim: dict[str, Any]) -> AuthorityAttestation | None:
        allowed_fields = {
            "v", "proposal_hash", "policy_hash", "system_version", "audience",
            "issued_at", "expires_at", "nonce", "maximum_effect", "tenant_id",
            "resource_state_version",
        }
        required_fields = allowed_fields - {"resource_state_version"}
        try:
            expected_effect = {key: float(value) for key, value in proposal.maximum_effect.items()}
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        proposal_hash = _proposal_hash(proposal)
        try:
            tenant_id = self.tenant_resolver(proposal)
            evaluated = self.evaluator(proposal)
        except Exception:
            return None
        safe_claim = (
            proposal_hash is not None
            and isinstance(claim, dict)
            and required_fields.issubset(claim)
            and set(claim).issubset(allowed_fields)
            and claim.get("v") == 2
            and claim.get("proposal_hash") == proposal_hash
            and claim.get("tenant_id") == tenant_id
            and claim.get("maximum_effect") == expected_effect
            and isinstance(claim.get("issued_at"), int)
            and not isinstance(claim.get("issued_at"), bool)
            and isinstance(claim.get("expires_at"), int)
            and claim["expires_at"] > claim["issued_at"]
            and isinstance(claim.get("nonce"), str)
            and 16 <= len(claim["nonce"]) <= 128
            and evaluated is True
        )
        if not safe_claim:
            return None
        return AuthorityAttestation(self.signer.key_id, _signature(self.signer, claim))


class ThresholdVerifier:
    def __init__(self, verifiers: Iterable[CapabilitySigner], threshold: int) -> None:
        self.verifiers = {item.key_id: item for item in verifiers}
        if threshold < 1 or threshold > len(self.verifiers):
            raise ValueError("invalid threshold")
        self.threshold = threshold

    def verify(self, bundle: AuthorityBundle) -> bool:
        if (not isinstance(bundle, AuthorityBundle) or not isinstance(bundle.claim, dict)
                or not isinstance(bundle.attestations, tuple)):
            return False
        valid: set[str] = set()
        for attestation in bundle.attestations:
            if not isinstance(attestation, AuthorityAttestation):
                return False
            verifier = self.verifiers.get(attestation.key_id)
            if verifier and attestation.key_id not in valid and _verify(verifier, bundle.claim, attestation.signature):
                valid.add(attestation.key_id)
        return len(valid) >= self.threshold


class ExternalAuditAnchor:
    """Independent append-only checkpoint service with signed receipts."""

    def __init__(self, signer: CapabilitySigner) -> None:
        self.signer = signer
        self._events: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def append(self, event: dict[str, Any]) -> AnchorReceipt:
        with self._lock:
            previous = self._events[-1]["event_hash"] if self._events else "GENESIS"
            event_hash = digest({"previous_hash": previous, "event": event})
            record = {"sequence": len(self._events) + 1, "previous_hash": previous, "event_hash": event_hash}
            receipt = AnchorReceipt(**record, signature=_signature(self.signer, record))
            self._events.append({**record, "event": event, "signature": receipt.signature})
            return receipt

    def verify_receipt(self, receipt: AnchorReceipt) -> bool:
        record = {"sequence": receipt.sequence, "previous_hash": receipt.previous_hash, "event_hash": receipt.event_hash}
        return _verify(self.signer, record, receipt.signature)

    def contains(self, receipt: AnchorReceipt) -> bool:
        with self._lock:
            if not self.verify_receipt(receipt) or receipt.sequence < 1 or receipt.sequence > len(self._events):
                return False
            row = self._events[receipt.sequence - 1]
            return row["event_hash"] == receipt.event_hash and row["previous_hash"] == receipt.previous_hash

    def head(self) -> AnchorReceipt | None:
        with self._lock:
            if not self._events:
                return None
            row = self._events[-1]
            return AnchorReceipt(row["sequence"], row["previous_hash"], row["event_hash"], row["signature"])

    def receipts_since(self, sequence: int) -> tuple[AnchorReceipt, ...]:
        with self._lock:
            return tuple(
                AnchorReceipt(row["sequence"], row["previous_hash"], row["event_hash"], row["signature"])
                for row in self._events[sequence:]
            )

    def snapshot_since(self, sequence: int) -> tuple[tuple[AnchorReceipt, ...], AnchorReceipt | None]:
        """Return continuation receipts and head from one atomic audit view."""
        with self._lock:
            receipts = tuple(
                AnchorReceipt(row["sequence"], row["previous_hash"], row["event_hash"], row["signature"])
                for row in self._events[sequence:]
            )
            if not self._events:
                return receipts, None
            row = self._events[-1]
            return receipts, AnchorReceipt(row["sequence"], row["previous_hash"], row["event_hash"], row["signature"])

    def snapshot_records(self) -> tuple[tuple[dict[str, Any], ...], AnchorReceipt | None]:
        """Capture historical records and their head in one append-locked view."""
        with self._lock:
            rows = tuple(dict(row) for row in self._events)
            if not rows:
                return rows, None
            last = rows[-1]
            return rows, AnchorReceipt(
                last["sequence"], last["previous_hash"],
                last["event_hash"], last["signature"],
            )

    def records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._events)

    def verify_chain(self) -> bool:
        with self._lock:
            previous = "GENESIS"
            for index, row in enumerate(self._events, 1):
                if row["sequence"] != index or row["previous_hash"] != previous:
                    return False
                if digest({"previous_hash": previous, "event": row["event"]}) != row["event_hash"]:
                    return False
                record = {key: row[key] for key in ("sequence", "previous_hash", "event_hash")}
                if not _verify(self.signer, record, row["signature"]):
                    return False
                previous = row["event_hash"]
            return True


class EnforcementGateway:
    """Verifies quorum and issues a dispatch token; holds no effect credential."""

    def __init__(
        self, signer: CapabilitySigner, authorities: ThresholdVerifier, audience: str,
        *, expected_policy_hash: str, expected_system_version: str,
        allow_test_time_override: bool = False,
    ) -> None:
        self.signer = signer
        self.authorities = authorities
        self.audience = audience
        self.expected_policy_hash = expected_policy_hash
        self.expected_system_version = expected_system_version
        self.allow_test_time_override = allow_test_time_override

    def _now(self, override: int | None) -> int:
        if override is not None:
            if not self.allow_test_time_override:
                raise ValueError("caller-supplied time is disabled")
            if isinstance(override, bool) or not isinstance(override, int) or override < 0:
                raise ValueError("invalid trusted time")
            return override
        return int(time.time())

    def dispatch(self, proposal: Proposal, bundle: AuthorityBundle, *, now: int | None = None) -> DispatchCapability | None:
        timestamp = self._now(now)
        claim = bundle.claim
        if not isinstance(claim, dict):
            return None
        if not self.authorities.verify(bundle):
            return None
        proposal_hash = _proposal_hash(proposal)
        if proposal_hash is None or claim.get("proposal_hash") != proposal_hash:
            return None
        if claim.get("policy_hash") != self.expected_policy_hash or claim.get("system_version") != self.expected_system_version:
            return None
        issued_at, expires_at = claim.get("issued_at"), claim.get("expires_at")
        if (isinstance(issued_at, bool) or not isinstance(issued_at, int)
                or isinstance(expires_at, bool) or not isinstance(expires_at, int)):
            return None
        if claim.get("audience") != self.audience or timestamp < issued_at or timestamp >= expires_at:
            return None
        dispatch_claim = {
            "v": 2,
            "bundle_hash": digest({"claim": claim, "attestations": [asdict(item) for item in bundle.attestations]}),
            "proposal_hash": claim["proposal_hash"],
            "nonce": claim["nonce"],
            "audience": self.audience,
            "expires_at": claim["expires_at"],
        }
        return DispatchCapability(dispatch_claim, self.signer.key_id, _signature(self.signer, dispatch_claim))


class DownstreamEnforcer:
    """Resource-side reference monitor that independently verifies everything."""

    def __init__(
        self,
        *,
        gateway_verifier: CapabilitySigner,
        authorities: ThresholdVerifier,
        anchor: ExternalAuditAnchor,
        anchor_verifier: CapabilitySigner,
        expected_workload_identity: str,
        audience: str,
        tools: tuple[ToolContract, ...],
        principal_limits: dict[str, float],
        global_limits: dict[str, float],
        expected_policy_hash: str,
        expected_system_version: str,
        store: StateStore | None = None,
        allow_test_time_override: bool = False,
        receipt_issuer: EffectReceiptIssuer | None = None,
        sender_proof_verifier: SenderProofVerifier | None = None,
        tenant_resolver: Callable[[Proposal], str] | None = None,
        external_policy_verifier: ExternalPolicyVerifier | None = None,
        workload_identity_verifier: WorkloadIdentityVerifier | None = None,
    ) -> None:
        self.gateway_verifier = gateway_verifier
        self.authorities = authorities
        self.anchor = anchor
        self.anchor_verifier = anchor_verifier
        self.expected_workload_identity = expected_workload_identity
        self.audience = audience
        self.tools = {tool.action: tool for tool in tools}
        self.principal_limits = dict(principal_limits)
        self.global_limits = dict(global_limits)
        self.expected_policy_hash = expected_policy_hash
        self.expected_system_version = expected_system_version
        self.allow_test_time_override = allow_test_time_override
        self.receipt_issuer = receipt_issuer
        self.sender_proof_verifier = sender_proof_verifier
        self.tenant_resolver = tenant_resolver or (lambda proposal: proposal.principal_id)
        self.external_policy_verifier = external_policy_verifier
        self.workload_identity_verifier = workload_identity_verifier
        self._sender_verifier_lock = threading.RLock()
        self.store = store or StateStore()
        self._last_anchor: AnchorReceipt | None = None
        self._anchor_initialized = False
        self._anchor_lock = threading.RLock()

    def bind_sender_proof_verifier(self, verifier: SenderProofVerifier) -> None:
        """Bind the operator-configured transport verifier exactly once."""
        if not isinstance(verifier, SenderProofVerifier):
            raise TypeError("invalid_sender_proof_verifier")
        with self._sender_verifier_lock:
            if self.sender_proof_verifier is not None and self.sender_proof_verifier is not verifier:
                raise RuntimeError("sender_proof_verifier_already_bound")
            self.sender_proof_verifier = verifier

    def _now(self, override: int | None) -> int:
        if override is not None:
            if not self.allow_test_time_override:
                raise ValueError("caller-supplied time is disabled")
            if isinstance(override, bool) or not isinstance(override, int) or override < 0:
                raise ValueError("invalid trusted time")
            return override
        return int(time.time())

    def _anchor_is_current(self) -> bool:
        with self._anchor_lock:
            if self._last_anchor is None:
                rows, head = self.anchor.snapshot_records()
                if head is None:
                    if rows:
                        return False
                    self._anchor_initialized = True
                    return True
                if not self._verify_anchor_receipt(head) or not self._verify_anchor_chain_locally(head, rows):
                    return False
                self._last_anchor = head
                self._anchor_initialized = True
                return True
            previous = self._last_anchor
            if not self._verify_anchor_receipt(previous):
                return False
            receipts, head = self.anchor.snapshot_since(previous.sequence)
            if head is None or head.sequence < previous.sequence:
                return False
            for receipt in receipts:
                if receipt.sequence != previous.sequence + 1 or receipt.previous_hash != previous.event_hash:
                    return False
                if not self._verify_anchor_receipt(receipt):
                    return False
                previous = receipt
            return previous == head and self._verify_anchor_receipt(head)

    def verify_full_audit_integrity(self) -> bool:
        """Full historical verification for startup and independent monitoring."""
        with self._anchor_lock:
            rows, head = self.anchor.snapshot_records()
            return (not rows) if head is None else (
                self._verify_anchor_receipt(head) and self._verify_anchor_chain_locally(head, rows)
            )

    def _verify_anchor_receipt(self, receipt: AnchorReceipt) -> bool:
        record = {"sequence": receipt.sequence, "previous_hash": receipt.previous_hash, "event_hash": receipt.event_hash}
        return _verify(self.anchor_verifier, record, receipt.signature)

    def _verify_anchor_chain_locally(
        self, head: AnchorReceipt, rows: tuple[dict[str, Any], ...],
    ) -> bool:
        if len(rows) != head.sequence:
            return False
        previous = "GENESIS"
        for sequence, row in enumerate(rows, 1):
            expected_hash = digest({"previous_hash": previous, "event": row.get("event")})
            receipt = AnchorReceipt(
                row.get("sequence"), row.get("previous_hash"),
                row.get("event_hash"), row.get("signature"),
            )
            if sequence != receipt.sequence or receipt.previous_hash != previous or receipt.event_hash != expected_hash:
                return False
            if not self._verify_anchor_receipt(receipt):
                return False
            previous = receipt.event_hash
        return previous == head.event_hash

    def _record_anchor(self, receipt: AnchorReceipt) -> None:
        with self._anchor_lock:
            if self._last_anchor is None or receipt.sequence > self._last_anchor.sequence:
                self._last_anchor = receipt
                self._anchor_initialized = True

    def execute(
        self,
        proposal: Proposal,
        bundle: AuthorityBundle,
        dispatch: DispatchCapability,
        *,
        workload_identity: str,
        policy_decision: ExternalPolicyDecision | None = None,
        identity_assertion: WorkloadIdentityAssertion | None = None,
        channel_binding: str | None = None,
        now: int | None = None,
    ) -> Decision:
        timestamp = self._now(now)
        if not isinstance(bundle, AuthorityBundle):
            return Decision(False, "malformed_authority_bundle")
        if not isinstance(dispatch, DispatchCapability):
            return Decision(False, "malformed_dispatch_capability")
        if not isinstance(workload_identity, str) or not workload_identity:
            return Decision(False, "wrong_workload_identity")
        if workload_identity != self.expected_workload_identity:
            return Decision(False, "wrong_workload_identity")
        try:
            if self.store.is_quarantined(workload_identity):
                return Decision(False, "workload_quarantined")
        except Exception:
            return Decision(False, "state_store_unavailable")
        try:
            if not self._anchor_is_current():
                return Decision(False, "audit_anchor_rollback_or_tamper")
        except Exception:
            return Decision(False, "audit_anchor_unavailable")
        if not self.authorities.verify(bundle):
            return Decision(False, "insufficient_authority_quorum")
        claim = bundle.claim
        if not isinstance(claim, dict):
            return Decision(False, "malformed_authority_claim")
        proposal_hash = _proposal_hash(proposal)
        if proposal_hash is None:
            return Decision(False, "malformed_proposal")
        if claim.get("proposal_hash") != proposal_hash or claim.get("audience") != self.audience:
            return Decision(False, "authority_contract_mismatch")
        if claim.get("policy_hash") != self.expected_policy_hash or claim.get("system_version") != self.expected_system_version:
            return Decision(False, "policy_or_system_mismatch")
        issued_at, expires_at = claim.get("issued_at"), claim.get("expires_at")
        if (isinstance(issued_at, bool) or not isinstance(issued_at, int)
                or isinstance(expires_at, bool) or not isinstance(expires_at, int)
                or timestamp < issued_at or timestamp >= expires_at):
            return Decision(False, "expired_or_invalid_time")
        bundle_hash = digest({"claim": claim, "attestations": [asdict(item) for item in bundle.attestations]})
        expected_dispatch = {
            "v": 2, "bundle_hash": bundle_hash, "proposal_hash": proposal_hash,
            "nonce": claim.get("nonce"), "audience": self.audience, "expires_at": claim.get("expires_at"),
        }
        if dispatch.gateway_key_id != self.gateway_verifier.key_id or dispatch.claim != expected_dispatch:
            return Decision(False, "dispatch_contract_mismatch")
        if not _verify(self.gateway_verifier, dispatch.claim, dispatch.gateway_signature):
            return Decision(False, "invalid_gateway_signature")
        tool = self.tools.get(proposal.action)
        if tool is None:
            return Decision(False, "unregistered_action")
        try:
            effect = tool.assessed_effect(proposal.resource, proposal.parameters)
        except (TypeError, ValueError):
            return Decision(False, "tool_contract_rejected")
        if any(isinstance(value, bool) or not float(value).is_integer() for value in proposal.maximum_effect.values()):
            return Decision(False, "non_integer_effect")
        if any(not float(value).is_integer() for value in effect.values()):
            return Decision(False, "non_integer_effect")
        declared = {key: int(value) for key, value in proposal.maximum_effect.items()}
        effect = {key: int(value) for key, value in effect.items()}
        if effect != declared or claim.get("maximum_effect") != declared:
            return Decision(False, "effect_mismatch")
        costs: dict[str, float] = {}
        limits: dict[str, float] = {}
        for key, value in effect.items():
            costs[f"principal:{proposal.principal_id}:{key}"] = value
            limits[f"principal:{proposal.principal_id}:{key}"] = self.principal_limits.get(key, 0.0)
            costs[f"global:{key}"] = value
            limits[f"global:{key}"] = self.global_limits.get(key, 0.0)
        tenant_id = claim.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id:
            return Decision(False, "missing_tenant_binding")
        try:
            expected_tenant = self.tenant_resolver(proposal)
        except Exception:
            return Decision(False, "tenant_resolution_failed")
        if not isinstance(expected_tenant, str) or not expected_tenant or tenant_id != expected_tenant:
            return Decision(False, "downstream_tenant_mismatch")
        idempotency_key = digest({
            "tenant": tenant_id, "action": proposal.action, "resource": proposal.resource,
            "transaction_id": proposal.transaction_id,
        })
        resource_key = digest({"tenant": tenant_id, "resource": proposal.resource})
        expected_version = claim.get("resource_state_version")
        if expected_version is not None and (isinstance(expected_version, bool) or not isinstance(expected_version, int) or expected_version < 0):
            return Decision(False, "invalid_resource_state_version")
        # Consume one-time external assurance only after every stateless contract
        # check succeeds, preventing malformed requests from burning valid proof.
        if self.workload_identity_verifier is not None:
            if identity_assertion is None:
                return Decision(False, "workload_identity_assertion_required")
            try:
                verified, reason = self.workload_identity_verifier.verify(
                    identity_assertion, now=timestamp, expected_channel_binding=channel_binding,
                )
            except Exception:
                return Decision(False, "workload_identity_service_unavailable")
            if not verified:
                return Decision(False, reason)
            if identity_assertion.spiffe_id != workload_identity:
                return Decision(False, "workload_identity_assertion_mismatch")
        if self.external_policy_verifier is not None:
            if policy_decision is None:
                return Decision(False, "external_policy_decision_required")
            try:
                verified, reason = self.external_policy_verifier.verify(policy_decision, proposal, now=timestamp)
            except Exception:
                return Decision(False, "external_policy_service_unavailable")
            if not verified:
                return Decision(False, reason)
        try:
            consumed, reason = self.store.consume(
                str(claim.get("nonce", "")), costs, limits, timestamp,
                idempotency_key=idempotency_key, request_hash=proposal_hash,
                resource_key=resource_key if expected_version is not None else None,
                expected_resource_version=expected_version,
                strict_integer=True,
            )
        except Exception:
            return Decision(False, "state_store_unavailable")
        if not consumed:
            return Decision(False, reason)
        try:
            prepared = self.anchor.append({"type": "prepared", "proposal_hash": proposal_hash, "nonce": claim["nonce"]})
        except Exception:
            self.store.quarantine(workload_identity, "audit_anchor_unavailable")
            return Decision(False, "audit_anchor_unavailable_workload_quarantined")
        prepared_event = {"type": "prepared", "proposal_hash": proposal_hash, "nonce": claim["nonce"]}
        if not self._verify_anchor_receipt(prepared) or prepared.event_hash != digest({"previous_hash": prepared.previous_hash, "event": prepared_event}):
            return Decision(False, "audit_prepare_failed")
        self._record_anchor(prepared)
        journaled, journal_reason = self.store.begin_effect(idempotency_key, proposal_hash, timestamp)
        if not journaled:
            self.store.quarantine(workload_identity, "effect_journal_conflict")
            return Decision(False, f"{journal_reason}_workload_quarantined")
        submitted, _ = self.store.transition_effect(
            idempotency_key, proposal_hash, from_state="prepared", to_state="submitted", now=timestamp,
        )
        if not submitted:
            self.store.quarantine(workload_identity, "effect_journal_transition_failure")
            return Decision(False, "effect_journal_transition_failure_workload_quarantined")
        try:
            result = tool.handler(proposal.resource, dict(proposal.parameters))
        except Exception:
            self.store.transition_effect(
                idempotency_key, proposal_hash, from_state="submitted", to_state="ambiguous", now=timestamp,
            )
            self.store.quarantine(workload_identity, "downstream_operation_failure")
            return Decision(False, "operation_failed_and_workload_quarantined")
        transitioned, _ = self.store.transition_effect(
            idempotency_key, proposal_hash, from_state="submitted", to_state="succeeded",
            now=timestamp, result_hash=digest(result),
        )
        if not transitioned:
            self.store.quarantine(workload_identity, "effect_journal_completion_failure")
            return Decision(True, "executed_but_journal_incomplete_workload_quarantined")
        completed_event = {"type": "completed", "proposal_hash": proposal_hash, "result_hash": digest(result)}
        try:
            completed = self.anchor.append(completed_event)
        except Exception:
            self.store.quarantine(workload_identity, "completion_anchor_failure")
            return Decision(True, "executed_but_anchor_incomplete_workload_quarantined")
        if self._verify_anchor_receipt(completed) and completed.event_hash == digest({"previous_hash": completed.previous_hash, "event": completed_event}):
            self._record_anchor(completed)
            receipt = None
            if self.receipt_issuer is not None:
                previous_version = expected_version if expected_version is not None else 0
                resulting_version = self.store.resource_version(resource_key) if expected_version is not None else previous_version + 1
                receipt = self.receipt_issuer.issue(
                    transaction_id=proposal.transaction_id,
                    capability_hash=digest(dispatch.claim), request_hash=proposal_hash,
                    exact_effect=effect, previous_state_version=previous_version,
                    resulting_state_version=resulting_version,
                    downstream_identity=self.expected_workload_identity, completed_at=timestamp,
                )
            return Decision(True, "executed", receipt=receipt)
        self.store.quarantine(workload_identity, "completion_anchor_failure")
        return Decision(True, "executed_but_anchor_incomplete_workload_quarantined")

    def execute_secure(
        self,
        proposal: Proposal,
        bundle: AuthorityBundle,
        dispatch: DispatchCapability,
        *,
        request_body: bytes,
        sender_proof: SenderProof,
        proof_verifier: SenderProofVerifier | None = None,
        workload_identity: str,
        policy_decision: ExternalPolicyDecision | None = None,
        identity_assertion: WorkloadIdentityAssertion | None = None,
        now: int | None = None,
    ) -> Decision:
        """Mandatory transport-bound entrypoint for cross-service requests."""
        with self._sender_verifier_lock:
            configured_verifier = self.sender_proof_verifier
        if configured_verifier is None:
            return Decision(False, "sender_proof_verifier_not_configured")
        if proof_verifier is not None and proof_verifier is not configured_verifier:
            return Decision(False, "sender_proof_verifier_substitution")
        verified, reason = configured_verifier.verify(sender_proof, request_body, now=now)
        if not verified:
            return Decision(False, reason)
        if sender_proof.subject != workload_identity:
            return Decision(False, "sender_workload_mismatch")
        expected_body = canonical_bytes({
            "proposal": asdict(proposal),
            "bundle": {
                "claim": bundle.claim,
                "attestations": [asdict(item) for item in bundle.attestations],
            },
            "dispatch": asdict(dispatch),
        })
        if request_body != expected_body:
            return Decision(False, "transport_payload_mismatch")
        return self.execute(
            proposal, bundle, dispatch, workload_identity=workload_identity,
            policy_decision=policy_decision, identity_assertion=identity_assertion,
            channel_binding=sender_proof.body_hash, now=now,
        )


def make_authority_claim(
    proposal: Proposal,
    *,
    policy_hash: str,
    system_version: str,
    audience: str,
    issued_at: int,
    expires_at: int,
    nonce: str | None = None,
    tenant_id: str | None = None,
    resource_state_version: int | None = None,
) -> dict[str, Any]:
    if expires_at <= issued_at:
        raise ValueError("invalid validity window")
    exact_effect: dict[str, int | float] = {}
    for key, value in proposal.maximum_effect.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid maximum effect")
        exact_effect[key] = int(value) if float(value).is_integer() else float(value)
    claim = {
        "v": 2,
        "proposal_hash": digest(asdict(proposal)),
        "policy_hash": policy_hash,
        "system_version": system_version,
        "audience": audience,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce or secrets.token_urlsafe(24),
        "maximum_effect": exact_effect,
        "tenant_id": tenant_id or proposal.principal_id,
    }
    if resource_state_version is not None:
        claim["resource_state_version"] = resource_state_version
    return claim
