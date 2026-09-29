"""Separately deployable service cores for AAK's distributed profile."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .action_gateway import (
    ActionEnvelope, ActionEnvelopeIssuer, ActionEnvelopeVerifier, MCPToolAdapter,
    ToolCall, ToolManifest,
)
from .canonical import canonical_bytes, digest
from .crypto import CapabilitySigner, b64decode, b64encode
from .staging import EgressGuard, OIDCWorkloadVerifier, OPAClient, StagingBoundaryError


class DistributedBoundaryError(ValueError):
    pass


class ProviderRejectedError(RuntimeError):
    """Provider definitively rejected the operation before any external effect."""


class ProviderOutcomeAmbiguousError(RuntimeError):
    """The operation may have committed; automatic retry is unsafe."""


@dataclass(frozen=True)
class InputPolicy:
    schema_hash: str
    validate: Callable[[Mapping[str, Any]], bool]

    def __post_init__(self) -> None:
        if not isinstance(self.schema_hash, str) or not self.schema_hash or not callable(self.validate):
            raise DistributedBoundaryError("invalid_input_policy")


@dataclass(frozen=True)
class AuthenticatedGatewayContext:
    """Context supplied by trusted ingress, never decoded from model arguments."""

    human_principal: str
    purpose: str
    workload_token: str
    certificate_fingerprint: str


@dataclass(frozen=True)
class GatewayGrant:
    call: ToolCall
    manifest: ToolManifest
    envelope: ActionEnvelope

    def to_wire(self) -> dict[str, Any]:
        return {"call": self.call.to_wire(), "manifest": self.manifest.to_wire(),
                "envelope": self.envelope.to_wire()}

    @classmethod
    def from_wire(cls, value: object) -> "GatewayGrant":
        if not isinstance(value, Mapping) or set(value) != {"call", "manifest", "envelope"}:
            raise DistributedBoundaryError("malformed_gateway_grant")
        try:
            return cls(ToolCall.from_wire(value["call"]), ToolManifest.from_wire(value["manifest"]),
                       ActionEnvelope.from_wire(value["envelope"]))
        except Exception as exc:
            raise DistributedBoundaryError("malformed_gateway_grant") from exc


class GatewayService:
    """Authenticates, asks OPA, and issues exact short-lived authority."""

    def __init__(
        self, *, adapter: MCPToolAdapter, identity: OIDCWorkloadVerifier,
        policy: OPAClient, issuer: ActionEnvelopeIssuer,
        manifests: Mapping[str, ToolManifest], maximum_ttl: int = 30,
        id_factory: Callable[[], str],
        input_policies: Mapping[str, InputPolicy],
    ) -> None:
        if (maximum_ttl < 1 or maximum_ttl > 60 or not manifests
                or set(input_policies) != set(manifests)
                or any(not isinstance(policy, InputPolicy) for policy in input_policies.values())
                or any(input_policies[action].schema_hash != manifest.input_schema_hash
                       for action, manifest in manifests.items())):
            raise DistributedBoundaryError("invalid_gateway_configuration")
        self.adapter = adapter
        self.identity = identity
        self.policy = policy
        self.issuer = issuer
        self.manifests = dict(manifests)
        self.input_policies = dict(input_policies)
        self.maximum_ttl = maximum_ttl
        self.id_factory = id_factory

    def authorize_mcp(
        self, request: Mapping[str, Any], context: AuthenticatedGatewayContext, *, now: int,
    ) -> GatewayGrant:
        if (not isinstance(context, AuthenticatedGatewayContext)
                or not context.human_principal or not context.purpose):
            raise DistributedBoundaryError("invalid_authenticated_context")
        try:
            call = self.adapter.translate(request)
            identity = self.identity.verify(
                context.workload_token,
                certificate_fingerprint=context.certificate_fingerprint,
                now=now,
            )
        except Exception as exc:
            raise DistributedBoundaryError("workload_identity_denied") from exc
        manifest = self.manifests.get(call.action)
        if manifest is None:
            raise DistributedBoundaryError("manifest_not_registered")
        try:
            valid_input = self.input_policies[call.action].validate(call.parameters)
        except Exception as exc:
            raise DistributedBoundaryError("input_schema_denied") from exc
        if valid_input is not True:
            raise DistributedBoundaryError("input_schema_denied")
        policy_input = {
            "schema_version": 1,
            "human_principal": context.human_principal,
            "agent_identity": identity.subject,
            "purpose": context.purpose,
            "protocol": call.protocol,
            "action": call.action,
            "resource": call.resource,
            "audience": call.audience,
            "request_hash": call.request_hash,
            "manifest_hash": manifest.manifest_hash,
        }
        try:
            decision = self.policy.decide(policy_input)
        except StagingBoundaryError as exc:
            raise DistributedBoundaryError(str(exc)) from exc
        if set(decision.maximum_effect) != set(manifest.effect_keys):
            raise DistributedBoundaryError("policy_effect_contract_mismatch")
        identifiers = [self.id_factory() for _ in range(3)]
        if any(not isinstance(value, str) or not value for value in identifiers) or len(set(identifiers)) != 3:
            raise DistributedBoundaryError("identifier_generation_failure")
        envelope = self.issuer.issue(
            envelope_id=identifiers[0], transaction_id=identifiers[1],
            human_principal=context.human_principal, agent_identity=identity.subject,
            delegation_chain=(context.human_principal, identity.subject), purpose=context.purpose,
            call=call, evidence_hashes=(), policy_engine="opa",
            policy_decision_id=decision.decision_id, policy_version=decision.policy_version,
            approval_refs=decision.approval_refs, maximum_effect=decision.maximum_effect,
            manifest=manifest, issued_at=now, expires_at=now + self.maximum_ttl,
            nonce=identifiers[2],
        )
        return GatewayGrant(call, manifest, envelope)


@dataclass(frozen=True)
class AuditReceipt:
    anchor_id: str
    sequence: int
    previous_hash: str
    event_hash: str
    key_id: str
    signature: str

    def claim(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value

    def to_wire(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_wire(cls, value: object) -> "AuditReceipt":
        required = {"anchor_id", "sequence", "previous_hash", "event_hash", "key_id", "signature"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise DistributedBoundaryError("malformed_audit_receipt")
        try:
            receipt = cls(**dict(value))
        except TypeError as exc:
            raise DistributedBoundaryError("malformed_audit_receipt") from exc
        if (isinstance(receipt.sequence, bool) or not isinstance(receipt.sequence, int) or receipt.sequence < 1
                or any(not isinstance(item, str) or not item for item in (
                    receipt.anchor_id, receipt.previous_hash, receipt.event_hash,
                    receipt.key_id, receipt.signature))):
            raise DistributedBoundaryError("malformed_audit_receipt")
        return receipt


class AuditAnchor(Protocol):
    def append(self, event: Mapping[str, Any]) -> AuditReceipt: ...


class DurableAuditAnchor:
    """Independent SQLite-backed append-only anchor with signed receipts."""

    def __init__(
        self, path: str | Path, signer: CapabilitySigner, *, anchor_id: str,
        trusted_verifiers: Mapping[str, CapabilitySigner] | None = None,
        required_checkpoint: AuditReceipt | None = None,
    ) -> None:
        if not isinstance(anchor_id, str) or not anchor_id:
            raise DistributedBoundaryError("invalid_audit_anchor_id")
        self.signer = signer
        self.anchor_id = anchor_id
        self.trusted_verifiers = dict(trusted_verifiers or {signer.key_id: signer})
        if self.trusted_verifiers.get(signer.key_id) is None:
            raise DistributedBoundaryError("audit_signer_not_trusted")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        existing = self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='anchor_events'"
        ).fetchone()
        if existing:
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(anchor_events)")}
            if not {"anchor_id", "key_id"}.issubset(columns):
                self.db.close()
                self.db = None
                raise DistributedBoundaryError("legacy_audit_schema_requires_export")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS anchor_events ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, event BLOB NOT NULL, "
            "previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE, "
            "anchor_id TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL)"
        )
        wrong_anchor = self.db.execute(
            "SELECT 1 FROM anchor_events WHERE anchor_id<>? LIMIT 1", (self.anchor_id,),
        ).fetchone()
        if wrong_anchor:
            self.db.close()
            self.db = None
            raise DistributedBoundaryError("audit_anchor_domain_mismatch")
        if required_checkpoint is not None and not self.verify_checkpoint(required_checkpoint):
            self.db.close()
            self.db = None
            raise DistributedBoundaryError("audit_rollback_detected")

    def close(self) -> None:
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None

    def append(self, event: Mapping[str, Any]) -> AuditReceipt:
        if not isinstance(event, Mapping):
            raise DistributedBoundaryError("invalid_audit_event")
        try:
            encoded = canonical_bytes(dict(event))
        except Exception as exc:
            raise DistributedBoundaryError("invalid_audit_event") from exc
        if len(encoded) > 64 * 1024:
            raise DistributedBoundaryError("audit_event_too_large")
        with self.lock:
            if self.db is None:
                raise DistributedBoundaryError("audit_unavailable")
            try:
                self.db.execute("BEGIN IMMEDIATE")
                row = self.db.execute(
                    "SELECT sequence, event_hash FROM anchor_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = (int(row[0]) + 1) if row else 1
                previous = row[1] if row else "GENESIS"
                event_hash = digest({"previous_hash": previous, "event": dict(event)})
                claim = {"anchor_id": self.anchor_id, "sequence": sequence, "previous_hash": previous,
                         "event_hash": event_hash, "key_id": self.signer.key_id}
                signature = b64encode(self.signer.sign(canonical_bytes(claim)))
                self.db.execute(
                    "INSERT INTO anchor_events(sequence,event,previous_hash,event_hash,anchor_id,key_id,signature) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (sequence, encoded, previous, event_hash, self.anchor_id, self.signer.key_id, signature),
                )
                self.db.execute("COMMIT")
                return AuditReceipt(**claim, signature=signature)
            except Exception as exc:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise DistributedBoundaryError("audit_unavailable") from exc

    def verify_receipt(self, receipt: AuditReceipt) -> bool:
        if not isinstance(receipt, AuditReceipt) or receipt.anchor_id != self.anchor_id:
            return False
        verifier = self.trusted_verifiers.get(receipt.key_id)
        if verifier is None or verifier.key_id != receipt.key_id:
            return False
        try:
            return verifier.verify(canonical_bytes(receipt.claim()), b64decode(receipt.signature))
        except Exception:
            return False

    def verify_chain(self) -> bool:
        with self.lock:
            if self.db is None:
                return False
            previous = "GENESIS"
            for sequence, encoded, previous_hash, event_hash, anchor_id, key_id, signature in self.db.execute(
                "SELECT sequence,event,previous_hash,event_hash,anchor_id,key_id,signature "
                "FROM anchor_events ORDER BY sequence"
            ):
                try:
                    event = __import__("json").loads(encoded)
                except Exception:
                    return False
                expected = digest({"previous_hash": previous, "event": event})
                receipt = AuditReceipt(anchor_id, sequence, previous_hash, event_hash, key_id, signature)
                if sequence < 1 or previous_hash != previous or event_hash != expected or not self.verify_receipt(receipt):
                    return False
                previous = event_hash
            return True

    def checkpoint(self) -> AuditReceipt | None:
        """Return the signed head for storage outside the audit database."""
        with self.lock:
            if self.db is None:
                raise DistributedBoundaryError("audit_unavailable")
            row = self.db.execute(
                "SELECT sequence,previous_hash,event_hash,anchor_id,key_id,signature "
                "FROM anchor_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            return AuditReceipt(row[3], int(row[0]), row[1], row[2], row[4], row[5])

    def verify_checkpoint(self, checkpoint: AuditReceipt) -> bool:
        """Reject a valid-but-older database when given an off-host signed head."""
        if not self.verify_receipt(checkpoint):
            return False
        with self.lock:
            if self.db is None:
                return False
            row = self.db.execute(
                "SELECT previous_hash,event_hash,anchor_id,key_id,signature "
                "FROM anchor_events WHERE sequence=?",
                (checkpoint.sequence,),
            ).fetchone()
            return row == (
                checkpoint.previous_hash, checkpoint.event_hash, checkpoint.anchor_id,
                checkpoint.key_id, checkpoint.signature,
            )

    def rotate_signer(self, signer: CapabilitySigner) -> None:
        with self.lock:
            if self.trusted_verifiers.get(signer.key_id) is None:
                raise DistributedBoundaryError("audit_signer_not_trusted")
            self.signer = signer


class IsolatedEffectBroker(Protocol):
    """Secret-bearing process: credentials never cross this interface."""

    def execute(
        self, *, origin: str, audience: str, action_hash: str,
        call: ToolCall, grant: GatewayGrant, now: int,
        authorization_event: Mapping[str, Any], authorization_receipt: AuditReceipt,
    ) -> Mapping[str, Any]: ...


class ProviderOperation(Protocol):
    def __call__(
        self, *, origin: str, audience: str, call: ToolCall, operation_id: str,
    ) -> Mapping[str, Any]: ...


class BrokerReplayStore(Protocol):
    def consume(self, envelope_id: str, action_hash: str, *, now: int) -> bool: ...


class SQLiteBrokerReplayStore:
    """Credential-domain replay ledger; separate from resource-side state."""

    def __init__(self, path: str | Path) -> None:
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS broker_consumptions ("
            "envelope_id TEXT PRIMARY KEY, action_hash TEXT NOT NULL, consumed_at INTEGER NOT NULL)"
        )

    def close(self) -> None:
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None

    def consume(self, envelope_id: str, action_hash: str, *, now: int) -> bool:
        if (not isinstance(envelope_id, str) or not envelope_id
                or not isinstance(action_hash, str) or not action_hash
                or isinstance(now, bool) or not isinstance(now, int)):
            raise DistributedBoundaryError("invalid_broker_consumption")
        with self.lock:
            if self.db is None:
                raise DistributedBoundaryError("broker_replay_store_unavailable")
            try:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute(
                    "INSERT INTO broker_consumptions(envelope_id,action_hash,consumed_at) VALUES(?,?,?)",
                    (envelope_id, action_hash, now),
                )
                self.db.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                return False
            except Exception as exc:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise DistributedBoundaryError("broker_replay_store_unavailable") from exc


class VerifyingEffectBroker:
    """Credential-side verifier: independently checks authority before effect."""

    def __init__(
        self, *, verifier: ActionEnvelopeVerifier, provider: ProviderOperation,
        allowed_origins: tuple[str, ...], audit_anchor_id: str,
        audit_verifiers: Mapping[str, CapabilitySigner],
        replay_store: BrokerReplayStore,
        input_policies: Mapping[str, InputPolicy],
    ) -> None:
        self.verifier = verifier
        self.provider = provider
        self.egress = EgressGuard(allowed_origins)
        self.audit_anchor_id = audit_anchor_id
        self.audit_verifiers = dict(audit_verifiers)
        self.replay_store = replay_store
        if not input_policies or any(not isinstance(value, InputPolicy) for value in input_policies.values()):
            raise DistributedBoundaryError("invalid_broker_input_policy")
        self.input_policies = dict(input_policies)

    def _verify_authorization_proof(
        self, event: Mapping[str, Any], receipt: AuditReceipt, grant: GatewayGrant,
        action_hash: str,
    ) -> None:
        fields = {
            "type", "envelope_id", "transaction_id", "request_hash",
            "agent_identity", "policy_decision_id", "action_hash",
        }
        if not isinstance(event, Mapping) or set(event) != fields:
            raise DistributedBoundaryError("broker_invalid_authorization_event")
        expected = {
            "type": "action_authorized",
            "envelope_id": grant.envelope.envelope_id,
            "transaction_id": grant.envelope.transaction_id,
            "request_hash": grant.call.request_hash,
            "agent_identity": grant.envelope.agent_identity,
            "policy_decision_id": grant.envelope.policy_decision_id,
            "action_hash": action_hash,
        }
        if dict(event) != expected or not isinstance(receipt, AuditReceipt):
            raise DistributedBoundaryError("broker_authorization_proof_mismatch")
        if receipt.anchor_id != self.audit_anchor_id:
            raise DistributedBoundaryError("broker_wrong_audit_anchor")
        verifier = self.audit_verifiers.get(receipt.key_id)
        if verifier is None or verifier.key_id != receipt.key_id:
            raise DistributedBoundaryError("broker_untrusted_audit_key")
        expected_hash = digest({"previous_hash": receipt.previous_hash, "event": dict(event)})
        try:
            valid = (
                receipt.event_hash == expected_hash
                and verifier.verify(
                    canonical_bytes(receipt.claim()), b64decode(receipt.signature),
                )
            )
        except Exception:
            valid = False
        if not valid:
            raise DistributedBoundaryError("broker_invalid_authorization_proof")

    def execute(
        self, *, origin: str, audience: str, action_hash: str,
        call: ToolCall, grant: GatewayGrant, now: int,
        authorization_event: Mapping[str, Any], authorization_receipt: AuditReceipt,
    ) -> Mapping[str, Any]:
        if not isinstance(grant, GatewayGrant) or call != grant.call:
            raise DistributedBoundaryError("broker_grant_mismatch")
        verified, reason = self.verifier.verify(
            grant.envelope, grant.call, grant.manifest, now=now,
        )
        if not verified:
            raise DistributedBoundaryError(f"broker_{reason}")
        try:
            configured_origin = self.egress.authorize(origin)
            manifest_origin = EgressGuard(grant.manifest.allowed_origins).authorize(origin)
        except Exception as exc:
            raise DistributedBoundaryError("broker_egress_denied") from exc
        if (audience != call.audience or action_hash != digest(grant.envelope.claim())
                or configured_origin != manifest_origin):
            raise DistributedBoundaryError("broker_execution_binding_mismatch")
        input_policy = self.input_policies.get(call.action)
        if input_policy is None or input_policy.schema_hash != grant.manifest.input_schema_hash:
            raise DistributedBoundaryError("broker_input_policy_mismatch")
        try:
            valid_input = input_policy.validate(call.parameters)
        except Exception as exc:
            raise DistributedBoundaryError("broker_input_schema_denied") from exc
        if valid_input is not True:
            raise DistributedBoundaryError("broker_input_schema_denied")
        self._verify_authorization_proof(
            authorization_event, authorization_receipt, grant, action_hash,
        )
        if not self.replay_store.consume(grant.envelope.envelope_id, action_hash, now=now):
            raise DistributedBoundaryError("broker_replay_denied")
        try:
            result = self.provider(
                origin=origin, audience=audience, call=call,
                operation_id=grant.envelope.transaction_id,
            )
        except ProviderRejectedError:
            raise
        except Exception as exc:
            raise ProviderOutcomeAmbiguousError("provider_outcome_ambiguous") from exc
        if not isinstance(result, Mapping):
            raise ProviderOutcomeAmbiguousError("provider_outcome_ambiguous")
        return result


@dataclass(frozen=True)
class EffectOutcome:
    committed: bool
    quarantined: bool
    result_hash: str | None
    reason: str
    authorization_receipt: AuditReceipt
    completion_receipt: AuditReceipt | None

    def to_wire(self) -> dict[str, Any]:
        return {
            "committed": self.committed, "quarantined": self.quarantined,
            "result_hash": self.result_hash, "reason": self.reason,
            "authorization_receipt": self.authorization_receipt.to_wire(),
            "completion_receipt": self.completion_receipt.to_wire() if self.completion_receipt else None,
        }

    @classmethod
    def from_wire(cls, value: object) -> "EffectOutcome":
        fields = {"committed", "quarantined", "result_hash", "reason",
                  "authorization_receipt", "completion_receipt"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise DistributedBoundaryError("malformed_effect_outcome")
        if (not isinstance(value["committed"], bool) or not isinstance(value["quarantined"], bool)
                or not isinstance(value["reason"], str) or not value["reason"]
                or value["result_hash"] is not None and not isinstance(value["result_hash"], str)):
            raise DistributedBoundaryError("malformed_effect_outcome")
        authorization = AuditReceipt.from_wire(value["authorization_receipt"])
        completion = None if value["completion_receipt"] is None else AuditReceipt.from_wire(value["completion_receipt"])
        return cls(value["committed"], value["quarantined"], value["result_hash"],
                   value["reason"], authorization, completion)


class ResourceExecutionService:
    """Resource-side verification, audit-before-effect, and isolated execution."""

    def __init__(
        self, *, verifier: ActionEnvelopeVerifier, audit: AuditAnchor,
        broker: IsolatedEffectBroker, quarantine: Callable[[str, str], None],
    ) -> None:
        self.verifier = verifier
        self.audit = audit
        self.broker = broker
        self.quarantine = quarantine

    def _quarantine(self, agent: str, reason: str) -> bool:
        try:
            self.quarantine(agent, reason)
            return True
        except Exception:
            return False

    def execute(
        self, grant: GatewayGrant, *, destination: str, now: int,
        effect_limits: Mapping[str, int],
    ) -> EffectOutcome:
        if not isinstance(grant, GatewayGrant):
            raise DistributedBoundaryError("malformed_gateway_grant")
        accepted, reason = self.verifier.verify_and_consume(
            grant.envelope, grant.call, grant.manifest, now=now, effect_limits=effect_limits,
        )
        if not accepted:
            raise DistributedBoundaryError(reason)
        event = {
            "type": "action_authorized", "envelope_id": grant.envelope.envelope_id,
            "transaction_id": grant.envelope.transaction_id, "request_hash": grant.call.request_hash,
            "agent_identity": grant.envelope.agent_identity, "policy_decision_id": grant.envelope.policy_decision_id,
            "action_hash": digest(grant.envelope.claim()),
        }
        try:
            authorization_receipt = self.audit.append(event)
        except Exception as exc:
            contained = self._quarantine(grant.envelope.agent_identity, "authorization_audit_unavailable")
            reason = "authorization_audit_unavailable" if contained else "authorization_audit_and_quarantine_unavailable"
            raise DistributedBoundaryError(reason) from exc
        try:
            origin = EgressGuard(grant.manifest.allowed_origins).authorize(destination)
        except Exception as exc:
            try:
                self.audit.append({**event, "type": "action_blocked", "reason": "egress_denied"})
            except Exception:
                self._quarantine(grant.envelope.agent_identity, "blocked_action_audit_unavailable")
            raise DistributedBoundaryError("egress_denied") from exc
        action_hash = event["action_hash"]
        try:
            result = self.broker.execute(
                origin=origin, audience=grant.call.audience, action_hash=action_hash,
                call=grant.call, grant=grant, now=now,
                authorization_event=event, authorization_receipt=authorization_receipt,
            )
            if not isinstance(result, Mapping):
                raise DistributedBoundaryError("invalid_provider_result")
            result_hash = digest(dict(result))
        except ProviderRejectedError:
            try:
                completion = self.audit.append({
                    **event, "type": "action_failed", "reason": "provider_rejected",
                })
            except Exception:
                completion = None
                self._quarantine(grant.envelope.agent_identity, "failure_audit_unavailable")
            return EffectOutcome(
                False, completion is None, None, "provider_rejected",
                authorization_receipt, completion,
            )
        except DistributedBoundaryError as exc:
            contained = self._quarantine(grant.envelope.agent_identity, "broker_boundary_denied")
            try:
                completion = self.audit.append({
                    **event, "type": "action_blocked", "reason": "broker_boundary_denied",
                })
            except Exception:
                completion = None
                contained = self._quarantine(
                    grant.envelope.agent_identity, "broker_denial_audit_unavailable",
                ) and contained
            reason = "broker_denied" if contained else "broker_denied_containment_unavailable"
            return EffectOutcome(False, contained, None, reason, authorization_receipt, completion)
        except Exception as exc:
            contained = self._quarantine(
                grant.envelope.agent_identity, "provider_outcome_ambiguous",
            )
            try:
                completion = self.audit.append({
                    **event, "type": "action_ambiguous",
                    "reason": "provider_outcome_ambiguous",
                })
            except Exception:
                completion = None
                contained = self._quarantine(
                    grant.envelope.agent_identity, "ambiguous_audit_unavailable",
                ) and contained
            reason = (
                "provider_outcome_ambiguous" if contained
                else "provider_ambiguity_containment_unavailable"
            )
            return EffectOutcome(False, contained, None, reason, authorization_receipt, completion)
        try:
            completion = self.audit.append({**event, "type": "action_committed", "result_hash": result_hash})
            return EffectOutcome(True, False, result_hash, "committed", authorization_receipt, completion)
        except Exception:
            contained = self._quarantine(grant.envelope.agent_identity, "completion_audit_unavailable")
            reason = "committed_audit_unavailable" if contained else "committed_containment_unavailable"
            return EffectOutcome(True, contained, result_hash, reason, authorization_receipt, None)
