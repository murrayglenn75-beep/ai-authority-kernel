"""Provider-neutral action assurance contracts for AI tool and API calls.

The model-facing protocol is deliberately separated from authorization.  MCP,
REST, or future adapters create the same immutable ToolCall.  A trusted issuer
may then grant a short-lived ActionEnvelope.  The resource-side verifier checks
the exact call and signed ToolManifest before consuming the authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, replace
from typing import Any, Mapping
from urllib.parse import urlsplit

from .canonical import canonical_bytes, digest
from .crypto import CapabilitySigner, b64decode, b64encode
from .store import StateStore
from .boundary import KeyRegistry


MAX_TEXT = 2048
MAX_PARAMETERS_BYTES = 64 * 1024
MAX_DELEGATION_DEPTH = 16
PROTOCOLS = frozenset({"mcp", "rest", "a2a", "native"})
RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})


class ActionBoundaryError(ValueError):
    """A stable, fail-closed error raised at a protocol boundary."""


def _exact_wire_fields(value: object, cls: type, *, error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {item.name for item in fields(cls)}:
        raise ActionBoundaryError(error)
    return value


def _text(value: object, *, field_name: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ActionBoundaryError(f"invalid_{field_name}")
    return value


def _integer(value: object, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ActionBoundaryError(f"invalid_{field_name}")
    return value


def _string_tuple(value: object, *, field_name: str, maximum: int = 64) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) > maximum:
        raise ActionBoundaryError(f"invalid_{field_name}")
    if any(not isinstance(item, str) or not item or len(item) > MAX_TEXT for item in value):
        raise ActionBoundaryError(f"invalid_{field_name}")
    if len(set(value)) != len(value):
        raise ActionBoundaryError(f"duplicate_{field_name}")
    return value


def _verify_signature(signer: CapabilitySigner, claim: Mapping[str, Any], signature: str) -> bool:
    try:
        return signer.verify(canonical_bytes(dict(claim)), b64decode(signature))
    except (TypeError, ValueError):
        return False


def _trusted_verifier(source: CapabilitySigner | KeyRegistry, key_id: str, now: int) -> CapabilitySigner | None:
    if isinstance(source, KeyRegistry):
        status = source.status(key_id, now)
        return status.verifier if status is not None else None
    return source if key_id == source.key_id else None


@dataclass(frozen=True)
class ToolCall:
    """Canonical action request produced by every supported protocol adapter."""

    protocol: str
    call_id: str
    action: str
    resource: str
    audience: str
    parameters: dict[str, Any]

    def claim(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    def to_wire(self) -> dict[str, Any]:
        return self.claim()

    @classmethod
    def from_wire(cls, value: object) -> "ToolCall":
        wire = _exact_wire_fields(value, cls, error="malformed_tool_call")
        call = cls(**dict(wire))
        call.validate()
        return call

    def validate(self) -> None:
        if self.protocol not in PROTOCOLS:
            raise ActionBoundaryError("unsupported_protocol")
        for name in ("call_id", "action", "resource", "audience"):
            _text(getattr(self, name), field_name=name)
        if not isinstance(self.parameters, dict):
            raise ActionBoundaryError("invalid_parameters")
        try:
            encoded = canonical_bytes(self.parameters)
        except (TypeError, ValueError, OverflowError):
            raise ActionBoundaryError("invalid_parameters") from None
        if len(encoded) > MAX_PARAMETERS_BYTES:
            raise ActionBoundaryError("parameters_too_large")

    @property
    def request_hash(self) -> str:
        return digest(self.claim())


@dataclass(frozen=True)
class ToolManifest:
    """Signed, operator-controlled description of an executable tool."""

    schema_version: int
    manifest_id: str
    tool_version: str
    action: str
    resource: str
    audience: str
    protocols: tuple[str, ...]
    input_schema_hash: str
    effect_keys: tuple[str, ...]
    risk_level: str
    allowed_origins: tuple[str, ...]
    issued_at: int
    expires_at: int
    key_id: str
    signature: str = ""

    def claim(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value

    def to_wire(self) -> dict[str, Any]:
        value = asdict(self)
        for name in ("protocols", "effect_keys", "allowed_origins"):
            value[name] = list(value[name])
        return value

    @classmethod
    def from_wire(cls, value: object) -> "ToolManifest":
        wire = dict(_exact_wire_fields(value, cls, error="malformed_tool_manifest"))
        for name in ("protocols", "effect_keys", "allowed_origins"):
            if not isinstance(wire[name], list):
                raise ActionBoundaryError("malformed_tool_manifest")
            wire[name] = tuple(wire[name])
        manifest = cls(**wire)
        ToolManifestVerifier.validate_structure(manifest)
        return manifest

    @property
    def manifest_hash(self) -> str:
        return digest(self.claim())


class ToolManifestIssuer:
    def __init__(self, signer: CapabilitySigner) -> None:
        self.signer = signer

    def issue(
        self,
        *,
        manifest_id: str,
        tool_version: str,
        action: str,
        resource: str,
        audience: str,
        protocols: tuple[str, ...],
        input_schema: Mapping[str, Any],
        effect_keys: tuple[str, ...],
        risk_level: str,
        allowed_origins: tuple[str, ...] = (),
        issued_at: int,
        expires_at: int,
    ) -> ToolManifest:
        manifest = ToolManifest(
            schema_version=1,
            manifest_id=manifest_id,
            tool_version=tool_version,
            action=action,
            resource=resource,
            audience=audience,
            protocols=protocols,
            input_schema_hash=digest(dict(input_schema)),
            effect_keys=effect_keys,
            risk_level=risk_level,
            allowed_origins=allowed_origins,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=self.signer.key_id,
        )
        ToolManifestVerifier.validate_structure(manifest)
        return replace(manifest, signature=b64encode(self.signer.sign(canonical_bytes(manifest.claim()))))


class ToolManifestVerifier:
    def __init__(self, signer: CapabilitySigner | KeyRegistry) -> None:
        self.signer = signer

    @staticmethod
    def validate_structure(manifest: ToolManifest) -> None:
        if not isinstance(manifest, ToolManifest) or manifest.schema_version != 1:
            raise ActionBoundaryError("unsupported_tool_manifest_schema")
        for name in (
            "manifest_id", "tool_version", "action", "resource", "audience",
            "input_schema_hash", "key_id",
        ):
            _text(getattr(manifest, name), field_name=name)
        protocols = _string_tuple(manifest.protocols, field_name="protocols", maximum=8)
        if not protocols or any(protocol not in PROTOCOLS for protocol in protocols):
            raise ActionBoundaryError("unsupported_manifest_protocol")
        _string_tuple(manifest.effect_keys, field_name="effect_keys", maximum=64)
        origins = _string_tuple(manifest.allowed_origins, field_name="allowed_origins", maximum=64)
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            ):
                raise ActionBoundaryError("invalid_allowed_origin")
        if manifest.risk_level not in RISK_LEVELS:
            raise ActionBoundaryError("invalid_risk_level")
        issued_at = _integer(manifest.issued_at, field_name="issued_at")
        expires_at = _integer(manifest.expires_at, field_name="expires_at")
        if expires_at <= issued_at:
            raise ActionBoundaryError("invalid_manifest_validity")

    def verify(self, manifest: ToolManifest, *, now: int) -> tuple[bool, str]:
        try:
            self.validate_structure(manifest)
            _integer(now, field_name="current_time")
        except ActionBoundaryError as exc:
            return False, str(exc)
        verifier = _trusted_verifier(self.signer, manifest.key_id, now)
        if verifier is None:
            return False, "wrong_tool_manifest_key"
        if not _verify_signature(verifier, manifest.claim(), manifest.signature):
            return False, "invalid_tool_manifest_signature"
        if now < manifest.issued_at or now >= manifest.expires_at:
            return False, "tool_manifest_expired_or_not_yet_valid"
        return True, "tool_manifest_verified"


@dataclass(frozen=True)
class ActionEnvelope:
    """Short-lived, exact-action authority presented at the resource owner."""

    schema_version: int
    envelope_id: str
    transaction_id: str
    human_principal: str
    agent_identity: str
    delegation_chain: tuple[str, ...]
    purpose: str
    protocol: str
    action: str
    resource: str
    audience: str
    request_hash: str
    evidence_hashes: tuple[str, ...]
    policy_engine: str
    policy_decision_id: str
    policy_version: str
    approval_refs: tuple[str, ...]
    maximum_effect: dict[str, int]
    tool_manifest_hash: str
    issued_at: int
    expires_at: int
    nonce: str
    key_id: str
    signature: str = ""

    def claim(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value

    def to_wire(self) -> dict[str, Any]:
        value = asdict(self)
        for name in ("delegation_chain", "evidence_hashes", "approval_refs"):
            value[name] = list(value[name])
        return value

    @classmethod
    def from_wire(cls, value: object) -> "ActionEnvelope":
        wire = dict(_exact_wire_fields(value, cls, error="malformed_action_envelope"))
        for name in ("delegation_chain", "evidence_hashes", "approval_refs"):
            if not isinstance(wire[name], list):
                raise ActionBoundaryError("malformed_action_envelope")
            wire[name] = tuple(wire[name])
        envelope = cls(**wire)
        ActionEnvelopeVerifier.validate_structure(envelope)
        return envelope


class ActionEnvelopeIssuer:
    def __init__(self, signer: CapabilitySigner) -> None:
        self.signer = signer

    def issue(
        self,
        *,
        envelope_id: str,
        transaction_id: str,
        human_principal: str,
        agent_identity: str,
        delegation_chain: tuple[str, ...],
        purpose: str,
        call: ToolCall,
        evidence_hashes: tuple[str, ...],
        policy_engine: str,
        policy_decision_id: str,
        policy_version: str,
        approval_refs: tuple[str, ...],
        maximum_effect: dict[str, int],
        manifest: ToolManifest,
        issued_at: int,
        expires_at: int,
        nonce: str,
    ) -> ActionEnvelope:
        call.validate()
        envelope = ActionEnvelope(
            schema_version=1,
            envelope_id=envelope_id,
            transaction_id=transaction_id,
            human_principal=human_principal,
            agent_identity=agent_identity,
            delegation_chain=delegation_chain,
            purpose=purpose,
            protocol=call.protocol,
            action=call.action,
            resource=call.resource,
            audience=call.audience,
            request_hash=call.request_hash,
            evidence_hashes=evidence_hashes,
            policy_engine=policy_engine,
            policy_decision_id=policy_decision_id,
            policy_version=policy_version,
            approval_refs=approval_refs,
            maximum_effect=maximum_effect,
            tool_manifest_hash=manifest.manifest_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            key_id=self.signer.key_id,
        )
        ActionEnvelopeVerifier.validate_structure(envelope)
        return replace(envelope, signature=b64encode(self.signer.sign(canonical_bytes(envelope.claim()))))


class ActionEnvelopeVerifier:
    """Resource-side verifier. Successful verification consumes authority."""

    def __init__(
        self,
        signer: CapabilitySigner | KeyRegistry,
        manifest_verifier: ToolManifestVerifier,
        *,
        expected_audience: str,
        store: StateStore | None = None,
    ) -> None:
        self.signer = signer
        self.manifest_verifier = manifest_verifier
        self.expected_audience = _text(expected_audience, field_name="expected_audience")
        self.store = store or StateStore()

    @staticmethod
    def validate_structure(envelope: ActionEnvelope) -> None:
        if not isinstance(envelope, ActionEnvelope) or envelope.schema_version != 1:
            raise ActionBoundaryError("unsupported_action_envelope_schema")
        for name in (
            "envelope_id", "transaction_id", "human_principal", "agent_identity", "purpose",
            "action", "resource", "audience", "request_hash", "policy_engine",
            "policy_decision_id", "policy_version", "tool_manifest_hash", "nonce", "key_id",
        ):
            _text(getattr(envelope, name), field_name=name)
        if envelope.protocol not in PROTOCOLS:
            raise ActionBoundaryError("unsupported_protocol")
        chain = _string_tuple(envelope.delegation_chain, field_name="delegation_chain", maximum=MAX_DELEGATION_DEPTH)
        if not chain or chain[0] != envelope.human_principal:
            raise ActionBoundaryError("delegation_principal_mismatch")
        if chain[-1] != envelope.agent_identity:
            raise ActionBoundaryError("delegation_terminal_mismatch")
        _string_tuple(envelope.evidence_hashes, field_name="evidence_hashes", maximum=128)
        _string_tuple(envelope.approval_refs, field_name="approval_refs", maximum=64)
        if not isinstance(envelope.maximum_effect, dict) or not envelope.maximum_effect:
            raise ActionBoundaryError("invalid_maximum_effect")
        for key, value in envelope.maximum_effect.items():
            _text(key, field_name="effect_key", maximum=256)
            _integer(value, field_name="effect_value")
        issued_at = _integer(envelope.issued_at, field_name="issued_at")
        expires_at = _integer(envelope.expires_at, field_name="expires_at")
        if expires_at <= issued_at:
            raise ActionBoundaryError("invalid_envelope_validity")

    def verify(
        self,
        envelope: ActionEnvelope,
        call: ToolCall,
        manifest: ToolManifest,
        *,
        now: int,
    ) -> tuple[bool, str]:
        try:
            self.validate_structure(envelope)
            call.validate()
            _integer(now, field_name="current_time")
        except ActionBoundaryError as exc:
            return False, str(exc)
        manifest_ok, manifest_reason = self.manifest_verifier.verify(manifest, now=now)
        if not manifest_ok:
            return False, manifest_reason
        verifier = _trusted_verifier(self.signer, envelope.key_id, now)
        if verifier is None:
            return False, "wrong_action_envelope_key"
        if not _verify_signature(verifier, envelope.claim(), envelope.signature):
            return False, "invalid_action_envelope_signature"
        if now < envelope.issued_at or now >= envelope.expires_at:
            return False, "action_envelope_expired_or_not_yet_valid"
        if envelope.audience != self.expected_audience or call.audience != self.expected_audience:
            return False, "action_audience_mismatch"
        expected = {
            "protocol": call.protocol,
            "action": call.action,
            "resource": call.resource,
            "audience": call.audience,
            "request_hash": call.request_hash,
            "tool_manifest_hash": manifest.manifest_hash,
        }
        if any(getattr(envelope, name) != value for name, value in expected.items()):
            return False, "exact_action_mismatch"
        if (
            manifest.action != call.action
            or manifest.resource != call.resource
            or manifest.audience != call.audience
            or call.protocol not in manifest.protocols
        ):
            return False, "tool_manifest_contract_mismatch"
        if set(envelope.maximum_effect) != set(manifest.effect_keys):
            return False, "tool_effect_contract_mismatch"
        return True, "action_envelope_verified"

    def verify_and_consume(
        self,
        envelope: ActionEnvelope,
        call: ToolCall,
        manifest: ToolManifest,
        *,
        now: int,
        effect_limits: Mapping[str, int],
    ) -> tuple[bool, str]:
        verified, reason = self.verify(envelope, call, manifest, now=now)
        if not verified:
            return False, reason
        if not isinstance(effect_limits, Mapping):
            return False, "invalid_effect_limits"
        limits: dict[str, int] = {}
        costs: dict[str, int] = {}
        for key, value in effect_limits.items():
            if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return False, "invalid_effect_limits"
            limits[f"{envelope.human_principal}:{key}"] = value
        for key, value in envelope.maximum_effect.items():
            costs[f"{envelope.human_principal}:{key}"] = value
        try:
            return self.store.consume(
                envelope.nonce,
                costs,
                limits,
                now,
                idempotency_key=f"{envelope.human_principal}:{envelope.transaction_id}",
                request_hash=envelope.request_hash,
                strict_integer=True,
            )
        except Exception:
            return False, "authority_state_unavailable"


@dataclass(frozen=True)
class MCPToolBinding:
    tool_name: str
    action: str
    resource: str
    audience: str


class MCPToolAdapter:
    """Strictly maps model-facing MCP names onto operator-owned contracts."""

    def __init__(self, bindings: tuple[MCPToolBinding, ...]) -> None:
        self.bindings: dict[str, MCPToolBinding] = {}
        for binding in bindings:
            _text(binding.tool_name, field_name="tool_name")
            for name in ("action", "resource", "audience"):
                _text(getattr(binding, name), field_name=name)
            if binding.tool_name in self.bindings:
                raise ActionBoundaryError("duplicate_mcp_tool_binding")
            self.bindings[binding.tool_name] = binding

    def translate(self, request: Mapping[str, Any]) -> ToolCall:
        if not isinstance(request, Mapping) or set(request) != {"jsonrpc", "id", "method", "params"}:
            raise ActionBoundaryError("malformed_mcp_request")
        if request["jsonrpc"] != "2.0" or request["method"] != "tools/call":
            raise ActionBoundaryError("unsupported_mcp_method")
        call_id = request["id"]
        if isinstance(call_id, bool) or not isinstance(call_id, (str, int)):
            raise ActionBoundaryError("invalid_mcp_call_id")
        params = request["params"]
        if not isinstance(params, Mapping) or set(params) != {"name", "arguments"}:
            raise ActionBoundaryError("malformed_mcp_tool_call")
        tool_name = params["name"]
        if not isinstance(tool_name, str):
            raise ActionBoundaryError("invalid_mcp_tool_name")
        binding = self.bindings.get(tool_name)
        if binding is None:
            raise ActionBoundaryError("unregistered_mcp_tool")
        arguments = params["arguments"]
        if not isinstance(arguments, dict):
            raise ActionBoundaryError("invalid_parameters")
        call = ToolCall("mcp", str(call_id), binding.action, binding.resource, binding.audience, arguments)
        call.validate()
        return call


@dataclass(frozen=True)
class RESTToolBinding:
    method: str
    route: str
    action: str
    resource: str
    audience: str


class RESTToolAdapter:
    """Maps fixed HTTP method/route pairs to canonical action requests."""

    def __init__(self, bindings: tuple[RESTToolBinding, ...]) -> None:
        self.bindings: dict[tuple[str, str], RESTToolBinding] = {}
        for binding in bindings:
            method = _text(binding.method, field_name="method", maximum=16).upper()
            route = _text(binding.route, field_name="route")
            if not route.startswith("/") or "?" in route or "#" in route:
                raise ActionBoundaryError("invalid_route")
            key = (method, route)
            if key in self.bindings:
                raise ActionBoundaryError("duplicate_rest_binding")
            self.bindings[key] = replace(binding, method=method)

    def translate(self, *, method: str, route: str, request_id: str, body: dict[str, Any]) -> ToolCall:
        key = (_text(method, field_name="method", maximum=16).upper(), _text(route, field_name="route"))
        binding = self.bindings.get(key)
        if binding is None:
            raise ActionBoundaryError("unregistered_rest_operation")
        call = ToolCall(
            "rest", _text(request_id, field_name="request_id"), binding.action,
            binding.resource, binding.audience, body,
        )
        call.validate()
        return call
