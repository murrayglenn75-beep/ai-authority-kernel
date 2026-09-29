"""Production-boundary adapters for the distributed AAK staging profile.

These adapters intentionally contain no provider credentials.  They validate
responses from separately deployed policy and identity systems and constrain
the executor's destination before a credential broker may be consulted.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes, digest
from .crypto import b64decode
from .store import StateStore


class StagingBoundaryError(ValueError):
    """Stable, fail-closed distributed-boundary failure."""


def _strict_json(encoded: bytes) -> object:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise StagingBoundaryError("duplicate_identity_claim")
            result[key] = value
        return result
    try:
        return json.loads(encoded, object_pairs_hook=pairs)
    except StagingBoundaryError:
        raise
    except Exception as exc:
        raise StagingBoundaryError("malformed_identity_token") from exc


class JSONTransport(Protocol):
    def __call__(self, url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> object: ...


@dataclass(frozen=True)
class OPADecision:
    decision_id: str
    policy_version: str
    maximum_effect: dict[str, int]
    approval_refs: tuple[str, ...]


class OPAClient:
    """Strict adapter for one separately administered OPA decision endpoint."""

    def __init__(self, endpoint: str, transport: JSONTransport, *, timeout: float = 2.0) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise StagingBoundaryError("invalid_opa_endpoint")
        if parsed.query or parsed.fragment or timeout <= 0 or timeout > 10:
            raise StagingBoundaryError("invalid_opa_endpoint")
        self.endpoint = endpoint
        self.transport = transport
        self.timeout = timeout

    def decide(self, policy_input: Mapping[str, Any]) -> OPADecision:
        if not isinstance(policy_input, Mapping):
            raise StagingBoundaryError("invalid_policy_input")
        try:
            body = canonical_bytes({"input": dict(policy_input)})
            response = self.transport(
                self.endpoint, body, {"content-type": "application/json"}, self.timeout,
            )
        except Exception as exc:
            raise StagingBoundaryError("policy_service_unavailable") from exc
        if not isinstance(response, Mapping) or set(response) != {"result"}:
            raise StagingBoundaryError("malformed_policy_response")
        result = response["result"]
        required = {"allow", "decision_id", "policy_version", "maximum_effect", "approval_refs"}
        if not isinstance(result, Mapping) or set(result) != required:
            raise StagingBoundaryError("malformed_policy_response")
        if result["allow"] is not True:
            raise StagingBoundaryError("external_policy_denied")
        decision_id = result["decision_id"]
        policy_version = result["policy_version"]
        maximum_effect = result["maximum_effect"]
        approval_refs = result["approval_refs"]
        if not isinstance(decision_id, str) or not decision_id or len(decision_id) > 256:
            raise StagingBoundaryError("malformed_policy_response")
        if not isinstance(policy_version, str) or not policy_version or len(policy_version) > 256:
            raise StagingBoundaryError("malformed_policy_response")
        if not isinstance(maximum_effect, dict) or not maximum_effect:
            raise StagingBoundaryError("malformed_policy_response")
        if any(not isinstance(k, str) or not k or isinstance(v, bool) or not isinstance(v, int) or v < 0
               for k, v in maximum_effect.items()):
            raise StagingBoundaryError("malformed_policy_response")
        if (not isinstance(approval_refs, list) or len(approval_refs) > 64
                or any(not isinstance(v, str) or not v or len(v) > 2048 for v in approval_refs)
                or len(set(approval_refs)) != len(approval_refs)):
            raise StagingBoundaryError("malformed_policy_response")
        return OPADecision(decision_id, policy_version, maximum_effect, tuple(approval_refs))


@dataclass(frozen=True)
class WorkloadClaims:
    subject: str
    issuer: str
    audience: str
    token_id: str
    certificate_fingerprint: str


class OIDCWorkloadVerifier:
    """Pinned EdDSA OIDC verifier with audience, certificate and replay binding."""

    def __init__(
        self, *, issuer: str, audience: str, public_keys: Mapping[str, bytes],
        store: StateStore | None = None, maximum_lifetime: int = 300,
    ) -> None:
        if not issuer.startswith("https://") or not audience or not public_keys:
            raise StagingBoundaryError("invalid_oidc_configuration")
        if maximum_lifetime < 1 or maximum_lifetime > 3600:
            raise StagingBoundaryError("invalid_oidc_configuration")
        try:
            self.keys = {kid: Ed25519PublicKey.from_public_bytes(value) for kid, value in public_keys.items()
                         if isinstance(kid, str) and kid}
        except (TypeError, ValueError) as exc:
            raise StagingBoundaryError("invalid_oidc_configuration") from exc
        if len(self.keys) != len(public_keys):
            raise StagingBoundaryError("invalid_oidc_configuration")
        self.issuer = issuer
        self.audience = audience
        self.store = store or StateStore()
        self.maximum_lifetime = maximum_lifetime
        self.namespace = digest({"issuer": issuer, "audience": audience, "keys": sorted(self.keys)})

    def verify(self, token: str, *, certificate_fingerprint: str, now: int | None = None) -> WorkloadClaims:
        current = int(time.time()) if now is None else now
        if isinstance(current, bool) or not isinstance(current, int) or current < 0:
            raise StagingBoundaryError("invalid_identity_time")
        if not isinstance(token, str) or len(token) > 16_384 or token.count(".") != 2:
            raise StagingBoundaryError("malformed_identity_token")
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
            header = _strict_json(b64decode(encoded_header))
            payload = _strict_json(b64decode(encoded_payload))
            signature = b64decode(encoded_signature)
        except StagingBoundaryError:
            raise
        except Exception as exc:
            raise StagingBoundaryError("malformed_identity_token") from exc
        if not isinstance(header, dict) or set(header) != {"alg", "kid", "typ"}:
            raise StagingBoundaryError("malformed_identity_token")
        if header["alg"] != "EdDSA" or header["typ"] != "JWT" or header["kid"] not in self.keys:
            raise StagingBoundaryError("untrusted_identity_key")
        try:
            self.keys[header["kid"]].verify(
                signature, f"{encoded_header}.{encoded_payload}".encode("ascii"),
            )
        except Exception as exc:
            raise StagingBoundaryError("invalid_identity_signature") from exc
        required = {"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cnf"}
        if not isinstance(payload, dict) or set(payload) != required:
            raise StagingBoundaryError("malformed_identity_claims")
        if payload["iss"] != self.issuer or payload["aud"] != self.audience:
            raise StagingBoundaryError("identity_binding_mismatch")
        if (not isinstance(payload["sub"], str) or not payload["sub"].startswith("spiffe://")
                or not isinstance(payload["jti"], str) or not payload["jti"]
                or any(isinstance(payload[k], bool) or not isinstance(payload[k], int) for k in ("iat", "nbf", "exp"))
                or payload["iat"] > current or payload["nbf"] > current or payload["exp"] <= current
                or payload["exp"] - payload["iat"] > self.maximum_lifetime):
            raise StagingBoundaryError("identity_expired_or_invalid")
        if (not isinstance(payload["cnf"], dict) or set(payload["cnf"]) != {"x5t#S256"}
                or payload["cnf"]["x5t#S256"] != certificate_fingerprint
                or not certificate_fingerprint):
            raise StagingBoundaryError("identity_certificate_mismatch")
        accepted, reason = self.store.accept_assurance_once(
            kind="identity", identifier=f"{self.namespace}:{payload['jti']}",
            expires_at=payload["exp"], now=current,
        )
        if not accepted:
            raise StagingBoundaryError("identity_replay" if reason == "assurance_replay" else "identity_state_unavailable")
        return WorkloadClaims(payload["sub"], payload["iss"], payload["aud"], payload["jti"], certificate_fingerprint)


class EgressGuard:
    """Exact HTTPS-origin enforcement for isolated executors."""

    def __init__(self, allowed_origins: tuple[str, ...]) -> None:
        if not allowed_origins:
            raise StagingBoundaryError("empty_egress_policy")
        self.allowed = frozenset(self._origin(value) for value in allowed_origins)

    @staticmethod
    def _origin(value: str) -> str:
        if not isinstance(value, str):
            raise StagingBoundaryError("invalid_egress_destination")
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise StagingBoundaryError("invalid_egress_destination")
        port = parsed.port
        authority = parsed.hostname.lower() + (f":{port}" if port and port != 443 else "")
        return f"https://{authority}"

    def authorize(self, destination: str) -> str:
        origin = self._origin(destination)
        if origin not in self.allowed:
            raise StagingBoundaryError("egress_denied")
        return origin


class CredentialBroker(Protocol):
    """Implemented by an isolated secret-bearing executor, never by the model."""

    def credential_for(self, *, audience: str, action_hash: str) -> str: ...


class AuthorizedExecutor:
    """Orders egress authorization before narrowly scoped credential retrieval."""

    def __init__(self, guard: EgressGuard, broker: CredentialBroker) -> None:
        self.guard = guard
        self.broker = broker

    def prepare(self, *, destination: str, audience: str, action_claim: Mapping[str, Any]) -> tuple[str, str]:
        origin = self.guard.authorize(destination)
        action_hash = digest(dict(action_claim))
        credential = self.broker.credential_for(audience=audience, action_hash=action_hash)
        if not isinstance(credential, str) or not credential:
            raise StagingBoundaryError("credential_broker_denied")
        return origin, credential
