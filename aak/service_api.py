"""Strict JSON API adapters for deploying AAK service cores independently."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Protocol

from .action_gateway import ToolCall
from .distributed import (
    AuditReceipt, DistributedBoundaryError, DurableAuditAnchor, EffectOutcome,
    GatewayGrant, IsolatedEffectBroker, ProviderOutcomeAmbiguousError,
    ProviderRejectedError, ResourceExecutionService,
)


MAX_SERVICE_BODY_BYTES = 256 * 1024


class JSONServiceCall(Protocol):
    def __call__(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _exact(value: object, fields: set[str], reason: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DistributedBoundaryError(reason)
    return value


class RemoteAuditAnchor:
    """Resource-side client for a separately deployed audit anchor."""

    def __init__(self, call: JSONServiceCall) -> None:
        self.call = call

    def append(self, event: Mapping[str, Any]) -> AuditReceipt:
        try:
            response = self.call("/v1/audit/events", {"event": dict(event)})
            wire = _exact(response, {"receipt"}, "malformed_audit_service_response")
            return AuditReceipt.from_wire(wire["receipt"])
        except DistributedBoundaryError:
            raise
        except Exception as exc:
            raise DistributedBoundaryError("audit_service_unavailable") from exc


class AuditServiceEndpoint:
    """Transport-neutral audit endpoint with an authenticated peer allowlist."""

    def __init__(self, anchor: DurableAuditAnchor, *, allowed_peers: frozenset[str]) -> None:
        if not allowed_peers:
            raise DistributedBoundaryError("empty_audit_peer_policy")
        self.anchor = anchor
        self.allowed_peers = allowed_peers

    def handle(self, path: str, body: object, *, peer_identity: str) -> dict[str, Any]:
        if peer_identity not in self.allowed_peers:
            raise DistributedBoundaryError("audit_peer_denied")
        if path != "/v1/audit/events":
            raise DistributedBoundaryError("audit_route_denied")
        wire = _exact(body, {"event"}, "malformed_audit_request")
        event = wire["event"]
        if not isinstance(event, Mapping):
            raise DistributedBoundaryError("malformed_audit_request")
        return {"receipt": self.anchor.append(event).to_wire()}


class RemoteEffectBroker:
    """Resource-side client; credentials remain inside the broker service."""

    def __init__(self, call: JSONServiceCall) -> None:
        self.call = call

    def execute(
        self, *, origin: str, audience: str, action_hash: str,
        call: ToolCall, grant: GatewayGrant, now: int,
        authorization_event: Mapping[str, Any], authorization_receipt: AuditReceipt,
    ) -> Mapping[str, Any]:
        payload = {
            "origin": origin, "audience": audience, "action_hash": action_hash,
            "call": call.to_wire(), "grant": grant.to_wire(),
            "authorization_event": dict(authorization_event),
            "authorization_receipt": authorization_receipt.to_wire(),
        }
        try:
            response = self.call("/v1/effects/execute", payload)
        except (ProviderRejectedError, ProviderOutcomeAmbiguousError):
            raise
        except Exception as exc:
            raise ProviderOutcomeAmbiguousError("broker_response_ambiguous") from exc
        try:
            wire = _exact(response, {"status", "result"}, "malformed_broker_service_response")
            if wire["status"] == "rejected" and wire["result"] is None:
                raise ProviderRejectedError("provider_rejected")
            if wire["status"] == "ambiguous" and wire["result"] is None:
                raise ProviderOutcomeAmbiguousError("provider_outcome_ambiguous")
            if wire["status"] != "succeeded" or not isinstance(wire["result"], Mapping):
                raise ProviderOutcomeAmbiguousError("broker_response_ambiguous")
            return dict(wire["result"])
        except (ProviderRejectedError, ProviderOutcomeAmbiguousError):
            raise
        except Exception as exc:
            raise ProviderOutcomeAmbiguousError("broker_response_ambiguous") from exc


class EffectBrokerEndpoint:
    """Credential-side endpoint that reconstructs and verifies the full grant."""

    def __init__(
        self, broker: IsolatedEffectBroker, *, allowed_peers: frozenset[str],
        clock: Callable[[], int],
    ) -> None:
        if not allowed_peers:
            raise DistributedBoundaryError("empty_broker_peer_policy")
        self.broker = broker
        self.allowed_peers = allowed_peers
        self.clock = clock

    def handle(self, path: str, body: object, *, peer_identity: str) -> dict[str, Any]:
        if peer_identity not in self.allowed_peers:
            raise DistributedBoundaryError("broker_peer_denied")
        if path != "/v1/effects/execute":
            raise DistributedBoundaryError("broker_route_denied")
        fields = {
            "origin", "audience", "action_hash", "call", "grant",
            "authorization_event", "authorization_receipt",
        }
        wire = _exact(body, fields, "malformed_broker_request")
        try:
            call = ToolCall.from_wire(wire["call"])
            grant = GatewayGrant.from_wire(wire["grant"])
            receipt = AuditReceipt.from_wire(wire["authorization_receipt"])
        except Exception as exc:
            raise DistributedBoundaryError("malformed_broker_request") from exc
        if (not isinstance(wire["origin"], str) or not isinstance(wire["audience"], str)
                or not isinstance(wire["action_hash"], str)
                or not isinstance(wire["authorization_event"], Mapping)):
            raise DistributedBoundaryError("malformed_broker_request")
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, int):
            raise DistributedBoundaryError("invalid_broker_clock")
        try:
            result = self.broker.execute(
                origin=wire["origin"], audience=wire["audience"], action_hash=wire["action_hash"],
                call=call, grant=grant, now=now,
                authorization_event=dict(wire["authorization_event"]),
                authorization_receipt=receipt,
            )
        except ProviderRejectedError:
            return {"status": "rejected", "result": None}
        except ProviderOutcomeAmbiguousError:
            return {"status": "ambiguous", "result": None}
        if not isinstance(result, Mapping):
            return {"status": "ambiguous", "result": None}
        return {"status": "succeeded", "result": dict(result)}


class RemoteResourceService:
    def __init__(self, call: JSONServiceCall) -> None:
        self.call = call

    def execute(self, grant: GatewayGrant) -> EffectOutcome:
        try:
            response = self.call("/v1/actions/execute", {"grant": grant.to_wire()})
            wire = _exact(response, {"outcome"}, "malformed_resource_service_response")
            return EffectOutcome.from_wire(wire["outcome"])
        except DistributedBoundaryError:
            raise
        except Exception as exc:
            raise DistributedBoundaryError("resource_service_unavailable") from exc


class ResourceServiceEndpoint:
    """Operator-configured resource endpoint; callers cannot choose limits or destination."""

    def __init__(
        self, service: ResourceExecutionService, *, allowed_peers: frozenset[str],
        destination: str, effect_limits: Mapping[str, int], clock: Callable[[], int],
    ) -> None:
        if not allowed_peers or not destination or not effect_limits:
            raise DistributedBoundaryError("invalid_resource_endpoint_configuration")
        self.service = service
        self.allowed_peers = allowed_peers
        self.destination = destination
        self.effect_limits = dict(effect_limits)
        self.clock = clock

    def handle(self, path: str, body: object, *, peer_identity: str) -> dict[str, Any]:
        if peer_identity not in self.allowed_peers:
            raise DistributedBoundaryError("resource_peer_denied")
        if path != "/v1/actions/execute":
            raise DistributedBoundaryError("resource_route_denied")
        wire = _exact(body, {"grant"}, "malformed_resource_request")
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, int):
            raise DistributedBoundaryError("invalid_resource_clock")
        grant = GatewayGrant.from_wire(wire["grant"])
        outcome = self.service.execute(
            grant, destination=self.destination, now=now, effect_limits=self.effect_limits,
        )
        return {"outcome": outcome.to_wire()}
