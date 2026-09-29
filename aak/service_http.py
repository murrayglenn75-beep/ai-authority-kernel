"""Small mutual-TLS HTTP transport for AAK staging service endpoints."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from .canonical import canonical_bytes
from .distributed import DistributedBoundaryError
from .service_api import MAX_SERVICE_BODY_BYTES


class ServiceEndpoint(Protocol):
    def handle(self, path: str, body: object, *, peer_identity: str) -> Mapping[str, Any]: ...


def strict_json_loads(value: bytes) -> object:
    if not isinstance(value, bytes) or len(value) > MAX_SERVICE_BODY_BYTES:
        raise DistributedBoundaryError("invalid_service_body")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise DistributedBoundaryError("duplicate_service_field")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=pairs)
    except DistributedBoundaryError:
        raise
    except Exception as exc:
        raise DistributedBoundaryError("invalid_service_json") from exc


def peer_spiffe_id(certificate_der: bytes) -> str:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        sans = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
    except Exception as exc:
        raise DistributedBoundaryError("invalid_peer_certificate") from exc
    spiffe = [value for value in sans if value.startswith("spiffe://")]
    if len(spiffe) != 1:
        raise DistributedBoundaryError("ambiguous_peer_identity")
    return spiffe[0]


class _NoRedirect(HTTPRedirectHandler):
    def http_error_301(self, *args): raise DistributedBoundaryError("service_redirect_denied")
    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, maximum_workers: int, connection_timeout: float, **kwargs):
        self._worker_slots = threading.BoundedSemaphore(maximum_workers)
        self._connection_timeout = connection_timeout
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self._connection_timeout)
        return request, address

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class MTLSJSONClient:
    def __init__(
        self, base_url: str, *, ca_file: str, certificate_file: str,
        private_key_file: str, timeout: float = 2.0,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or base_url.endswith("/") or not 0 < timeout <= 10
        ):
            raise ValueError("invalid_service_client_configuration")
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certificate_file, private_key_file)
        self.base_url = base_url
        self.timeout = timeout
        self.opener = build_opener(HTTPSHandler(context=context), _NoRedirect())

    def __call__(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise DistributedBoundaryError("invalid_service_path")
        body = canonical_bytes(dict(payload))
        if len(body) > MAX_SERVICE_BODY_BYTES:
            raise DistributedBoundaryError("service_request_too_large")
        request = Request(
            self.base_url + path, data=body, method="POST",
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/json":
                    raise DistributedBoundaryError("invalid_service_response")
                encoded = response.read(MAX_SERVICE_BODY_BYTES + 1)
        except DistributedBoundaryError:
            raise
        except (HTTPError, OSError, TimeoutError) as exc:
            raise DistributedBoundaryError("service_unavailable_or_denied") from exc
        if len(encoded) > MAX_SERVICE_BODY_BYTES:
            raise DistributedBoundaryError("service_response_too_large")
        decoded = strict_json_loads(encoded)
        if not isinstance(decoded, Mapping):
            raise DistributedBoundaryError("invalid_service_response")
        return decoded


class MTLSServiceHost:
    """Runnable service host. Only mutually authenticated TLS 1.3 is accepted."""

    def __init__(
        self, endpoint: ServiceEndpoint, *, host: str, port: int,
        ca_file: str, certificate_file: str, private_key_file: str,
        event_sink: Callable[[Mapping[str, Any]], None] | None = None,
        maximum_workers: int = 32, connection_timeout: float = 5.0,
    ) -> None:
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("invalid_service_port")
        if (isinstance(maximum_workers, bool) or not isinstance(maximum_workers, int)
                or not 1 <= maximum_workers <= 256
                or not isinstance(connection_timeout, (int, float))
                or isinstance(connection_timeout, bool)
                or not 0.1 <= connection_timeout <= 30):
            raise ValueError("invalid_service_capacity_configuration")
        service_endpoint = endpoint
        security_event_sink = event_sink or (lambda _event: None)

        class Handler(BaseHTTPRequestHandler):
            server_version = "AAK-Service"
            sys_version = ""

            def log_message(self, _format, *_args):
                return

            def _reply(self, status: int, value: Mapping[str, Any]):
                encoded = canonical_bytes(dict(value))
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(encoded)))
                self.send_header("cache-control", "no-store")
                self.send_header("x-content-type-options", "nosniff")
                self.end_headers()
                self.wfile.write(encoded)

            def _peer_identity(self) -> str:
                certificate = self.connection.getpeercert(binary_form=True)
                if not certificate:
                    raise DistributedBoundaryError("peer_certificate_required")
                return peer_spiffe_id(certificate)

            def _record(self, *, outcome: str, peer_identity: str | None = None) -> None:
                try:
                    security_event_sink({
                        "type": "service_request", "method": self.command,
                        "path": self.path, "peer_identity": peer_identity,
                        "outcome": outcome,
                    })
                except Exception:
                    return

            def do_GET(self):
                identity = None
                try:
                    identity = self._peer_identity()
                    allowed = getattr(service_endpoint, "allowed_peers", frozenset())
                    if identity not in allowed:
                        raise DistributedBoundaryError("health_peer_denied")
                    if self.path != "/healthz":
                        raise DistributedBoundaryError("health_route_denied")
                    self._record(outcome="accepted", peer_identity=identity)
                    self._reply(200, {"status": "alive"})
                except DistributedBoundaryError:
                    self._record(outcome="denied", peer_identity=identity)
                    self._reply(403, {"error": "denied"})

            def do_POST(self):
                identity = None
                try:
                    if len(self.headers) > 32 or any(
                        len(name) > 128 or len(value) > 4096
                        for name, value in self.headers.items()
                    ):
                        raise DistributedBoundaryError("service_headers_denied")
                    if self.headers.get("transfer-encoding") is not None:
                        raise DistributedBoundaryError("transfer_encoding_denied")
                    if self.headers.get_content_type() != "application/json":
                        raise DistributedBoundaryError("content_type_denied")
                    lengths = self.headers.get_all("content-length", [])
                    if len(lengths) != 1 or not lengths[0].isdigit():
                        raise DistributedBoundaryError("content_length_required")
                    length = int(lengths[0])
                    if length < 1 or length > MAX_SERVICE_BODY_BYTES:
                        raise DistributedBoundaryError("invalid_service_body")
                    body = strict_json_loads(self.rfile.read(length))
                    identity = self._peer_identity()
                    result = service_endpoint.handle(self.path, body, peer_identity=identity)
                    self._record(outcome="accepted", peer_identity=identity)
                    self._reply(200, result)
                except DistributedBoundaryError:
                    self._record(outcome="denied", peer_identity=identity)
                    self._reply(403, {"error": "denied"})
                except Exception:
                    self._record(outcome="unavailable", peer_identity=identity)
                    self._reply(503, {"error": "unavailable"})

        self.server = _BoundedThreadingHTTPServer(
            (host, port), Handler, maximum_workers=maximum_workers,
            connection_timeout=float(connection_timeout),
        )
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_file)
        context.load_cert_chain(certificate_file, private_key_file)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)

    @property
    def address(self) -> tuple[str, int]:
        return self.server.server_address

    def serve_forever(self) -> None:
        self.server.serve_forever(poll_interval=0.1)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
