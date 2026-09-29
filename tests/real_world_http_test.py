"""Production-like local HTTP integration test for AAK. No external effects."""

import concurrent.futures
import collections
import json
import statistics
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aak import (
    AuthorityAttestation, AuthorityBundle, DispatchCapability, DownstreamEnforcer,
    Ed25519Signer, EnforcementGateway, ExternalAuditAnchor, IndependentAuthority,
    KeyRegistry, KeyStatus, Proposal, SenderProof, SenderProofVerifier,
    StrictJSONGate, ThresholdVerifier, ToolContract, create_sender_proof,
    make_authority_claim,
)
from aak.boundary import BoundaryError
from aak.canonical import canonical_bytes
from aak.store import StateStore


NOW = int(time.time())
effects: list[str] = []
effects_lock = threading.Lock()
authority_keys = [Ed25519Signer.generate() for _ in range(3)]
authorities = [IndependentAuthority(k, lambda p: p.action == "payment.transfer" and p.parameters.get("amount", 999) <= 10) for k in authority_keys]
threshold = ThresholdVerifier(authority_keys, 2)
gateway_key = Ed25519Signer.generate()
gateway = EnforcementGateway(
    gateway_key, threshold, "payments-prod", expected_policy_hash="policy-http",
    expected_system_version="v0.8.2",
)
anchor_key = Ed25519Signer.generate()
anchor = ExternalAuditAnchor(anchor_key)
sender_key = Ed25519Signer.generate()
proof_verifier = SenderProofVerifier(
    KeyRegistry((KeyStatus(sender_key, NOW - 60, NOW + 3600),)),
    audience="payments-http", route="/v1/effects", method="POST",
    expected_subject="executor-http", max_replay_entries=20_000,
)
wire_gate = StrictJSONGate(required_fields=("proposal", "bundle", "dispatch"), max_bytes=32_768, max_depth=16)


def handler(_resource, params):
    with effects_lock:
        effects.append(params["effect_id"])
    return {"settled": True}


tool = ToolContract(
    "payment.transfer",
    lambda resource, params: resource == "account/vendor" and set(params) == {"amount", "effect_id"},
    lambda _resource, params: {"money": float(params["amount"]), "operations": 1.0},
    handler,
)


def decode_body(raw: bytes):
    value = wire_gate.parse(raw)
    p = value["proposal"]
    if not isinstance(p, dict) or set(p) != {
        "transaction_id", "principal_id", "agent_instance", "purpose", "action",
        "resource", "parameters", "maximum_effect", "evidence", "approvals",
    }:
        raise BoundaryError("proposal_schema_mismatch")
    proposal = Proposal(**dict(p, evidence=tuple(p["evidence"]), approvals=tuple(p["approvals"])))
    b = value["bundle"]
    if not isinstance(b, dict) or set(b) != {"claim", "attestations"} or not isinstance(b["attestations"], list):
        raise BoundaryError("bundle_schema_mismatch")
    bundle = AuthorityBundle(b["claim"], tuple(AuthorityAttestation(**item) for item in b["attestations"]))
    d = value["dispatch"]
    if not isinstance(d, dict) or set(d) != {"claim", "gateway_key_id", "gateway_signature"}:
        raise BoundaryError("dispatch_schema_mismatch")
    return proposal, bundle, DispatchCapability(**d)


class API(BaseHTTPRequestHandler):
    downstream = None

    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        if self.path != "/v1/effects":
            self.send_error(404)
            return
        try:
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdigit() or int(raw_length) < 1 or int(raw_length) > 32_768:
                raise BoundaryError("invalid_content_length")
            raw = self.rfile.read(int(raw_length))
            proposal, bundle, dispatch = decode_body(raw)
            issued_at = int(self.headers["X-AAK-Issued-At"])
            proof = SenderProof(
                self.headers["X-AAK-Key-Id"], self.headers["X-AAK-Subject"], "POST",
                "/v1/effects", self.headers["X-AAK-Audience"], self.headers["X-AAK-Body-Hash"],
                issued_at, self.headers["X-AAK-Nonce"], self.headers["X-AAK-Signature"],
            )
            result = self.downstream.execute_secure(
                proposal, bundle, dispatch, request_body=raw, sender_proof=proof,
                workload_identity="executor-http",
            )
            status = 200 if result.allowed else 403
            response = canonical_bytes({"allowed": result.allowed, "reason": result.reason})
        except (BoundaryError, KeyError, TypeError, ValueError):
            status = 400
            response = canonical_bytes({"allowed": False, "reason": "malformed_request"})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class ResilientHTTPServer(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True
    block_on_close = True


def prepare(transaction_id: str, effect_id: str):
    proposal = Proposal(
        transaction_id, "tenant-http", "model", "approved invoice", "payment.transfer",
        "account/vendor", {"amount": 1, "effect_id": effect_id}, {"money": 1, "operations": 1},
        ("invoice",), ("reviewer",),
    )
    claim = make_authority_claim(
        proposal, policy_hash="policy-http", system_version="v0.8.2",
        audience="payments-prod", issued_at=NOW - 1, expires_at=NOW + 300,
    )
    bundle = AuthorityBundle(claim, tuple(a.attest(proposal, claim) for a in authorities[:2]))
    dispatch = gateway.dispatch(proposal, bundle)
    assert dispatch is not None
    raw = canonical_bytes({
        "proposal": asdict(proposal),
        "bundle": {"claim": bundle.claim, "attestations": [asdict(a) for a in bundle.attestations]},
        "dispatch": asdict(dispatch),
    })
    proof = create_sender_proof(
        sender_key, method="POST", route="/v1/effects", audience="payments-http",
        body=raw, issued_at=NOW, nonce=f"http-{effect_id}", subject="executor-http",
    )
    headers = {
        "Content-Type": "application/json", "X-AAK-Key-Id": proof.key_id,
        "X-AAK-Subject": proof.subject, "X-AAK-Audience": proof.audience,
        "X-AAK-Body-Hash": proof.body_hash, "X-AAK-Issued-At": str(proof.issued_at),
        "X-AAK-Nonce": proof.nonce, "X-AAK-Signature": proof.signature,
    }
    return raw, headers


def send(url: str, raw: bytes, headers: dict[str, str]):
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, raw, headers, method="POST"), timeout=10) as response:
            value = json.loads(response.read())
            status = response.status
    except urllib.error.HTTPError as error:
        value = json.loads(error.read())
        status = error.code
    return status, value, time.perf_counter() - start


with tempfile.TemporaryDirectory() as directory:
    downstream = DownstreamEnforcer(
        gateway_verifier=gateway_key, authorities=threshold, anchor=anchor,
        anchor_verifier=anchor_key, expected_workload_identity="executor-http",
        audience="payments-prod", tools=(tool,), principal_limits={"money": 100_000, "operations": 100_000},
        global_limits={"money": 100_000, "operations": 100_000}, expected_policy_hash="policy-http",
        expected_system_version="v0.8.2", store=StateStore(f"{directory}/state.sqlite"),
        sender_proof_verifier=proof_verifier,
    )
    API.downstream = downstream
    server = ResilientHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/v1/effects"
    try:
        requests = [prepare(f"valid-{i}", f"valid-{i}") for i in range(500)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda item: send(url, *item), requests))
        reason_counts = collections.Counter(value["reason"] for _, value, _ in results)
        if sum(value["allowed"] for _, value, _ in results) != 500:
            raise AssertionError(f"valid HTTP request denials: {dict(reason_counts)}")
        latencies = [elapsed * 1000 for _, _, elapsed in results]

        # A valid capture is accepted once and every network replay is denied.
        captured = prepare("captured", "captured")
        assert send(url, *captured)[1]["allowed"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            replayed = list(pool.map(lambda _i: send(url, *captured), range(100)))
        assert all(not value["allowed"] for _, value, _ in replayed)

        # Fifty fresh capabilities race one business transaction; exactly one effect.
        races = [prepare("one-business-transaction", f"race-{i}") for i in range(50)]
        # Keep the proposal hash identical while transport nonces remain fresh.
        base_raw, _ = races[0]
        race_requests = []
        for index in range(50):
            proof = create_sender_proof(
                sender_key, method="POST", route="/v1/effects", audience="payments-http",
                body=base_raw, issued_at=NOW, nonce=f"race-proof-{index}", subject="executor-http",
            )
            race_requests.append((base_raw, {
                "Content-Type": "application/json", "X-AAK-Key-Id": proof.key_id,
                "X-AAK-Subject": proof.subject, "X-AAK-Audience": proof.audience,
                "X-AAK-Body-Hash": proof.body_hash, "X-AAK-Issued-At": str(proof.issued_at),
                "X-AAK-Nonce": proof.nonce, "X-AAK-Signature": proof.signature,
            }))
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            raced = list(pool.map(lambda item: send(url, *item), race_requests))
        assert sum(value["allowed"] for _, value, _ in raced) == 1

        # Malformed and oversized requests fail without reaching an effect.
        before = len(effects)
        malformed_headers = {"Content-Type": "application/json"}
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            malformed = list(pool.map(lambda i: send(url, b'{' if i % 2 else b'x' * 40_000, malformed_headers), range(1_000)))
        assert all(not value["allowed"] for _, value, _ in malformed)
        assert len(effects) == before

        # Dependency failure before an effect denies, quarantines, and blocks follow-up.
        original_append = anchor.append
        anchor.append = lambda _event: (_ for _ in ()).throw(OSError("injected audit outage"))
        outage = send(url, *prepare("audit-outage", "audit-outage"))
        anchor.append = original_append
        assert not outage[1]["allowed"] and outage[1]["reason"] == "audit_anchor_unavailable_workload_quarantined"
        follow_up = send(url, *prepare("after-outage", "after-outage"))
        assert not follow_up[1]["allowed"] and follow_up[1]["reason"] == "workload_quarantined"
        assert len(effects) == before

        assert downstream.verify_full_audit_integrity()
        p95 = statistics.quantiles(latencies, n=20)[18]
        print(json.dumps({
            "http_requests": 1_653, "valid_effects": 502,
            "unauthorized_or_duplicate_effects": 0, "crashes": 0,
            "latency_ms_p50": round(statistics.median(latencies), 2),
            "latency_ms_p95": round(p95, 2), "audit_integrity": True,
            "sqlite_file_backed": True,
        }, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
