"""Local defensive saturation and failure-logic checks for AAK v0.8."""

import concurrent.futures
import time
import tracemalloc

from aak import (
    CompoundAttackGuard, Ed25519Signer, KeyRegistry, KeyStatus,
    SenderProofVerifier, StrictJSONGate, create_sender_proof,
)
from aak.boundary import BoundaryError
from aak.canonical import canonical_bytes
from aak.store import StateStore


metrics = {}
tracemalloc.start()

# Replay-cache saturation must remain bounded and fail closed.
key = Ed25519Signer.generate()
registry = KeyRegistry((KeyStatus(key, 0, 10**10),))
body = canonical_bytes({"transaction_id": "stress", "amount": 1})
verifier = SenderProofVerifier(
    registry, audience="stress", route="/v1/effects", method="POST",
    max_replay_entries=10_000, allow_test_time_override=True,
)
accepted = capacity_denied = 0
start = time.perf_counter()
for index in range(50_000):
    proof = create_sender_proof(
        key, method="POST", route="/v1/effects", audience="stress", body=body,
        issued_at=100, nonce=f"stress-{index}", subject="executor",
    )
    allowed, reason = verifier.verify(proof, body, now=101)
    accepted += int(allowed)
    capacity_denied += int(reason == "replay_cache_capacity_reached")
assert accepted == 10_000 and capacity_denied == 40_000
assert len(verifier._seen) == 10_000 and len(verifier._seen_order) == 10_000
metrics["proof_flood_seconds"] = round(time.perf_counter() - start, 3)

# One authenticated source cannot create unbounded correlated events.
guard = CompoundAttackGuard(threshold=1_000_000, max_events_per_source=100)
start = time.perf_counter()
blocked = 0
for index in range(100_000):
    decision = guard.record(
        "spiffe://prod/executor", boundary="wire", signal="malformed",
        now=100, externally_authenticated=True,
    )
    blocked += int(not decision.allowed)
assert blocked == 99_900
assert len(guard._events["spiffe://prod/executor"]) == 100
metrics["single_source_flood_seconds"] = round(time.perf_counter() - start, 3)

# Identity-cardinality attack cannot exceed max_sources.
guard = CompoundAttackGuard(threshold=1_000_000, max_sources=1_000)
capacity_denied = 0
for index in range(50_000):
    decision = guard.record(
        f"spiffe://prod/source/{index}", boundary="wire", signal="malformed",
        now=100, externally_authenticated=True,
    )
    capacity_denied += int(decision.reason == "compound_guard_capacity_fail_closed")
assert len(guard._events) == 1_000 and capacity_denied == 49_000

# Malformed/oversize flood must not crash or parse.
gate = StrictJSONGate(required_fields=("transaction_id", "amount"), max_bytes=128)
rejected = 0
for index in range(100_000):
    raw = (b'{' + bytes([index % 256]) * 256) if index % 2 else b'{"amount":1,"amount":2,"transaction_id":"x"}'
    try:
        gate.parse(raw)
    except BoundaryError:
        rejected += 1
assert rejected == 100_000

# Many simultaneous fresh nonces targeting one transaction permit one reserve.
store = StateStore()
def reserve(index: int) -> tuple[bool, str]:
    return store.consume(
        f"nonce-{index}", {"ops": 1}, {"ops": 100_000}, 100,
        idempotency_key="tenant:payment:tx-one", request_hash="same",
        strict_integer=True,
    )

with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
    results = list(pool.map(reserve, range(10_000)))
assert sum(allowed for allowed, _ in results) == 1
assert sum(reason == "duplicate_transaction" for _, reason in results) == 9_999

current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
metrics.update({
    "operations": 310_000,
    "unauthorized_or_duplicate_effects": 0,
    "crashes": 0,
    "peak_traced_mib": round(peak / 1024 / 1024, 2),
})
print("resilience_stress", metrics)
