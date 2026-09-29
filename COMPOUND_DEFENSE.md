# Compound attack defense

AAK v0.8 adds a circuit breaker for coordinated attacks that touch several
interaction points at once. It complements authorization; it does not replace
signature, quorum, budget, state or downstream checks.

## Deployment position

The guard belongs at an external policy-enforcement point receiving verified
events from the transport proxy, authority services, gateway, audit monitor and
downstream reference monitor. Its `trusted_source_id` must be derived from mTLS,
SPIFFE or an equivalent authenticated channel.

```python
from aak import CompoundAttackGuard

guard = CompoundAttackGuard(
    threshold=12,
    window_seconds=60,
    block_seconds=300,
    max_sources=10_000,
)

decision = guard.record(
    "spiffe://prod/ns/payments/sa/executor",
    boundary="authority",
    signal="quorum_bypass",
    now=verified_server_time,
    externally_authenticated=True,
)

if not decision.allowed:
    deny_at_external_proxy(decision.reason)
```

Supported signals are malformed input, replay, binding mismatch, identity
mismatch, invalid signature, quorum bypass, tenant substitution and audit
tampering. Operators can replace the weight map, but changes must go through the
same signed policy-release process as other security policy.

## Anti-lockout rules

- Do not score unauthenticated identity claims.
- Do not let the model call `record()` directly.
- Do not make the in-process object the only enforcement point.
- Replicate block decisions to the external gateway with a signed policy event.
- Reserve administrative capacity for investigation and recovery.
- Alert before automatic blocks approach a tenant-wide or global scope.
- Keep emergency access separately authenticated and fully audited.

## Validation

The guard has regression tests for multi-boundary correlation, timed release,
spoofed-victim protection and bounded storage. The wider AAK campaign completed
100,000 compound attacks with no unauthorized effects or crashes, including a
50-request simultaneous valid-signature race in which exactly one effect ran.

AAK v0.8.1 additionally bounds events per source and uses per-source cleanup
with rate-limited global maintenance, preventing event-memory and source-scan
CPU exhaustion.
