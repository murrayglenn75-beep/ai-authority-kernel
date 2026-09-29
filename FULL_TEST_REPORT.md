# AAK v0.4 full security validation

Date: 2026-09-12

## Result

The tested kernel allowed no unauthorized effect in the included threat model.
This is a strong local result, not a claim that the system is bulletproof.

| Area | Test performed | Result | Fix or control |
|---|---|---:|---|
| Capability integrity | 10,000 signed-token mutations | Pass | Ed25519 verification fails closed |
| Parser resilience | 10,000 random tokens plus malformed structured proposals | Pass | Strict type, finite-number, and canonical-form checks |
| Contract binding | Principal, resource, action, parameters, effect, evidence, approval and transaction substitutions | Pass | Exact proposal hash and field bindings |
| Replay | Sequential replay and 8-way concurrent replay | Pass | Atomic nonce consumption |
| Concurrency stability | Concurrent replay repeated 200 times | Pass after fix | Every SQLite access now shares one re-entrant lock |
| Budgets | Split-action cumulative spend | Pass | Atomic per-principal buckets |
| Time | Expiry, premature use, and caller-supplied production time | Pass after fix | Time override disabled unless explicitly enabled for tests |
| Audit outage before effect | Injected first-write failure | Pass after fix | No effect; agent quarantined |
| Audit outage after effect | Injected completion-write failure | Pass after fix | Report committed effect, quarantine, and prevent retry |
| Revocation | Revoke unused token, then execute | Pass after fix | Revocation is enforced and audit-recorded |
| Executor exception | Handler throws after authorization | Pass | Agent quarantined; token remains consumed |
| Audit tampering | Modify an existing event | Pass | Hash-chain verification detects modification |
| Packaging | Compile all sources and build wheel | Pass | Deterministic source compilation and wheel build |
| Dependencies | Installed-package consistency check | Pass | No broken requirements |

## Measured totals

- Unit/security tests: 34 passed, 0 failed.
- Hostile black-box attempts: 20,008 denied without unauthorized effects.
- Authorized control: one effect; replay: zero additional effects.
- Final local microbenchmark: authorize p50 0.0667 ms, p95 0.1008 ms,
  p99 0.1443 ms; execute p50 0.1919 ms, p95 0.3038 ms, p99 2.0207 ms.

Performance measurements describe this machine and are not service-level guarantees.

## Issues found and fixed

1. Shared SQLite reads could race with a consume transaction and raise an
   intermittent `sqlite3.InterfaceError`. All connection access is now locked.
2. The public test-time parameter could let production application code choose
   token time. Overrides now require an explicit test-only constructor flag.
3. Audit failures were not separated into pre-effect and post-effect states.
   The kernel now fails closed before an effect and reports success plus
   quarantine after an effect, avoiding duplicate retries.
4. Revocation was effective but not auditable. It now appends a chained event.
5. Malformed typed fields and non-finite values could raise instead of returning
   a denial. They now return `malformed_proposal`.
6. Stale bytecode and direct benchmark invocation exposed release reproducibility
   problems. Sources are force-compiled and documented commands are explicit.

## Residual attack boundaries

These cannot be made safe by rules inside the AI or by this Python process alone:

- A compromised tool handler can perform more than its declared effect.
- A host attacker can replace AAK, patch the policy, steal credentials, or call
  the downstream service directly.
- Restoring an older state database can erase nonce, budget, revocation, and
  audit history unless an external monotonic checkpoint detects it.
- Multiple independent SQLite files do not provide distributed consistency.
- A compromised evidence verifier, signing service, or administrator remains a
  trusted-component failure.
- Side channels, denial of service, supply-chain compromise, and hardware or OS
  compromise are outside this local test harness.

Production containment therefore requires downstream capability enforcement,
separate service identities, least-privilege credentials, egress allowlists,
durable serializable shared state, HSM/KMS signing, externally anchored audit
checkpoints, signed policy deployment, and independent penetration testing.
