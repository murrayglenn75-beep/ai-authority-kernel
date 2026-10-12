# Agent runtime safety: authority independent of orchestration

Status: proposed hardening contract; **not** evidence of passing tests or production integration.

## Decision rule
Choose a minimal tool loop for linear, stateless, reversible work. Choose a durable state machine/graph when human approvals, cross-process resumption, branching or delayed external effects require explicit transitions. Neither is the security boundary: AAK must verify every proposed effect regardless of caller.

## Required effect protocol
1. Canonicalize task, resource, action, subject and parameters into an immutable intent fingerprint.
2. Evaluate authorization at execution time. Issue narrowly scoped, expiring, single-use grants bound to the intent and principal.
3. Persist a unique operation ID and an auditable **prepared** record before dispatch.
4. Atomically claim each operation with fencing/lease and uniqueness; duplicate request must return the prior result, not re-execute.
5. On provider timeout after dispatch, enter **outcome_unknown**, not retryable failure. Query provider by idempotency key and reconcile before any possible repeat.
6. Persist final committed/failed/quarantined status. Revocation must prevent future effects; it cannot undo effects already committed.
7. Keep model text, graph state, and checkpoints untrusted; only independent broker/verifier holds provider credentials.

## Adversarial acceptance tests
- Same operation delivered 1000 times concurrently -> at most one externally committed effect.
- Crash before dispatch, after dispatch and before acknowledgement -> restart reconciles without double execution.
- Stale fencing token/expired grant -> rejected.
- Tool result injection and graph checkpoint tampering -> cannot authorize effects.
- Audit unavailable -> fail closed before effect; ambiguous post-commit audit -> quarantine and reconcile.
- Provider lacking idempotency/reconciliation -> manual review on uncertain outcome, never blind retry.

Measure violations, false-deny rate, recovery time, p95 latency and durable bytes, alongside baseline loop and graph solutions. Do not claim exactly-once external delivery without provider-level assumptions.
