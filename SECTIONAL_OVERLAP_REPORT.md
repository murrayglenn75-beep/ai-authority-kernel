# AAK sectional and overlap validation

## Section results

| Section | Tests | Result |
|---|---:|---|
| Interaction and transport boundary | 28 | Passed |
| Federated authority and downstream enforcement | 27 | Passed |
| Core authority kernel | 38 | Passed |
| Restart, multi-process and storage failure | 4 | Passed |
| Total after improvements | 97 | Passed |

## Defensive overlap

| Attack | First control | Independent fallback | Overlap |
|---|---|---|---|
| Body or parameter substitution | Sender body hash | Proposal hash and exact downstream payload | 3 layers |
| Tenant substitution | Authority tenant resolver | Downstream tenant resolver | 2 layers |
| Quorum forgery | Gateway quorum verifier | Downstream quorum verifier | 2 layers |
| Policy or system substitution | Gateway version binding | Downstream version binding | 2 layers |
| Sender/workload impersonation | Proof subject registry | Downstream workload comparison | 2 layers |
| Capability replay | Sender replay cache | Nonce and business idempotency store | 3 layers |
| Effect understatement | Authority maximum-effect binding | Tool-derived downstream effect | 2 layers |
| Stale resource race | Signed state version | Atomic SQLite state transition | 2 layers |
| Audit rollback/head forgery | Signed incremental continuity | Full-history independent verification | 2 layers |
| Policy rollback | Signed release quorum | Monotonic generation gate | 2 checks in one boundary |

## Improvements produced by this analysis

1. Transport verifier ownership moved into `DownstreamEnforcer`; callers can no
   longer substitute a verifier configured with attacker keys.
2. Downstream tenant identity is now resolved independently rather than trusting
   a nonempty authority claim.
3. Audit validation was divided into incremental signed-head continuity for the
   execution path and complete history verification for startup/monitoring.
   This removed quadratic request latency without abandoning full verification.
4. Exact integer maximum effects are now preserved on the wire, resolving a
   contradiction between claim creation and strict JSON validation.

## Single-boundary dependencies remaining

- Raw HTTP schema enforcement depends on the service adapter. Production must
  reuse the strict codec and must not deserialize directly into effect code.
- Policy release admission remains an administrative control-plane boundary and
  requires independent deployment enforcement.
- Historical audit availability depends on the external immutable store. AAK
  verifies its proofs but cannot make a compromised ordinary database immutable.
- Network admission and connection limits must be enforced by a production
  proxy or service mesh; the standard-library test server is not a production
  gateway.
