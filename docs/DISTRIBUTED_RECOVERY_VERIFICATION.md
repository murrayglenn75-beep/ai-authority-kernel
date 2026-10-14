# Distributed effect-recovery verification plan (2026-10-11)

Status: **verification plan, not a passed test report**. This work extends the existing v1.6-rc1 local effect journal, signed transaction IDs and quarantine behavior. It does **not** claim production-ready exactly-once execution.

## Non-negotiable invariants

1. No provider invocation occurs before independent authorization, exact-request binding and durable authorization evidence are verified.
2. A retry with the same idempotency key but a different canonical request is rejected, not silently coalesced.
3. An expired worker lease cannot commit a new authoritative state transition after a newer fencing epoch becomes active.
4. Ambiguous provider effects are **not** called failure and are **not** blindly retried. The journal persists `UNKNOWN` or `RECONCILIATION_REQUIRED` until authoritative provider evidence is obtained.
5. Reconciliation must use provider-native transaction lookup where available. Otherwise require human investigation, record the unresolved status and preserve the original transaction ID.
6. Audit failure after a committed provider effect must quarantine further work without rewriting the historical outcome.

## Fault-injection matrix

| Failure point | Required evidence | Expected behavior |
| --- | --- | --- |
| Before durable command insert | No provider calls; no consumed grant | Fail closed |
| After command insert, before grant consume | Journal durable; no provider calls | Recover as pending; reauthorize as policy requires |
| After grant consume, before provider call | Consumed grant and durable execution intent | Recovery must not mint or reuse authority unsafely |
| Provider commits, response is dropped | Provider shows one committed transaction; journal uncertain | Quarantine; reconcile with original transaction ID; no blind resend |
| Provider rejects definitively | Rejection receipt from trusted adapter | Record terminal rejection; no effect |
| Worker pauses past lease, second worker takes over | Fencing epoch and writes from both workers | Reject stale worker writes |
| Network partition between worker and database | Durable journal and epoch history | Stop side effects where authority/durability cannot be confirmed |
| Audit completion unavailable after success | Provider receipt and quarantine event | Committed-but-quarantined, no automatic repetition |
| Repeated callback / duplicate delivery | Original and duplicate callback IDs | One state transition; no duplicate effect |
| Signing key rotates during recovery | Historical key ID, verified old receipt, new key activation | Verify history without accepting revoked authority for new work |

## Reproducible evidence requirements

- Run **two or more independent worker processes** plus independently hosted PostgreSQL and a controllable mock provider.
- The mock provider must persist side effects across worker death and be able to **commit then drop the response**.
- Record test revision, commit SHA, environment versions, seeded fault schedule, command ID, provider transaction ID, fencing epoch and outcome.
- Make failed cases available with minimal reproductions. A green simulation must not be described as an external-provider certification.
- Run each scenario repeatedly with randomized timing; measure unauthorized effects, duplicate effects, stuck reconciliations and recovery latency.
- Use a separately administered audit/checkpoint verifier when making audit-tamper resistance claims.

## Suggested ownership across projects

- **AAK:** enforce grants, resource verification, provider-bound signed transaction IDs and signed receipts.
- **FORGE:** own worker leases, fencing, durable orchestration and reconciliation scheduling.
- **Ethical Hacker / Agent Security Lab:** test attack, stale-worker and timeout scenarios against the integrated boundary.
- **Fluxo:** validate financial-command invariants using a sandbox provider rather than actual money.

## Release rule

Do not advertise exactly-once effects. Do not mark the distributed resilience gate PASS without a recorded, independently rerunnable run of the above scenarios. Local unit-test results remain valid but have a narrower scope.
