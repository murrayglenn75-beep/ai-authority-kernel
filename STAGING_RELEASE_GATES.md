# AAK–FORGE staging and production release gates

Status: experimental draft; not approved for production. Date: 2026-10-11.

## Completed, CI-verifiable local and database scenarios
- [x] Independent PostgreSQL connections race for the same run lease.
- [x] Lease expiry and increasing token reject stale workers.
- [x] Abrupt worker process exit and takeover against disposable PostgreSQL service.
- [x] Database-owned time controls expiry.
- [x] Duplicate signed transaction reservation is rejected.
- [x] Signed gateway / resource / broker integration tests.
- [x] PostgreSQL broker fence adapter persists the signed envelope transaction ID and denies a second dispatch in a local test.

## Release blockers (not certified)
- [ ] Deploy identity gateway, resource verifier, audit anchor and broker as independently authenticated workloads (mTLS/workload identity; no trusting HTTP headers for peer identity).
- [ ] Verify the broker's fencing store is shared and strongly consistent across hosts; enforce an authoritative, authenticated run-to-worker binding, not a client-selected run ID/token.
- [ ] Network partition tests: old worker isolated, lease expires, new worker takes over, old worker unable to execute at credentialed broker. Verify downstream side effects across hosts.
- [ ] Fail-stop and kill -9 at each boundary: before/after audit, dispatch reservation, broker replay consumption, external provider submission and provider response.
- [ ] Provider test tenant and idempotent API sandbox, with same signed transaction ID used as provider idempotency key where supported.
- [ ] Authenticated provider reconciliation for ambiguous submissions (match exact request fingerprint, identity and provider receipt); no automatic retry while unresolved.
- [ ] Verify no credentials, privileged grant minting or provider secrets enter model context.
- [ ] Threat review of prompt-injection content, untrusted tool outputs, authorization transfer and compromised workers.
- [ ] External review of database migrations, roles, TLS, backup/restore, failover behavior and operational alarms.
- [ ] Demonstrate bounded latency under provider hangs, resource exhaustion and policy outages.
- [ ] Validate documentation, runbook, operator approvals, alerts and release rollback plan.

## Operational runbook
1. Treat pending or ambiguous external effects as quarantined. Never use database lease expiry alone as permission to repeat a provider call.
2. Stop issuing grants before failover or migration; retain broker transaction IDs, signed authorization receipts and audit anchors.
3. Query PostgreSQL pending reservations and reconcile against authenticated provider records. Do not change outcomes from a model's report.
4. Require operator approval for inconclusive reconciliation; prefer permanent quarantine to duplicated effects.
5. Rotate keys/revoke grants, inspect durable audit, rehearse restore and test under load before promotion.
6. Keep PR #6 draft until all above critical blockers are executed and evidenced.

## Limitations of current tests
GitHub Actions runs on an ephemeral runner and a disposable PostgreSQL service; this is not proof of a distributed, globally exactly-once system. Local signed fixtures, deterministic models and fake external providers are useful but insufficient for production certification.

## Integrated shared-database evidence (2026-10-11)
- PostgresFencingStore.broker_fence builds a trusted broker hook which reserves the grant's exact signed transaction ID.
- CI exercises this hook inside the actual VerifyingEffectBroker with signed fixture and checks one fake-provider call and replay denial.
- Separate process termination after PostgreSQL dispatch reservation retains a pending record and prevents resubmission after reopening a connection.
- These tests are not independent-host network partition tests and do not provide provider-signed reconciliation, service credentials or exactly-once external effects.
