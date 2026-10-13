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

## Database connection-failure injection
The PostgreSQL CI suite also terminates an independently connected PostgreSQL backend while a dispatch reservation remains uncommitted. It checks that PostgreSQL rolls back the incomplete reservation and that a later authorized reservation can be created. This is a session-disconnect/rollback test, **not** a partitioned external provider or multi-region application test. A durable committed pending record is never automatically replayed.

## Provider reconciliation evidence verifier
- Added provider_reconciliation.VerifiedProviderReconciliation which checks the full signed receipt with an operator-configured trusted public key, exact transaction ID and exact request fingerprint. Tampered receipts, unknown keys, non-definitive states and mismatched IDs remain REQUIRE_OPERATOR. The verifier cannot mint authority and never retries effects.
- The simulated signing key is a test-only provider fixture. **A real provider must actually issue or supply verifiable authenticated evidence** through a provider-specific connector. The API does not currently bind the request fingerprint to PostgreSQL pending journal rows; that linkage is a remaining release blocker before automated state settlement.

## Signed receipt persistence (2026-10-11)
- PostgreSQL now persists the grant's signed request fingerprint atomically with each broker dispatch reservation (separate FK-bound table).
- A provider-signed receipt with matching transaction and request hash can be classified using trusted public keys and recorded once in immutable aak_provider_outcomes; forged evidence and unknown states require an operator.
- The broker provider call remains non-atomic with PostgreSQL. Neither a signed test fixture nor a stored decision establishes production provider API compatibility; external receipt verification, trusted key distribution and authenticated reconciliation lookup must be implemented against a real provider.
- Existing pending reservations are never retried or discarded automatically. Historical reservations without a request binding remain ineligible for settlement.

## Signed transport to real effect broker (2026-10-12)
- CI `tests/test_real_broker_tcp.py` executes an actual `VerifyingEffectBroker` behind signed HTTP request verification with real `GatewayGrant`, Ed25519 audit receipt verification, PostgreSQL fencing and broker replay checks. Its stale owner is denied before the synthetic provider; the new owner succeeds once; replay is denied.
- The new test runs on a single GitHub Actions host, with the broker in-process behind a loopback TCP endpoint. It does not yet replace `tests/container_network_harness.py`'s simplified broker implementation, authenticate mTLS identities across hosts, or call a real idempotent provider. Those remain required acceptance gates.

## Isolated-container real broker acceptance (2026-10-12)
- `tests/container_network_harness.py` now executes the actual `VerifyingEffectBroker` via `EffectBrokerEndpoint` in its isolated Docker broker service, with separately signed worker transport identity, freshly authorized signed gateway grants, signed audit receipts, PostgreSQL lease fencing, and persistent broker replay records.
- The container test verifies a valid operation, forced old-lease expiry/new-owner takeover, old-worker denial, duplicate operation denial and an isolated container disconnected from the broker network. Runtime CI run 38326036593 passed container-network, postgres-fencing and defensive-checks jobs.
- This is still a single Docker host and a test-only synthetic provider with plaintext test HTTP. The harness derives authorization fixtures locally; it is not a separately deployed gateway or audit service. Production mTLS/workload attestation, broker credential handling, provider-side idempotency, real independently hosted failures and provider-signed reconciliation remain release blockers.

## CI ephemeral mutual TLS transport (2026-10-12)
- The isolated-container broker now requires a certificate signed by an ephemeral CI CA, and its HTTPS server certificate is validated against the `broker` DNS SAN by worker clients.
- Each worker mounts an independent client certificate; the broker verifies certificate Common Name matches the independently signed service identity before routing to `EffectBrokerEndpoint`. A cross-worker certificate/signature mismatch is actively denied in container CI.
- The CA and keys are disposable test material, not SPIFFE/SPIRE identity, rotation or production PKI. CI containers remain on one Docker host and PostgreSQL currently uses a test-only unencrypted DSN. Network partition and real provider release blockers remain unresolved.
- Runtime CI run 38326657863 passed container-network, PostgreSQL and defensive jobs.
