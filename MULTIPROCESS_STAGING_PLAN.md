# Multi-process staging deployment plan

Status: reproducible CI-level proof only; not a deployed multi-host release.

## Components and trust boundaries
1. **Gateway:** issues signed grants after authenticated workload identity and policy decision.
2. **Resource verifier:** independently validates signed grants, consumes authority and appends authorization audit before effect.
3. **Broker:** owns provider credentials; independently verifies signature, audit receipt, request parameters and network destination.
4. **PostgreSQL coordinator:** stores monotonic worker leases, signed-operation dispatch reservations, and authenticated outcome evidence. Restrict access to service roles.
5. **Workers:** never hold provider credentials or mint grants. An agent-proposed action must pass the signed AAK authority boundary.

## Required deployment isolation
- Separate process identity and privileges for gateway, verifier, broker, audit and workers.
- TLS/mTLS and pinned workload identity for all networked requests; do not trust caller-supplied identity headers.
- Shared PostgreSQL with authenticated TLS and least-privilege service account; separate schema/roles for lease acquisition, reservation and outcome records.
- Provider sandbox with low-risk test operations, idempotency keys and independently authenticated lookup of transaction receipts.
- Central log/audit collection; scrub credentials and sensitive payloads.
- Stop-on-unknown-effect: unresolved pending transactions are never automatically retried.

## Executable verification already in CI
The postgres-fencing job runs tests/test_postgres_fencing.py against disposable PostgreSQL 16. Tests include competing DB connections, two independent Python worker processes, takeover, unexpected worker exit, broker call with a signed grant, immutable provider test receipt, and a forcibly terminated PostgreSQL connection.

## Multi-host acceptance test (not yet executed)
1. Deploy worker A and worker B on different hosts; connect both to the same staging PostgreSQL instance.
2. Admit worker A, reserve a signed operation, then isolate A from the coordinator while it can still attempt to reach the broker.
3. Advance past lease expiry, admit worker B, and prove A's stale operation fails at the broker before reaching the sandbox provider.
4. Kill broker before/after submission, drop responses and repeatedly poll verified provider reconciliation.
5. Prove provider-side duplicate suppression by the signed transaction ID, and quarantine unknown results.
6. Test audit outage, database outage, policy outage and identity compromise; verify deny-by-default with zero unauthorized provider effects.
7. Collect logs, exact commands, versions, host IDs and receipts; perform human security review before release.

## Launch restrictions
No production external calls or credentials should be introduced by CI. Do not mistake independent processes on one CI host for independent hosts under network partition. Production gate remains open.

## Signed service transport prototype
`aak/authenticated_service.py` adds a signed peer/destination/path/body/timestamp/nonce envelope and a durable SQLite nonce replay ledger. CI checks forged peers, tampered destinations/bodies, stale timestamps and replay across restarts. The verified peer identity is passed to strict endpoint handlers only after signature checks. This is *application-level identity proof*; production requires authenticated TLS, strict transport byte limits, durable multi-replica replay state, scoped keys and a deployed-service network test. The demonstration uses no production provider credentials.

## Shared signed-request replay coordination
`aak/postgres_service_replay.py` stores destination/peer/nonce as a PostgreSQL unique key, allowing separate verifier instances to reject the same signed request through independent DB connections. `AuthenticatedServiceDispatch` now fails closed when ledger access raises an exception. The PostgreSQL CI scenario tests reuse, tampering and independently signed destinations. The earlier SQLite ledger remains single-host only. This does not certify actual cross-host network failure behavior, TLS channel binding, or provisioning of identity keys.

## TCP transport demonstration
`tests/test_tcp_fencing_integration.py` opens a real 127.0.0.1 HTTP endpoint and sends cryptographically signed worker requests through it. PostgreSQL lease takeover makes the former worker unable to reserve another operation; the second worker succeeds and duplicate delivery is denied. Worker identities have separate signing keys, and forgery of the other identity is rejected. This remains one GitHub Actions host and a local fake effect counter; plaintext loopback HTTP is test-only. It is **not** TLS-authenticated multi-host deployment, realistic network partition or a real AAK VerifyingEffectBroker/provider side effect. Do not reduce the release countdown based on this test alone.
