# AAK–FORGE separate-host staging acceptance

**Status: deployment procedure, not a completed multi-host test.**
No real host inventory, trusted workload-identity infrastructure or provider sandbox is configured by this document.

## Topology
- Host A: signed-grant issuing gateway and resource verifier, with independent identity and authorization keys.
- Host B: effect broker with provider credentials, read-only trust roots, mTLS listener and its own durable broker replay ledger.
- Host C: PostgreSQL coordinator with TLS, independently managed backups and least-privilege service roles. Use a single strongly consistent writer.
- Host D: worker A. Host E: worker B. Never share private signing keys between workers.
- Independent audit anchor: reachable by resource verifier; broker verifies signed audit receipts independently.

## Deployment gates
1. Establish an isolated staging network, provision short-lived workload identities and mTLS certificates from a trusted CA, and check SAN/identity binding. CI's self-signed CA and certificate Common Name checks are only scaffolding: prefer SPIFFE identities in SANs.
2. Configure PostgreSQL TLS verification and separate migration/admin, lease, broker reservation, provider-outcome and read-only accounts. Worker credentials must not write effect reservations.
3. Start the broker with only provider-facing credentials and verifier public keys. Require fixed trusted run/worker binding from the signed operation, not caller-chosen lease tokens.
4. Test a harmless provider sandbox operation using a stable provider idempotency key equal to the signed transaction ID; prove authenticated lookup and request-fingerprint matching.
5. Synchronize evidence collection (run ID, host ID, sanitized trace ID, database lease token, grant ID, authorization receipt, provider idempotency key, provider receipt) without exposing private keys or payload secrets.

## Partition acceptance matrix
- Cut A-to-C: gateway must not issue authorization dependent on unverified state.
- Cut D-to-B: worker A cannot reach effects; no unsafe retry after connection resumes.
- Cut B-to-C while D-to-B stays live: authenticated broker rejects operations that cannot be fenced.
- After A's lease expires, allow E to take over and restore D-to-B: stale A still denied.
- Cut B-to-provider just after submit; quarantine unknown outcome pending independent provider reconciliation.
- Stop audit before authorization: reject; stop completion audit after known commit: quarantine and record committed-but-unconfirmed.
- Test coordinator restart, broker crash, multiple broker replicas, database failover and persistent replay state. Verify no unauthorized provider effect and no unaccounted provider effect.

## Exit criteria
Capture command transcripts, sanitized packet/flow captures, signed audit receipts, provider sandbox records, exact source commits, container/image hashes, TLS identity checks, metrics and independent review. Mark the milestone complete **only** after distinct hosts are verified with genuine network faults. One-host Docker isolation is a prerequisite, not equivalent proof.
