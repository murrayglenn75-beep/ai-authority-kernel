# Security boundary and limitations

## v0.5 security objective

Within the declared trust model, compromise of the AI/model host, one authority
signer, the enforcement gateway, the executor client, or the audit transport
alone must not create an unauthorized effect. The downstream resource owner
independently verifies every authorization input and remains a root of trust.

## Protected by this starter

- Exact-action binding
- Token tampering and replay rejection
- Expiry and policy-version binding
- Rule-level and cumulative budgets
- Independent approvals
- Fail-closed policy evaluation
- Hash-chained external audit events
- Agent quarantine after executor failure
- Trusted tool registration and model-independent impact derivation
- Authorized-approver allowlists and duplicate-resistant quorum checks
- Audit chain verification and tamper detection
- Ed25519 public-key verification and signing-key identity binding
- Evidence verification that defaults to deny
- Explicit revocation of unused capabilities
- Production callers cannot override the trusted process clock
- Audit-outage containment before and after external effects
- Thread-safe local state access and atomic replay/budget enforcement
- Strict malformed and non-finite input rejection
- Two-of-three independent authority quorum with duplicate-signer resistance
- Downstream re-verification of authority and gateway signatures
- Exact audience, policy hash and system-version binding
- Workload-identity binding at the resource boundary
- Principal and global cumulative budgets
- Signed external audit receipts with rollback/tamper detection
- Sender-constrained proofs bound to method, canonical route, audience and body
- Strict duplicate-free canonical JSON with size and depth limits
- Key activation, expiry and revocation checks
- Atomic business idempotency and optional resource-version preconditions
- Signed effect receipts and integer-only consequential effect units
- Quorum-protected, environment-bound, monotonic policy deployment
- Versioned, signed Action Envelopes bound to the exact canonical tool call
- Signed Tool Manifests binding tool version, resource, audience, protocols,
  input-schema hash, effect keys, risk level and allowed origins
- Strict MCP and REST translation through operator-owned bindings
- Human-to-agent delegation-chain binding and downstream atomic consumption
- Strict OPA response validation with denial on outage or ambiguity
- Certificate-bound, replay-resistant EdDSA OIDC workload tokens
- Serializable PostgreSQL replay, idempotency, version and integer-budget state
- Exact HTTPS-origin egress checks before credential-broker access
- Strict gateway-grant serialization across process boundaries
- Audit-before-effect enforcement and explicit committed-but-unanchored outcomes
- Isolated effect execution that does not export provider credentials
- Quarantine containment after audit or reconciliation failure
- Independent broker-side verification of the signed grant, manifest, exact
  call, audience, expiry, action hash and destination before secret use
- TLS 1.3 mutual authentication with exact SPIFFE URI peer allowlists
- Strict, bounded remote JSON schemas with duplicate-key and redirect rejection
- Overlapping asymmetric-key rotation with activation, expiry and timed revocation
- Signed audit authorization proof required at the credential broker
- Durable broker-domain replay consumption independent of resource-side state
- Signed off-host audit checkpoints that detect valid-prefix rollback
- Service-owned authorization clocks; remote callers cannot submit execution time
- Bounded HTTPS workers, connection deadlines and ambiguous-framing rejection
- Manifest-hash-bound input policies enforced independently at gateway and broker
- Explicit succeeded, rejected and ambiguous provider outcome states
- Lost broker responses treated as ambiguous and quarantined against retry
- Signed transaction IDs passed to providers as reconciliation/idempotency keys
- Anchor-domain-bound audit receipts with historical key identity across rotation

## Required before production

- Replace HMAC with asymmetric signing in an HSM/KMS.
- Run issuer, executor, audit, and model in separate identities and services.
- Use a durable serializable database shared by every kernel instance.
- Add authenticated, verified evidence records rather than evidence identifiers.
- Add policy signatures, a network-secured time source, key rotation, and revocation distribution.
- Add privacy/DLP, covert-channel controls, network egress filtering, and malware scanning.
- Define domain-specific rights, risk, and emergency policies.
- Formally model concurrency and revocation properties.
- Commission independent penetration testing and red-team review.

The starter limits a compromised model. It does not protect against simultaneous
compromise of the signing service, policy service, executor, audit service, and
their administrators.

It also does not yet prove resistance to host-kernel compromise, side channels,
hardware attacks, rollback of the state database, compromised trusted tool
implementations, or distributed consistency failures.

The v0.5 Python classes demonstrate protocol semantics in one test process;
they do not themselves create independent network, cloud-account or
administrator boundaries. Production must deploy those components separately.

Version 0.8 models cryptographic proof-of-possession at the application layer;
production must bind that proof to a real mTLS/SPIFFE or DPoP workload key. Its
local SQLite transaction semantics must be replaced by a serializable shared
database before more than one enforcement instance is deployed.

No in-process library can contain an attacker who controls the host, replaces
the kernel, or invokes the underlying service with stolen credentials. Enforce
the same capability at the downstream service, isolate executor credentials,
restrict network egress, and anchor audit/state checkpoints outside that host.

The v1.2 reference adapters normalize MCP and REST requests but do not run an
OAuth server, validate a JSON Schema, perform DNS or network enforcement, or
broker provider credentials. Production integrations must authenticate the
transport, validate inputs against the schema identified by the signed
manifest, inject secrets only inside an isolated executor, restrict egress to
the manifest's approved origins, and enforce the Action Envelope again at the
resource owner.

The PostgreSQL implementation and Compose topology have been locally inspected
and unit-tested through adapter contracts, but no Docker engine was available
in the release environment. Do not treat this release as evidence of live OPA,
OIDC or PostgreSQL interoperability until `deploy/staging` is exercised on an
isolated staging host and the resulting logs and versions are recorded.

The v1.6 loopback transport tests exercise real TLS 1.3 mutual authentication
and process-separated HTTP handling, but they are not evidence of container,
orchestrator, network-policy, live OPA/OIDC/PostgreSQL, certificate-rotation or
database-failover behavior. Those remain deployment evidence gates.

The v1.6 audit receipt schema is intentionally incompatible with the earlier
unscoped receipt table. An existing legacy database fails closed with
`legacy_audit_schema_requires_export`; export and independently verify its last
trusted checkpoint before initializing a domain-bound v1.6 anchor.
