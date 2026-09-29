# Action Assurance Gateway architecture

## Product boundary

AAK is a provider-neutral action-assurance layer. It does not replace identity
providers, policy engines, credential vaults, API gateways or SIEM systems. It
binds their verified decisions into one exact, short-lived authority contract
and requires the final resource owner to enforce that contract immediately
before a consequential effect.

## Canonical flow

1. An authenticated protocol gateway maps an MCP tool name or REST method and
   route to an operator-registered action, resource and audience.
2. The gateway creates a canonical `ToolCall`; model-controlled arguments may
   populate parameters but cannot change the registered destination contract.
3. Independent identity, policy, evidence and approval services evaluate the
   request. Their stable references and versions become inputs to issuance.
4. A trusted authority signs an `ActionEnvelope` binding the human principal,
   terminal agent identity, delegation chain, purpose, exact request hash,
   policy decision, approvals, maximum effects, manifest hash, nonce and time.
5. The isolated executor obtains a narrowly scoped credential after approval.
   The model and orchestration process never receive the credential.
6. A verifier beside the resource owner verifies the envelope and signed
   `ToolManifest`, checks exact equality with the received call, and atomically
   consumes the nonce, business transaction and cumulative effect budget.
7. The provider effect is journalled as prepared, submitted, succeeded, failed
   or ambiguous. Ambiguous results are reconciled rather than blindly retried.

## Stable security invariant

No model output, protocol adapter or single upstream component may independently
create an unauthorized consequential effect. The downstream owner accepts only
an exact request covered by fresh, single-use, independently verifiable
authority.

## Implemented in v1.1-rc1

- Versioned signed `ActionEnvelope` and `ToolManifest` contracts
- Strict exact-field JSON wire decoders for cross-service contracts
- Human-to-agent delegation-chain binding
- Exact canonical request and manifest hashing
- Operator-owned MCP tool and REST route bindings
- Unsupported-version, malformed, expired and tampered input rejection
- Resource-side audience, protocol, action, resource and parameter verification
- Atomic nonce, business-idempotency and integer budget consumption
- HTTPS-only allowed-origin declarations in signed manifests
- Cross-platform deterministic state lifecycle and spawn-based process testing
- A 100,000-case synthetic mutation harness

## Required for production evidence

- A serializable PostgreSQL state adapter with failover and migration tests
- Real OIDC or SPIFFE authentication and proof-of-possession at each hop
- Real OPA or Cedar policy-decision verification
- JSON Schema validation matching the signed input-schema hash
- Strict duplicate-key JSON parsing before invoking the wire decoders
- Isolated credential broker and network egress enforcement
- Separate gateway, issuer, executor, verifier, audit and reconciliation services
- Durable signed receipts and an off-host append-only audit anchor
- MCP OAuth conformance, rate limiting, DDoS protection and tenant isolation
- Independent penetration testing and recovery exercises

## Future adapters

MCP and REST are translation adapters, not privileged formats. A2A, AP2,
OpenAPI, queue, webhook and model-provider adapters must emit the same
`ToolCall` and cannot weaken the resource-side verification rules. Unknown
schema versions and unavailable mandatory controls always fail closed.
