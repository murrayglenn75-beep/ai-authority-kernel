# AAK future-proofing contract

AAK keeps its security invariants stable while infrastructure changes.

## Stable invariants

1. Models propose; they never possess effect credentials or issue authority.
2. Decisions bind the exact proposal, policy, audience and validity time.
3. The resource owner independently verifies authority immediately before use.
4. Unknown versions, unavailable controls and uncertain outcomes fail closed.
5. Ambiguous external effects are reconciled and never automatically retried.

## Replaceable adapters

| Boundary | Reference implementation | Production target |
|---|---|---|
| Policy | `ExternalPolicyIssuer`; strict OPA staging adapter | Independently administered OPA, Cedar or another PDP |
| Identity | `WorkloadIdentityIssuer` | SPIFFE/SPIRE or cloud workload identity |
| State | SQLite `StateStore`; PostgreSQL staging adapter | Replicated serializable SQL with tested failover |
| Signing | `CapabilitySigner` | KMS/HSM signer and public verifier |
| Audit | `ExternalAuditAnchor` | Off-host append-only transparency service |
| Effects | `ToolContract` and journal | Provider idempotency and reconciliation adapter |
| Action contract | `ActionEnvelope` and `ToolManifest` | Cross-language verifier SDKs and sidecars |
| Protocols | MCP and REST adapters | A2A, AP2, OpenAPI and framework adapters |

## Evolution rules

- Signed structures carry explicit schema versions; unsupported versions are denied.
- Provider-specific data remains outside the authorization core.
- New cryptography implements `CapabilitySigner`; trusted verifiers remain key-pinned.
- Database upgrades are forward-only, restart-safe and tested against old data.
- Consistency floors and replay records live in shared transactional state, not
  process memory; every replica must use the same authoritative store.
- Workload assertions bind to the authenticated request body or TLS exporter;
  identity strings copied from request data are never sufficient.
- Issuance migrates before verification; old verification is removed only after
  every old capability has expired.
- Adapters must pass tamper, replay, rollback, outage, concurrency, clock-skew,
  ambiguous-effect and recovery contract tests before promotion.
- Protocol adapters may translate syntax but may not weaken the canonical
  action contract or select unregistered resources, audiences or destinations.
- Identity, policy and credential products remain replaceable integrations;
  AAK does not become an identity directory, policy language or secrets vault.

## Evidence still requiring real infrastructure

This release creates and tests the integration seams. Production evidence still
requires independent hosts, real OPA/SPIRE/KMS deployments, a replicated database,
provider sandboxes, network policies, observability, disaster-recovery exercises
and independent security review.
