# Scoped context authorization integration contract

Dependency: Brain-AI scoped context proof-of-concept branch `feature/scoped-context-layer-2026-11-07`.

## Trust boundary
- Resolve subject, tenant and collection permissions from a verified application session or signed capability, never from agent messages or retrieved text.
- Run independent AAK authorization **before** any collection access, search, tool invocation, indexing, cache lookup, or voice transcript retrieval.
- Bind authorization to action `knowledge.read`, subject, tenant, collection, content classification, purpose and expiry; deny by default.
- Recheck every read at the service boundary; filtering results after a broad read is not sufficient.
- Keep constitutional rules and Murray Laws outside any writable knowledge collection; no retrieved content may override authority policy.
- Audit allow and deny decisions with stable trace IDs, data source IDs and policy versions, without logging sensitive excerpts.
- Disallow cross-tenant caching, shared embeddings or transcript caches until independent isolation tests pass.
- Do not give an unauthenticated plugin, local voice engine or arbitrary MCP server direct database access.

## Required integration tests
1. Deny a fabricated principal supplied by an LLM instead of authenticated session identity.
2. Deny cross-tenant reads, missing collection grants, expired capability and missing purpose.
3. Deny protected document paths and symlink traversal; test path and encoding edge cases.
4. Deny unauthorized bulk export, tool-chain privilege escalation and cross-user cache hits.
5. Verify any approved result carries source reference and content digest; never treat it as an authorization token.
6. Confirm no secrets or private voice samples are emitted to logs or untrusted providers.

## Status
This contract is not connected to AAK's runtime yet. The Brain-AI prototype's local permissions are defensive checks, not an independently authenticated authorization service. Implementation requires repository-specific interface review, negative tests and human approval before merge.
