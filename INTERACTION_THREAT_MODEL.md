# AAK v0.6 interaction-point threat model

The attack surface is each handoff where data, identity or authority crosses a
trust boundary. Prompt rules are not counted as a security boundary.

| Interaction | Attack paths tested | Enforced control | Residual production requirement |
|---|---|---|---|
| Model → proposal API | Oversize/deep JSON, duplicate keys, NaN/floats, invalid UTF-8, Unicode ambiguity, extra fields | Strict canonical schema and integer units | API gateway limits, authenticated tenant identity, DDoS protection |
| Authority → gateway | Forged/duplicate signer, one compromised signer, policy/version substitution | Distinct threshold signatures and pinned policy/system values | Separate services, administrators and HSM keys |
| Operator → policy | One approval, duplicate approval, staging-to-production substitution, rollback/replay | Quorum-signed release, environment binding, monotonic generation | Protected review workflow and transparency log |
| Gateway → executor | Stolen dispatch, audience or payload substitution | Exact signed capability and short expiry | Gateway key in HSM; no effect credential |
| Executor → downstream | Identity spoof, method/route/body substitution, proof replay, stale proof, key revocation | Sender proof bound to key, method, canonical route, audience, body hash, nonce and time | mTLS/SPIFFE or DPoP key attestation and network allowlist |
| Downstream → resource | New nonce for same transaction, cross-tenant collision, stale state, fractional effect | Atomic tenant-scoped idempotency, resource version and integer budgets | Serializable shared database and resource-native enforcement |
| Downstream → audit | Forged receipt, event mutation, missing history, snapshot rollback, outage | Local signature/hash verification, continuity proof and quarantine | Off-account WORM replication and independently operated signing |
| Downstream → caller | False success, altered effect or state result | Signed receipt binding transaction, capability, request, effect, state versions and identity | Durable receipt registry and reconciliation workflow |
| Recovery/operator path | Emergency policy rollback or unsigned deployment | No implicit bypass; normal quorum and monotonic rules remain active | Separately designed multi-party break-glass procedure with expiry and audit |

## Security invariant

An interaction is accepted only if its content, sender, destination, time,
nonce, policy, state version and maximum effect all agree cryptographically and
semantically. A valid token copied from one interaction must not be usable at
another interaction.

## Limits

The Python implementation validates protocol behavior. It does not create
network isolation, authenticate a TLS certificate, provide DDoS protection or
make in-memory registries durable. A fully compromised downstream resource
owner remains capable of changing its own state.
