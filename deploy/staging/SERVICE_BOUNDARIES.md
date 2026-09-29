# Separated service deployment boundary

Deploy each component with a different workload identity, network policy,
service account and administrator. Importing the Python classes into one
process validates behavior but does not create these isolation boundaries.

| Service | May access | Must not access |
|---|---|---|
| Model application | Gateway MCP endpoint | OPA, state DB, audit DB, broker, provider credentials |
| Gateway | OIDC verification keys, OPA, envelope signer | Provider credentials, provider network, authority state DB |
| Resource verifier | Authority state DB, audit anchor, effect broker | Envelope signing key, OPA administration, provider credentials |
| Effect broker | Approved provider origins, secret manager | Model network, envelope signing key, policy administration |
| Audit anchor | Dedicated append-only audit DB, audit signing key | Provider credentials, policy administration |

Required request path:

1. Authenticated ingress creates `AuthenticatedGatewayContext` from verified
   transport identity, never from MCP arguments.
2. `GatewayService` validates the MCP mapping, certificate-bound workload token
   and exact OPA decision, enforces an operator-owned input policy bound to the
   signed manifest schema hash, then emits a signed `GatewayGrant`.
3. `ResourceExecutionService` reconstructs the strict wire grant, independently
   verifies it and atomically consumes its nonce and budgets.
4. The audit anchor commits `action_authorized` before any provider call.
5. The resource verifier checks the signed manifest's exact HTTPS origin.
6. The resource sends the signed authorization receipt and exact authorization
   event to the isolated broker. The broker verifies the audit signature and
   anchor domain, action binding and input policy, then atomically consumes the
   envelope in its own durable replay ledger before performing the provider
   action internally. It never returns a secret to the resource verifier.
7. The audit anchor records committed, failed or blocked state. If completion
   anchoring fails after a provider effect, the result is returned as committed
   and the workload is quarantined; automatic retry is forbidden.
8. Provider adapters receive the signed transaction ID as their idempotency and
   reconciliation key. A lost response or unknown provider result is ambiguous,
   quarantines the workload and must never be retried automatically.

## Promotion checks

- Terminate mTLS only at an authenticated proxy that deletes spoofable identity
  headers and injects verified identity metadata.
- Deny all network paths not listed in the table above.
- Put signing and provider keys in different KMS/HSM or secret-manager scopes.
- Use a replicated serializable authority database and an independently
  administered append-only audit store.
- Test OPA, database, identity, broker, audit and network-policy outages both
  individually and simultaneously.
- Prove that a compromised gateway cannot reach a provider and a compromised
  model cannot reach the broker, database or audit signer.
- Store each signed audit-head checkpoint outside the audit database and supply
  the last trusted checkpoint when the audit service restarts.
- Give every environment a unique audit anchor ID and a distinct signing key.
  Retain old public verifiers during rotation so historical receipts remain
  verifiable.
- Use service-owned trusted clocks; never expose execution time as a remote
  request field.
