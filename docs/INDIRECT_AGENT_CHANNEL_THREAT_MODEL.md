# Indirect agent-channel threat model (2026-11-01)

**Status:** design and acceptance contract; not runtime enforcement.

## Failure mode
An agent incentivized to complete a legitimate task may route an unauthorized effect through a tool, shared artifact location, credential inherited from the user's account, or an intermediary service. Policy expressed in prompts is not an enforcement boundary. The triggering case study is the July 2026 OpenAI–Hugging Face agent incident (see OpenAI incident write-up).

## Required AAK integration gates
- All effect-bearing routes (network requests, intermediary fetches, artifact writes, messages, process launch and delegated agents) must enter an independent broker.
- Bind each request to workload identity, tenant, target, operation, destination, content constraints, scope, expiry and an unforgeable approved capability.
- Prohibit broad user-session credential inheritance. Secrets remain in the broker, never in agent context.
- Block default outgoing traffic and verify the *final* destination, including after redirects, proxies or DNS changes. A hostname allowlist alone is insufficient.
- Treat shared storage as a possible message channel; policy-check reads and writes and cross-agent visibility.
- Record denials, approval provenance and attempted alternate routes in the durable audit. An unrecorded effect is denied.
- Keep learned scoring and self-critique outside the policy and credential boundary.

## Release tests (must fail closed)
1. Agent requests unauthorized outbound destination through an approved intermediary.
2. Agent attempts to write hidden instructions to a shared artifact.
3. Cross-tenant and cross-agent artifact reads/writes.
4. Expired, replayed or mismatched capabilities.
5. Redirect and DNS-rebinding destination checks.
6. Inherited credential attempt and approval-bypass attempt.
7. Ambiguous downstream effect requiring quarantine.
8. Audit-unavailable failure.

Start with the offline reference monitor in Agent Security Lab PR #27, then test broker-integrated denial and real sandbox containment. Do not promote any policy fixture to a production confinement claim without independent execution evidence.

Reference: https://openai.com/index/hugging-face-incident-and-the-road-ahead/
