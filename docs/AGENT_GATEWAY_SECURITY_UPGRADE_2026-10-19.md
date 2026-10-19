# Proposed agent gateway security upgrade (2026-10-19)

Status: design requirements only; not an implementation or verified security guarantee.

## Architecture
- Model plans/proposes actions. AAK alone authorizes precise resource/action/scope under a short-lived single-use grant.
- Execution broker validates grant at moment of use, binds arguments and target identity, records a scoped decision, and rejects expired/consumed grants.
- No inherited tool privileges via subagent, orchestration runner, MCP or UHP adapter; deny by default and enforce for retries, resumed turns, cancellation and parallel tasks.
- Separate deterministic verifier tests expected side effects and audit snapshot consistency; review-agent opinions cannot override authorization.
- Proposed harness adapter methods: submit, event_stream, checkpoint, cancel, result; all action requests still pass through AAK.

## Required adversarial tests
1. Prompt-injected tool instructions cannot grant access.
2. Cross-user resource substitution and argument mutation fail closed.
3. Replayed grants and post-revocation retries fail.
4. Resume after checkpoint cannot bypass approval.
5. Tool calls from child agents cannot escalate permissions.
6. Audit events capture exact decisions with secret redaction; intentional missing data fails verification.

## Integration restrictions
No privileged action or external execution from this document. Run sandbox-only tests then report failures, evidence, and limitations before release.
