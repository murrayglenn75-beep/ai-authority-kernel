# November 2026: agent-tool supply-chain and earned-autonomy gates

**Status:** integration specification and review gate; this document does not claim new runtime protections or passing tests. Existing AAK controls are authoritative.

## Third-party skills/MCP intake (deny by default)

Before onboarding any plugin, skill, MCP tool, downloaded archive or agent extension:

1. Resolve upstream provenance to an immutable commit/digest; record license, maintainer, dependencies and update source. Reject mutable or unverifiable sources.
2. In an isolated, network-restricted environment perform static inspection for shell execution, outbound network calls, environment/credential access, hidden prompts, dependency install hooks and filesystem writes. An optional scanner (e.g. SkillSpector) is supporting evidence **not** an allow decision.
3. Require security review of every critical finding, even if an aggregate score is low. Never execute untrusted code in the scanner's own privileged environment.
4. Maintain a reviewed allowlist of skill digest, granted capabilities, approved destination, expiry, reviewer and revocation timestamp.
5. At use time independently verify exact digest, requested tool, arguments, destination, identity, policy revision, budget and approval at the resource boundary; log signed accept/deny outcome.

## Earned autonomy

- `HALT` by default when policy, provenance, audit continuity or exact action identity is unknown.
- `REVIEW` enables dry-run and non-effectful evaluation but requires human authorization **before** any externally visible action.
- `LIMITED_EXECUTE` can be issued only for enumerated reversible, bounded effects and only when an independent evaluator verifies a pinned, human-labeled dataset, adequate sample size, acceptable one-sided false-accept upper confidence bound, approval and evidence expiry, total cost/action budget and no policy regression.
- Public publishing, real financial transfers, access grants and irreversible external operations remain explicitly human-approved. Never treat an agent's self-report as authority.
- Reject duplicate JSON keys, malformed version fields and stale/replayed capabilities; on ambiguous effect outcome quarantine instead of retrying without reconciliation.

## Evaluation/release contract

Store an append-only record for each attempt: fixture ID/hash, frozen grader ID/hash, dataset split/version, model/harness version, policy revision, request/response evidence hashes, outcome, cost, latency, timestamps and idempotency key. A crash or budget stop must resume without replaying already-paid attempts.

Acceptance tests to implement before release:
- Modified skill digest and revoked/expired approval fail closed.
- Prompt injection in SKILL.md / tool output cannot elevate authority.
- Duplicate-key policy JSON, replayed token, action-ID mismatch and wrong resource are denied.
- One-sided upper confidence bound is computed from independent human labels and fails closed when underpowered.
- A provider timeout after ambiguous submission is quarantined, not blindly retried.
- Audit write failure blocks issuance and external effects.

**No deployment assertion:** complete code review, independent adversarial tests, CI and operator approval before any enforcement change. Do not weaken the existing Murray Laws / AAK trust boundaries.
