# Governed Evolution Integration Contract (Proposal)

Status: **design proposal only; not an enabled runtime feature**  
Date: 2026-10-27  
Tracking: #23

## Safety invariant

A model may suggest a modification, but it must not approve or apply its own proposal. The authorized execution broker is separate from the proposer, evaluator, and external data adapters.

**User-authored foundational AI laws are mandatory and non-self-modifiable. Their exact text has not been established in this document.** Any implementation MUST require the exact verified text, version and digest before enabling evolution, and MUST reject proposed edits to it or the verification/authority mechanism. Do not substitute a guessed paraphrase.

## Proposed transaction state machine

`OBSERVED -> PROPOSED -> SIMULATED -> VERIFIED -> AUTHORIZED -> STAGED -> DEPLOYED -> MONITORED -> LEARNED`

Any error, ambiguity, denied permission, or missing evidence transitions to `REJECTED`; deployment failure enters `ROLLBACK_REQUIRED`, followed by independently verified `ROLLED_BACK` or a locked-down incident state.

No transition may be initiated solely by text retrieved from the web.

## Required proposal manifest

- `proposal_id`: collision-resistant immutable identifier
- `source_commit` and `target_environment`
- `action_type` and explicit file/endpoint/resource allowlist
- `diff_digest`, `artifact_digest`, `rollback_digest`
- `policy_version` and `foundational_laws_digest`
- `test_evidence_digest` (unit, integration, security, held-out replay)
- `expires_at`, `requested_by`, `approval_identity`, `approval_nonce`
- `risk_class`, `budget_limits`, `expected_impact`

A canonical serialization must be used before signature verification. Manifest hashes alone are not authorization.

## Independent gates

1. **Provenance:** Bind artifacts to exact source revisions and verified hashes.
2. **Policy:** Fail closed on missing laws, authority, signatures, scope, expiry or policy version.
3. **Sandbox:** No ambient secrets, network, deployment permissions or mutable hidden answers in generated-code tests.
4. **Evaluation:** Compare against pinned baseline and held-out cases; track failures as well as improvements.
5. **Approval:** One-use signed and scoped grant, atomically consumed to defeat replay or concurrent use.
6. **Deployment:** Atomic or canary rollout with health checks; signed rollback artifact must already exist.
7. **Audit:** Append-only, tamper-evident proposal-to-outcome trail with independent verifier identity.
8. **Learning:** Persist only evidence-backed outcomes, provenance, uncertainty and causal limitations.

## Adversarial acceptance tests

- Unsigned, altered, expired, wrong-scope and replayed approvals rejected
- Concurrent replay attempts permit at most one atomic consume
- Web-page instructions cannot grant authority or trigger deployment
- Proposed changes to foundational laws, verifier, and execution broker rejected
- Malicious manifest paths/symlinks and transitive build scripts cannot escape sandbox
- Rollback failure blocks subsequent evolutions and produces incident evidence
- Agent-graph hot swap fails safely for in-flight jobs
- Measured outcomes use fixed seeds and held-out baselines

## First implementation slice

Build a **proposal-only**, offline gate: strict typed manifest validator, pure policy decision with explicit deny codes, stubbed cryptographic verifier interface, bounded simulation hook and append-only event schema. No deployment or network tool privileges. Require independent review before enabling any execution.

## Source notes

Google Project Chrysalis (October 2026) describes a reference architecture and simulated outage, not a production guarantee. Firecrawl is an external web-retrieval option; all fetched content is untrusted and subject to licensing, cost and provenance review.

This document does not assert any implementation, test results or service-level improvement.
