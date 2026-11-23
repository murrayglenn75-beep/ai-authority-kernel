# Code ownership and AI-assisted change policy

This repository uses a human-reviewable, evidence-based release gate. AI-generated code is treated as untrusted until reviewed and tested.

## Ownership
- All files have a default accountable owner in `.github/CODEOWNERS`. Ownership means responsibility for review, not proof a review occurred.
- Changes to authorization, financial effects, identity, production deployment, agent skills and CI require explicit human review.
- No agent may approve its own code, disable an enforcement gate, silently merge a PR, or alter security policy through a prompt.

## Pull request evidence
Every substantive PR should identify:
1. User problem, affected paths, and alternatives considered.
2. Existing functions/modules checked before adding new abstractions.
3. Tests run with exact commands and outcomes; do not call unrun checks “passed”.
4. Security and privacy effects, including auth, secrets, data flow and external network use.
5. Rollback procedure and a clear explanation of how the implementation works.

## Maintainability criteria
- Prefer reusing existing functions, narrow interfaces and small patches.
- Reject duplicated business logic, unexplained dependencies, avoidable complexity or opaque generated code.
- Require understandable naming, architectural explanations, regression tests and deterministic side-effect handling.
- Keep the model, evaluation, execution and independent authorization boundaries separate.
- Avoid sensitive personal data in traces, prompts and test fixtures.

## CI gate
`python3 scripts/maintainability_gate.py --self-test`
`python3 scripts/maintainability_gate.py --base <base-sha>`

The gate rejects merge-conflict markers, whitespace errors, and newly introduced oversized source files. Duplicate snippets are reported for review without falsely treating similar boilerplate as proof of a defect.
CI alone cannot certify code comprehensibility or human approval. Repository admins must separately configure branch protection / required reviews in GitHub settings.

Status: This policy and check are proposed via a draft PR; merge, branch protection and human approval are separate decisions.
