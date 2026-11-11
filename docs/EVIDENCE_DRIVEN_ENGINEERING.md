# Evidence-driven engineering and reuse (proposal)

## Principles
- Inspect -> reproduce -> trace -> propose -> approve -> implement -> test -> verify -> record.
- A failure report is evidence, **not** a proven root cause. Never fabricate explanations.
- Record confidence, file/line or test evidence, reproduction steps, environment and unresolved unknowns.
- Agent-generated patches must pass the existing authority gateway and single-use, exact-action approval rules.
- Keep retrieved content (RAG, REA outputs, external repos) untrusted: do not let it grant tool permissions.
- Store reusable skills with version, owner, inputs, outputs, security constraints, test cases and provenance.
- Coordinate specialized agents through explicit task ownership; drafts remain drafts until approved.
- Do not reuse third-party proprietary implementations; inspect only authorized targets and implement original code.

## New utility
`python scripts/explain_failures.py path/to/junit.xml --output failure-report.json`

Outputs JSON schema `engineering.failure-report.v1` with failing test names, bounded error evidence, unknown root causes and next verification step. It only parses JUnit XML; it does **not** run repairs, inspect binaries or provide AI-generated causal diagnoses. Exit codes: 0 pass, 1 failed tests, 2 invalid input.

## Adoption gates
1. Generate JUnit artifacts from the existing test runner.
2. Execute the parser on the artifact and preserve output in CI.
3. Add an optional, independently reviewed troubleshooting agent only after tool permissions, prompt-injection tests and provenance controls are verified.
4. Record fixes as portable skills only after regression tests pass on another clean environment.
5. Measure repeat incident reduction, regression rate, time-to-repair and false-cause attribution.

## Project-specific next integrations
- AAK: broker authorization for any repair action, grant consumption, audit binding.
- FORGE/TANDEM: specialist task routing, visible shared history, draft/approval separation.
- Ethical Hacker: trustworthy triage from collected artifacts, never claims based only on a model.
- Fluxo/Signet/CFO-OS: reusable tested domain modules with contract/permission checks.
- APEX/ACE/Brain-AI: provenance-aware retrieval, local-resource budgets, versioned skill registry.
- SINAL: instrument and validate frame -> signal -> pulse pipeline against reference devices; not clinical accuracy by assertion.

Adapted from the user-supplied REA, multi-agent workflow and reusable-AI-engineering ideas; no external library has been incorporated.
