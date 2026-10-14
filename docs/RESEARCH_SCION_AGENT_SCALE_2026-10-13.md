# Engineering research: Anthropic Scion and agent-scale code integration

Source: Anthropic Engineering, "Redesigning source control at Anthropic" (2026-10-13)
https://www.anthropic.com/engineering/redesigning-source-control

## Reported observations (not independently reproduced)
Anthropic reports its monorepo moved from approximately 2,500 merged changes/day in May 2026 to over 30,000 in September 2026. Its teams built Scion source control, Antique review, source search and fine-grained IAM. Associated public summaries describe checkout speed and CPU/resource gains relative to its previous setup. These numbers are workload-specific and do not prove an equivalent productivity or code-quality change for this repository.

## Applicable engineering principles
1. **Keep Git/GitHub here.** Scion's replacement of Git was at Anthropic's scale; no evidence justifies replacing our source control.
2. Isolate concurrent agents with dedicated branches/worktrees, constrained credentials and explicit ownership; ensure cleanup after failure.
3. Build changed-file and dependency-aware checks for efficiency, never skipping required baseline, security, CI and high-impact verification.
4. Cache by immutable source digest and pinned toolchain/lockfile; invalidate stale or unverifiable results.
5. Provide review packets containing issue, diff, risk classification, executable test evidence, architecture impact, supply-chain findings, approval and rollback evidence.
6. Enforce path-sensitive operation authority outside the model. Renames, symlinks, submodules, migration files and CI configuration must not bypass gates.
7. Track checkout duration, CPU/time per CI, cache hit correctness, merge-conflict rate, review latency, production regressions and recovery success. Claims require reproducible measurement.

## This repository's proposed application
Model Git path-scoped operation grants and independent approval for merge/deploy; bind grants to repository, base SHA and diff digest.

## Release evidence / acceptance gates (proposed)
- Establish a before/after baseline and representative task set.
- Document attack surface and protected-path policy.
- Exercise negative tests for invalid grants, manipulated diffs, stale hashes and missing evidence.
- Show actual CI regression pass and reproduce patch/test evidence on clean checkout.
- Keep all sensitive merges/deployments subject to independent human authorization.
- Mark any missing implementation, integrations, or validation as **outstanding**.

Status: **Research and project-specific backlog guidance only**. This file does not claim implementation or production readiness.
