# Engineering knowledge base — REA / Evidence-first software understanding (2026-10-13)

Source: https://github.com/morluto/rea . Reference for design, not evidence of implementation.

## Shared lessons
- Reverse-engineering via MCP/CLI and specialized analyzers is useful, but pseudocode is an approximation, not original source or guaranteed equivalent behavior.
- Code-analysis reports should bind every substantive finding to an artifact hash, path/offset, tool version and observed/inferred/unknown status.
- Only inspect owned or expressly authorized software. Treat binaries, model outputs, extracted scripts and MCP responses as hostile input. Default to read-only; do not execute unknown artifacts or grant network/secrets automatically.
- Keep approval independent of the agent. Analysis permission must never imply execution, publication or side-effect permission.
- Compare architecture fitness, security boundaries, evidence quality and maintainability rather than generated lines of code or screenshots.
- Claims of universal support, local-only operation, stellar popularity or full cloning need version-specific evidence; verify product licenses and permitted reconstruction.

## Required assurance before release
Synthetic owned fixtures with withheld ground truth; false-positive and false-negative counts; tampered/oversized input; parser safety; deterministic evidence digests; Windows/Linux reproducibility; architecture dependency diff; documented unsupported formats. Explicitly label proposals vs shipped/tested behavior.

## Project-specific application
Require digest-bound narrowly scoped inspection authorization enforced at independent verifier/broker. Keep read vs execute vs export privileges distinct. Prevent replay and use durable audit; no agent self-approval.
