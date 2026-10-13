# Engineering knowledge update — verified software understanding (2026-10-12)

## Source and claim discipline
- Reference: REA / Reverse Engineer Anything, https://github.com/morluto/rea ; background article https://startupfortune.com/an-ai-agent-that-reverse-engineers-any-software-just-hit-number-one-on-github/ ; LinkedIn discussion supplied by project owner.
- REA presents reverse-engineering tooling accessible to AI agents. Its name is **not** evidence of universal decompilation or correct reconstruction.
- Social claims of ~100k stars, commercial product clones, or software becoming effectively open source are **unverified here**, time-sensitive or overstated; do not repeat as technical guarantees.
- Reverse engineering does not confer licenses to reproduce copyrighted assets, bypass access controls or redistribute proprietary code.

## Cross-project design principles
1. Inspect before modifying; distinguish **observed fact**, **tool output**, **hypothesis**, and **unverified inference**.
2. Use existing static analyzers and controlled adapters instead of reimplementing full decompilers.
3. Treat analyzed binaries, outputs, extracted scripts, metadata and MCP tool responses as hostile inputs. Never execute unknown artifacts merely to inspect them.
4. Scope each investigation to authorized targets and record target hash, ownership/authorization attestation, analyst/tool identity, parser versions and evidence offsets.
5. Keep analysis and execution separate: read-only default, sandbox with filesystem/network/CPU/memory/time restrictions, explicit approval for potentially consequential operations.
6. Isolate original and reconstructed code/artifacts; use clean-room implementation when legally required, track dependencies/licenses, and prohibit secret ingestion.
7. Verify independently: compare predicted findings with owned test fixtures, manually reviewed ground truth, negative controls and reproducible scripts.
8. Prefer the smallest understandable architecture; architectural fitness, maintainability, recovery and security outrank generated line count or demo quality.
9. When an external effect is uncertain, do not blindly retry; require idempotency and reconciliation, independent authority and auditable transitions.

## Shared acceptance criteria
- Unauthorized target -> refused with no analysis.
- Malformed or adversarial file -> controlled failure without host execution or credential exposure.
- Injected instructions in extracted text -> cannot alter approval, output path or tool authority.
- Hash mismatch between inspected artifact and evidence -> finding rejected.
- Owned fixture with known behavior -> evidence must identify correct paths/offsets; compare precision, recall and false positives.
- Unsupported formats -> explicit unsupported result, not speculative claims.
- Crash/restart, concurrency, timeouts -> bounded resource usage and recoverable state without duplicated effects.
- Evaluate extra services, dependencies, and coupling added by any integration before merging.

## Status
Research and acceptance specification only. No reverse engineering adapter, benchmark, sandbox isolation, or production security guarantee is implied by this file.

## AAK — authorization and evidence envelope for inspection
- New *proposed* permission family: artifact.inspect.read scoped to artifact digest, path/format, bounded output and tool identity.
- Separate explicit permissions for artifact.execute, decompile.external_service, reconstruct.write and export.share; read-only grants must never imply these.
- Broker independently verifies artifact hash and path canonicalization, prohibits symlink/path traversal and blocks model instructions from granting scope.
- Write immutable audit envelopes tying decision, authorization, tool versions, evidence hashes and redacted result.
- Tests: stale grant, changed artifact digest, forged MCP result, injected approval text, concurrent replay and audit unavailable. No automatic extension to external provider calls.
