# Learned decision-head integration contract (research candidate)

Status: proposed integration, **not trusted-core implementation**.

A LoRA-trained classifier / Clef-style decision head may rank **proposals** outside the AAK security boundary. Its score never mints grants, expands privileges, bypasses review or executes a tool.

## Required flow
1. Receive bounded option IDs plus immutable evidence and tenant/context references.
2. Treat model scores, prompt, retrieved content and calibration metadata as untrusted.
3. Reject nonfinite, unnormalized or malformed scores and unseen option IDs; abstain on uncertainty, ties and shift.
4. If an option survives evaluation, translate to a separately reviewed exact-action proposal.
5. Reverify identity, policy, resource scope, freshness, approval and effect contract independently at the AAK boundary.
6. Deny/record when any gate fails; retain tamper-evident audit and model/version evidence.

## Release evidence
Frozen train/validation/test split with leakage controls; per-slice calibration and Brier/reliability diagrams; negative-option and prompt-injection fixtures; drift/OOD and abstention tests; CPU/RAM measures; deny-all adversarial tests. No trained weights are bundled or presumed validated. The AAK executor must work safely with the learned scorer unavailable.

Research provenance: Unsloth/Clef screenshot shared 2026-11-01 and Library `2026-11-01-unsloth-clef-decision-head-research.md`.
