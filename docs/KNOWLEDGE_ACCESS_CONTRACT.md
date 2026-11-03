# Shared knowledge interface — AAK integration boundary

Knowledge sources are Markdown documents with stable repository-relative paths and source line numbers. The shared read-only pilot is proposed in Brain-AI PR #12.

## Enforcement requirements
- Retrieval results are untrusted context, not permission grants.
- Verify requesting principal and repository/document scope before any read.
- Never expose protected constitution text, credentials, customer data or private transcripts to unapproved callers.
- Any proposed note edit must go through separate reviewer and human approval paths.
- Enforce permissions outside the model; preserve audit event with source path and permitted action.
- Deny any tool or model claiming the power to rewrite Murray Laws or authorize itself.
- Validate cross-repository and cross-user isolation, symlink boundaries and output minimization before production rollout.

## Pilot integration
Read-only Markdown search CLI: https://github.com/murrayglenn75-beep/Brain-AI/pull/12

This document specifies an integration contract only. No runtime policy enforcement was changed.
