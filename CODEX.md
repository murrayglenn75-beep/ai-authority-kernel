# Codex working agreement

AAK is a defensive authorization boundary for AI-initiated effects.

## Required workflow

1. Read `README.md`, `SECURITY.md`, `FUTURE_PROOFING.md` and
   `INTERACTION_THREAT_MODEL.md` before changing security behavior.
2. Treat model output, request identity, policy data and provider responses as
   untrusted until independently verified.
3. Preserve deny-by-default behavior. Never introduce a fail-open fallback.
4. Never place effect credentials in the model or gateway process.
5. Use `apply_patch` for edits and add a regression test for every bug fix.
6. Run `python -m unittest discover -s tests -q` after each logical change.
7. Run `./run-tests-gitbash.sh --full` before a release.
8. Do not claim real OPA, SPIFFE, KMS, PostgreSQL or provider evidence unless
   those external systems were actually used and the environment is documented.

## Next build target

Move the v1.1 Action Assurance contracts into a distributed staging deployment:
PostgreSQL-backed state, one real OPA or Cedar decision adapter, one real
OIDC/SPIFFE workload identity, an MCP gateway and a separately deployed
resource-side verifier. Keep provider-specific code outside the core.
