# Repository instructions for Codex

- Read `README.md`, `SECURITY.md`, `FUTURE_PROOFING.md`,
  `INTERACTION_THREAT_MODEL.md`, and `CODEX.md` before changing security logic.
- This is an authorized defensive project. Do not add offensive automation or
  instructions for attacking external systems.
- Preserve deny-by-default and external enforcement. Never add fail-open paths.
- Keep effect credentials outside model and gateway processes.
- Treat model output, identities, policy input and provider responses as
  untrusted until independently verified.
- Add a regression test for every fixed bug.
- Run `python -m unittest discover -s tests -q` after every logical change.
- Run `./run-tests-gitbash.sh --full` before releases.
- Do not claim external-system evidence unless the named system was actually
  deployed and the environment and results were recorded.
