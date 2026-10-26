# Cognitive and Behavioural Validation Gate (CBVG) v0.1

This experimental gate receives structured evaluation results for the **integrated** agent, not just the authority kernel. It does **not** execute tools, update model weights, grant permissions or deploy software.

## Required suites

- `blind_interview`: blinded human judges, with pre-registered prompts and human comparison responses; report raw judge decisions and confidence intervals, not just a pass/fail score.
- `novel_reasoning`: held-out engineering tasks, evidence-based scoring and contamination checks.
- `memory_transfer`: correction, delayed retention, novel transfer and deliberate forgetting.
- `adversarial_authority`: injection, privilege escalation and untrusted feedback attempts; **zero** permitted violations.
- `independent_regression`: baseline versus candidate on protected samples with paired comparisons.

## Trust boundary

The first implementation uses HMAC as a **local fixture / adapter**. A real independent evaluator must manage its secret outside agent control, supply immutable task and scorer digests, and persist used nonces in durable shared storage. The in-memory replay set here is insufficient across restarts. Evidence signatures attest receipts; they do not prove that human judges were blinded or that results are correct.

A successful `admit` result means only **receipt structurally admitted**. It is not authorization to promote a model, write memory or execute an action. Such operations must still pass existing AAK exact-action grants, independent resource verification and durable audit.

## Release blockers

1. Replace test HMAC with independent verifier identity and durable replay / evidence store.
2. Authenticate suite IDs, scorer hashes, judge allocation and hidden data provenance.
3. Implement held-out task harness with human blinded judgement, paired baseline comparison, uncertainty intervals and minimum effect sizes.
4. Add long-horizon memory correction and delayed tests, adversarial red-team runs and contamination audits.
5. Bind CBVG decisions to a specific candidate artifact and AAK promotion grant.
6. Run tests in repository CI, then reproduce independently on a Windows CPU-first machine.

## Run unit tests

```bash
python -m unittest discover -s tests -p 'test_cbvg.py' -v
```

No claim of human indistinguishability, general intelligence, or production safety follows from passing unit tests.
