# Reviewer quick start — AI Authority Kernel

**Purpose:** Check whether a model-requested effect is independently authorized and recorded, rather than taking security claims on trust.

## Reproduce the documented local checks

On a compatible Windows Git Bash environment:

```bash
./setup-gitbash.sh
./run-tests-gitbash.sh
```

See [GITBASH_SETUP.md](../GITBASH_SETUP.md) and [README](../README.md) for prerequisites and the exact control-flow scope.

## Inspect the trust boundaries

- Trace model request → gateway authorization → signed scoped grant → independent resource verification → isolated broker → provider → audit evidence.
- Inspect replay protection, exact-request binding and handling of ambiguous provider outcomes.
- Find the tests covering rejection, concurrency, audit outages and denial/quarantine states.
- Review the actual CI run for the commit being assessed, not only historic counts in the README.

## What this demonstrates — and does not

The repository documents local simulations, automated tests and staging-oriented security contracts. It **does not establish** an independently audited production deployment, an HSM-backed key lifecycle, or resilience of real remote providers under all failure modes. A successful local test is narrower than an end-to-end service security guarantee.

## Suggested reviewer questions

1. Where can a model-supplied value influence the authority decision?
2. What prevents reuse of a signed grant?
3. What state is reported when the provider acts but an acknowledgement or audit response is lost?
4. Which controls still depend on operator configuration in a production installation?
