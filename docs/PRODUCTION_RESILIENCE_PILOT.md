# Opt-in production reliability pilot

The standard-library async executor in `engineering/production_resilience.py` provides concurrency caps, per-attempt timeouts, retries for explicitly transient failures, and fail-closed empty retrieval. It does not change existing runtime behavior or authorize tools.

Run locally from `engineering/`:
`python -m unittest -v test_production_resilience.py`

Use **only with idempotent operations** unless the call has a durable idempotency key. A timeout cannot prove a side effect did not occur. Do not retry payments, writes, credential changes, or other effects blindly.

Next steps: integrate behind feature flags at selected ingress points; emit privacy-safe traces and error categories; benchmark p50/p95 latency, cost per successful task and retries; add production-scale load tests. Security policy and Murray Laws remain independent of LLM outputs.

Local isolated prototype tests: 6 passed on 2026-11-04. GitHub CI has not run these tests.
