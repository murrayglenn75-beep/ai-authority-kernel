# Comparative security analysis

This is a documentation-level comparison, not a head-to-head benchmark. A blank
or undocumented feature is not proof that another implementation lacks it.

## Closest published work

### Arbiter-K / ArbiterOS

Published design: deterministic semantic kernel, typed instructions, taint
tracking, execution sinks, policies, budgets, and rollback. The paper reports
more than 92% interception in one configuration and less than 6% false
interception on benign NanoBot operations.

Public paper: https://arxiv.org/abs/2604.18652

Opportunities for AAK differentiation:

- Exact approved-payload/executed-payload cryptographic binding
- Single-use, replay-resistant capabilities
- Impact derived by trusted executors rather than declared by the model
- Atomic cumulative budgets across independently valid requests
- Explicit proposer/approver separation
- Audit-chain integrity tests
- A compromise-first rather than trajectory-correction-first security claim

Arbiter-K is stronger than current AAK in semantic taint propagation,
instruction dependency graphs, rollback, benchmark breadth, and integration
with real agent frameworks.

### MI9

Published design: semantic telemetry, continuous authorization, delegation
graphs, FSM conformance, drift detection, and graduated containment.

Public paper: https://arxiv.org/abs/2508.03858

The authors explicitly identify synthetic evaluation, instrumentation blind
spots, runtime overhead, and attacks against the governance mechanism as open
limitations. AAK targets these with sink-level authorization that does not
require visibility into private reasoning. MI9 remains stronger in continuous
goal-drift monitoring and temporal conformance.

### AAGATE

Published design: Kubernetes control plane, zero-trust service mesh,
purpose-bound identity, shadow red teaming, behavioral analytics, and proposed
zero-knowledge compliance proofs.

Public paper: https://arxiv.org/abs/2510.25863

AAK is smaller and easier to embed, and its claims are attached to executable
unit tests. AAGATE is broader at organizational and infrastructure scale.

## Current evidence

AAK v0.2 tests deterministic properties at the kernel boundary. It has not yet
been evaluated on AgentDojo, Agent-SafetyBench, a live LLM, Kubernetes, or a
distributed database. No superiority claim is valid until the same workloads,
attack corpus, false-positive definition, latency environment, and threat model
are used for every system.

## Target benchmark

The fair benchmark must report:

- Attack interception rate
- False-interception rate
- Unauthorized external effects, not only detected attempts
- Time-to-containment
- Token replay success under concurrency
- Cumulative-budget bypass success
- Parameter-substitution success
- Understated-impact success
- Audit-tamper detection
- P50/P95/P99 authorization latency
- Availability during enforcement-component failure
