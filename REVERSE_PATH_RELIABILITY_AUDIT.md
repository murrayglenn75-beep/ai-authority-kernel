# Reverse-path reliability audit — October 2026

## Method
Trace a proposed action backwards from provider commit to isolated broker,
resource verifier, signed authority, checkpoint, model adapter, and finally
untrusted model/tool input.

## Fixed in this branch
1. **Batch preflight:** every call in a model reply is checked before the first
   effect. A later unknown tool cannot cause a partial earlier dispatch.
2. **Payload limits:** canonical tool arguments are bounded by UTF-8 bytes.
3. **Model counters:** boolean token counts are rejected as invalid.
4. **Tool result bounds:** rendered results are truncated by UTF-8 bytes and
   explicitly labelled untrusted in the history object.
5. **Durable local replay:** SQLite journal rejects the same effect identity
   across process restarts; ambiguous provider outcomes are not retried.
6. **Rate limits:** a 429 after a prior effect quarantines the run.

## Stress evidence (local simplified C state machine)
100,000,000 deterministic state vectors were run locally on October 10, 2026.
Independent bitmask oracle vs conditional gate: 0 mismatches; 96,904 valid
dispatch states; 99,903,096 denied states. Deliberately removing approval from
a mutant gate produced 97,162 detected mismatches. **This is not** 100 million
Python integration tests, provider operations, unique test cases or a production
security certification. The 10-bit model has only 1,024 distinct states.

## Unresolved failure modes
- The model and runtime are not yet wired end-to-end through a real AAK
  GatewayService -> ResourceExecutionService -> isolated effect broker.
- FORGE distributed state, lease fencing and failover are not implemented.
- Tool response labels do not make untrusted text safe from prompt injection;
  tool content isolation and red-team harness are still required.
- Provider idempotency/definitive rejection must be checked against authenticated
  provider receipts; absent records must not be treated as rejection.
- Large initial histories, adversarially nested JSON, parallel workers,
  deadline expiry inside a provider call, cancelled requests and memory pressure
  need additional limits and tests.
- Provider token usage is adapter-reported and can be inaccurate.
- A known run_id with altered history may not safely resume; no implicit resume.
- SQLite rollback/snapshot replacement requires an independent monotonic anchor.
- Mixed read/write batches cannot be made atomic across providers by the
  preflight check.
- Host compromise or misconfigured verifier remains outside local guarantees.

## Promotion gates
Require actual live provider benchmarks, real isolated broker integration,
serialized distributed worker leases with fencing, independent audit anchoring,
failover/crash fault injection, MITRE ATLAS and OWASP LLM tool-output abuse
tests, and all existing CI checks on supported platforms.
