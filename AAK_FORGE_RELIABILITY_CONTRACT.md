# AAK–FORGE reliability contract (experimental v0.1)

## Purpose
Combine FORGE's durable scheduling with AAK's independent effect authorization.
A model may propose an action but **cannot issue, extend, or consume its own
authorization**. Resumed work must reacquire any required authority; approval
is not inferred from checkpoint state.

## Roles
- Model adapter: operator-selected native provider tool calls or strict JSON.
- FORGE: scheduler, checkpoint durability, worker fencing, time/tool/token budgets.
- AAK gateway: trusted identity, signed policy decisions, narrow action envelope.
- AAK resource owner: independently verifies grant, caller, action and approval.
- Broker: isolated credentials, provider transaction idempotency and effect journal.
- Reconciler: authenticated provider receipt/lookup, signed audit completion.
No network/credential access from the model process is trusted.

## Recovery transition contract
| State | Event | Next | May dispatch? |
|---|---|---|---|
| New | Durable pre-effect checkpoint | PREPARED | Only after AAK authorization |
| PREPARED | Broker accepts request | SUBMITTED | One bounded attempt |
| SUBMITTED | Verified successful receipt | SUCCEEDED | No |
| SUBMITTED | Verified pre-effect rejection | REJECTED | No automatic re-dispatch |
| SUBMITTED | Timeout, crash, lost response | AMBIGUOUS | Never |
| AMBIGUOUS | Authenticated exact provider lookup | SUCCEEDED/REJECTED | No |
| AMBIGUOUS | Unknown, absent or mismatched evidence | QUARANTINED | Never |
| Any | Approval revoked, stale policy, invalid identity | QUARANTINED | Never |

**Never equate an absent provider record with proof of non-execution.**
Repeated transaction IDs require provider-side idempotency or rejection, and
client-side checkpointing cannot produce exactly-once provider effects alone.

## Multiworker protocol (NOT IMPLEMENTED)
Use a shared serializable authority store: CAS lease acquisition with
monotonically increasing fencing tokens, strict expiry checked by *downstream*
broker, renewal only by current owner, atomic dispatch journal, and no retries
for uncertain effects. Workers must not derive a new transaction ID on recovery.
A local SQLite journal is not sufficient for multi-host leasing.

## Threat tests required
- MITRE ATLAS: prompt injection tries to change destination, policy, tool,
  approval identity, or suppress audit.
- MITRE ATT&CK/CAPEC: replay, request confusion, duplicate calls and confused
  deputy escalation.
- OWASP agent/tool risks: untrusted tool output cannot issue authority.
- malformed JSON: duplicate keys, fenced JSON, NaN/Infinity, huge payloads,
  missing arguments, schema drift and nested ambiguous requests.
- durability: worker killed before/after dispatch, DB outage, rollback, clock
  skew, lost responses, concurrent races, revocation between plan and execution.
- provider compatibility: native vs strict prompt JSON, sample-count confidence
  intervals, error attribution, 429 Retry-After and 5xx, token costs.
- traceability: signed run/step/call/transaction identifier, decision reason,
  policy revision, provider outcome and audit anchor; redact secrets and PII.

## Release gates
1. All AAK existing unit and adversarial tests must pass on supported OSes.
2. Native and prompt adapters tested against real providers and documented versions.
3. Real resource verifier/isolated broker and authenticated reconciliation wired.
4. Atomic multi-worker fencing demonstrated with fault injection.
5. Approval revocation, timeout, restart and uncertain effects fail closed.
6. Independently review architecture and threat model, and do not mark as
   production-ready without operational evidence.

## Scope of PR #6
Experimental runtime, local journal, native-tool normalization and recovery
decision contracts. No FORGE integration, live provider SDK, or multiworker
recovery is implied by this document.
