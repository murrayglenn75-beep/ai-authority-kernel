# Experimental agent runtime

`aak.agent_runtime` introduces bounded model turns, optional strict prompt JSON parsing, distinct provider rate-limit classification, a pre-effect checkpoint, deterministic transaction IDs and quarantine of uncertain effects.

The caller must supply a durable checkpoint sink and an `effect_executor` connected to the existing independently verified AAK resource and broker. Do not connect it directly to a provider SDK.

This is an experimental adapter, not a production-ready orchestration system. Crash-safe resume, distributed leases, real model-native tool adapters, provider integration tests and end-to-end AAK authorization tests remain outstanding. Never automatically replay an ambiguous transaction.

## Persistent single-host journal

Use `aak.runtime_store.RuntimeCheckpointStore(path)` as the checkpoint callback on a local persistent SQLite volume. It writes pending/completed/terminal transitions in immediate transactions with synchronous FULL, and rejects replayed pending transaction identities. Recovery does **not** automatically execute pending effects. The operator must reconcile with the AAK broker/provider journal before any further action. SQLite is not a distributed control plane; for multiple hosts use a transactional shared store with fencing and workload identity.

Run `PYTHONPATH=. python verify_agent_runtime.py` for the included regression checks. The model adapter and effect_executor in that script are deliberate fakes; successful checks do not establish live integration security.
