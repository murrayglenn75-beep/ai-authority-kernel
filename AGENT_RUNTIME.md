# Experimental agent runtime

`aak.agent_runtime` introduces bounded model turns, optional strict prompt JSON parsing, distinct provider rate-limit classification, a pre-effect checkpoint, deterministic transaction IDs and quarantine of uncertain effects.

The caller must supply a durable checkpoint sink and an `effect_executor` connected to the existing independently verified AAK resource and broker. Do not connect it directly to a provider SDK.

This is an experimental adapter, not a production-ready orchestration system. Crash-safe resume, distributed leases, real model-native tool adapters, provider integration tests and end-to-end AAK authorization tests remain outstanding. Never automatically replay an ambiguous transaction.
