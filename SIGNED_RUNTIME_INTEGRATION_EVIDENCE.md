# Signed runtime integration evidence — 2026-10-10

## Executed check

GitHub Actions `agent-runtime-defensive-checks`, run #68:
https://github.com/murrayglenn75-beep/ai-authority-kernel/actions/runs/38088994434

The run completed successfully. Its step "Run signed AAK integration scenario" completed successfully after installing runtime dependencies.

Integration source: `tests/test_runtime_integration.py`.

The scenario reuses `DistributedServiceTests` genuine fixture:
- Ed25519 signing keys, signed ToolManifest and ActionEnvelope
- certificate-bound EdDSA OIDC identity fixture
- strict OPA decision fixture
- GatewayService-issued exact grant
- ResourceExecutionService independent verifier
- VerifyingEffectBroker with independent replay SQLite store
- DurableAuditAnchor and signed chain verification
- RuntimeCheckpointStore and BoundedAgent
- deterministic fake provider (never live production credentials)

### Verified assertions
1. Matching model call dispatched to resource service and broker.
2. Exactly one synthetic provider invocation; broker gets gateway envelope transaction ID.
3. Audit chain passes verification; checkpoint ends completed.
4. Resource denies consumed grant replay and provider call count remains one.
5. Altered requested parameters are rejected before reaching the resource.

## Critical limitations
- Simulated provider, controlled local clock, OIDC/OPA fixture transport and local SQLite. This is **not live-provider** validation.
- `ExactGrantBoundary` matches action, resource, audience and canonical parameters. The runtime-generated transaction hash and separately issued envelope transaction ID are not yet cryptographically bound together. This remains an integration gap.
- AAK signed grant is prepared by fixture setup, not dynamically obtained from a deployed identity/policy service inside the model run.
- The test inherits existing distributed unit checks; all passing asserts are local integration evidence, not independently deployed services.
- No multi-host fencing, distributed crash reconciliation, actual provider idempotency check or production security certification is implied.
- This PR remains draft pending threat-model review and extended fault-injection tests.

## Next proof gates
- Bind model runtime transaction to broker's signed transaction identity and test mismatch.
- Execute dynamic GatewayService authorization with per-run identity and approval.
- Run independently deployed process/service topology against a real provider sandbox.
- Implement shared durable fencing and prove crash/restart/reconcile behavior.
