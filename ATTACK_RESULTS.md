# AAK v0.4 local attack results

Date: 2026-09-12

## Results

| Test layer | Attempts | Unauthorized effects |
| --- | ---: | ---: |
| Signed-token mutation | 10,000 | 0 |
| Random malformed tokens | 10,000 | 0 |
| Exact-contract substitutions | 8 | 0 |
| Authorized control | 1 | 1 expected |
| Replay after successful execution | 1 | 0 |

All 34 deterministic unit/security tests passed. The concurrent replay test
also passed 200 consecutive stress repetitions after a shared-connection race
was found and fixed.

## Contract substitutions tested

- Principal replacement
- Resource redirection
- Action replacement
- Parameter escalation
- Impact understatement
- Evidence replacement
- Approver replacement
- Transaction replacement

## Additional tested properties

- Token expiry
- Explicit revocation
- Cross-key token rejection
- Cross-version invalidation
- Atomic replay rejection under eight concurrent attempts
- Cumulative budget enforcement
- Duplicate approval rejection
- Self-approval rejection
- Unregistered action rejection
- Unknown parameter rejection
- Negative and unknown effect rejection
- Audit-chain tamper detection
- Agent quarantine after executor failure
- Audit failure before and after an external effect
- Production time-override rejection
- Malformed structured-input rejection
- Revocation audit recording

## Interpretation

The measured security outcome is external effect count, not whether an attack
was merely logged or classified. Within this local harness, hostile inputs did
not reach the registered side-effect handler.

## Not yet tested

- AgentDojo and Agent-SafetyBench
- Compromised trusted executor code
- Operating-system or database compromise
- Distributed race conditions across multiple database nodes
- State rollback and backup restoration attacks
- Network partition and clock compromise
- Side-channel and covert-channel data exfiltration
- Hardware and supply-chain compromise
- Live LLM false-denial and task-success rates
- Independent penetration testing
