# AAK authorization maturity — verified local scope

This gate reruns two existing local campaigns through the actual AAK resource-side service endpoint / broker code, validates zero unauthorized acceptances/provider effects/crashes, checks exact attempt counts and stores SHA-256 hashes of campaign source files in a CI artifact. These campaigns exercise deliberately invalid requests, not a deployed remote provider.

**Claims this can support:** the included local malformed-service and reverse-path denial scenarios passed for the recorded number of attempts on the tested commit.

**Claims this cannot support:** actual independent remote services, TLS network partition tolerance, external provider settlement correctness, signed CI provenance, production secret management, HSM-backed keys, real approval identity, exactly-once effects or a third-party security audit.

## Next genuine cross-service release gate
- Separate identities, hosts/processes and trust domains for gateway, resource verifier, effect broker and audit service
- Configure mutual TLS and secrets management without checking credentials into source
- Independent audit receipts anchored off-host and reviewed under network partition
- Abrupt broker crash immediately before and after provider commit with externally checked effect count
- Verify expiry, replay and revocation while a service is unavailable
- Signed immutable CI artifacts, repeatable migration/rollback and manual security review

No live provider execution, new infrastructure or service deployment is created by this PR.
