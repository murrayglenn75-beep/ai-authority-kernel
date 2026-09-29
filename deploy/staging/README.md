# Distributed staging profile

This topology creates real PostgreSQL, OPA and OIDC process boundaries for
staging validation. It is not a production deployment. The gateway, resource
verifier, credential broker and audit anchor must run as separately identified
services before consequential integrations are enabled.

`SERVICE_BOUNDARIES.md` defines the mandatory identities, network permissions,
request order and failure behavior for those four application services. The
Python service cores are implemented in `aak/distributed.py`; bind them to your
authenticated service framework without weakening the strict wire contracts.

## Git Bash startup

1. Copy this repository to a local trusted machine with Docker Desktop.
2. Run `./deploy/staging/generate-staging-secrets.sh`. It creates staging-only
   passwords, a 30-day CA and separate SPIFFE-identified service certificates;
   generated secrets are ignored by Git and the script refuses to overwrite
   an existing primary secret.
3. Run `./deploy/staging/run-evidence-gate.sh` and preserve its output.
4. Complete the gateway, resource, broker and audit container wiring plus the
   failover scenarios listed below before adding any provider credential.

The evidence script deliberately exits non-zero when Docker is unavailable or
when only the infrastructure containers have started. This prevents a partial
run from being mistaken for deployment evidence.

## Promotion evidence still required

- Run gateway, resource, broker and audit under distinct workload identities.
- Enforce the documented network allowlist between every service.
- Connect live OPA, OIDC and PostgreSQL adapters and record their versions.
- Rotate service certificates and signing keys during active traffic.
- Interrupt multiple services simultaneously and prove fail-closed behavior.
- Fail over PostgreSQL and verify replay, budget and audit-chain continuity.

The container networks are internal and no host ports are published. Reach
services only through test containers attached to the appropriate network.
OPA is deny-by-default. PostgreSQL transactions are serializable. Secrets are
mounted from files and must never be copied into model or gateway environments.

The compose file pins image versions but not immutable digests. Resolve and
review multi-architecture digests, vulnerability scans and signatures in CI,
then pin approved digests before promoting this profile beyond local staging.
