#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

python -W error::ResourceWarning -m unittest discover -s tests -q
AAK_SERVICE_ATTEMPTS="${AAK_SERVICE_ATTEMPTS:-100000}" PYTHONPATH=. python tests/service_boundary_red_team.py

if ! command -v docker >/dev/null 2>&1; then
  echo "Local service contracts passed; live Docker evidence remains NOT RUN." >&2
  exit 2
fi

required=(postgres_password.txt keycloak_admin_password.txt opa_tls.crt opa_tls.key)
for file in "${required[@]}"; do
  [[ -s "deploy/staging/secrets/$file" ]] || {
    echo "Missing deploy/staging/secrets/$file; run generate-staging-secrets.sh" >&2
    exit 1
  }
done

docker compose -f deploy/staging/compose.yaml config --quiet
docker compose -f deploy/staging/compose.yaml up -d --wait postgres opa identity
docker compose -f deploy/staging/compose.yaml ps

echo "Infrastructure containers started. This is not the complete promotion result."
echo "Gateway, resource, broker and audit service images plus failover tests are still required."
exit 3
