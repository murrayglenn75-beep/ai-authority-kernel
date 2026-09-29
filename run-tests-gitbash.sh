#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_dir"

if [[ -f .venv/Scripts/activate ]]; then
  source .venv/Scripts/activate
elif [[ -f .venv/bin/activate ]]; then
  source .venv/bin/activate
else
  echo "Run ./setup-gitbash.sh first." >&2
  exit 1
fi

python -W error::ResourceWarning -m unittest discover -s tests -q

if [[ "${1:-}" == "--full" ]]; then
  AAK_COMPOUND_ATTEMPTS="${AAK_COMPOUND_ATTEMPTS:-100000}" PYTHONPATH=. python tests/compound_red_team.py
  AAK_ASSURANCE_ATTEMPTS="${AAK_ASSURANCE_ATTEMPTS:-100000}" PYTHONPATH=. python tests/assurance_red_team.py
  AAK_ACTION_GATEWAY_ATTEMPTS="${AAK_ACTION_GATEWAY_ATTEMPTS:-100000}" PYTHONPATH=. python tests/action_gateway_red_team.py
  AAK_STAGING_ATTEMPTS="${AAK_STAGING_ATTEMPTS:-100000}" PYTHONPATH=. python tests/staging_red_team.py
  AAK_DISTRIBUTED_ATTEMPTS="${AAK_DISTRIBUTED_ATTEMPTS:-100000}" PYTHONPATH=. python tests/distributed_services_red_team.py
  AAK_SERVICE_ATTEMPTS="${AAK_SERVICE_ATTEMPTS:-100000}" PYTHONPATH=. python tests/service_boundary_red_team.py
  AAK_REVERSE_ATTEMPTS="${AAK_REVERSE_ATTEMPTS:-100000}" PYTHONPATH=. python tests/reverse_path_red_team.py
  PYTHONPATH=. python tests/resilience_stress.py
  PYTHONPATH=. python tests/real_world_http_test.py
  if ! command -v openssl >/dev/null 2>&1; then
    echo "OpenSSL is required for the full mutual-TLS identity test." >&2
    exit 1
  fi
  PYTHONPATH=. python tests/mtls_identity_test.py
fi

echo "AAK defensive verification passed."
