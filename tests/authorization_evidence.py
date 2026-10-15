"""Run existing local denial campaigns and record machine-readable evidence.

The sandbox uses local fixtures; this cannot attest to independent remote services.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGNS = (
    ("service_boundary", "tests/service_boundary_red_team.py", "AAK_SERVICE_ATTEMPTS"),
    ("reverse_path", "tests/reverse_path_red_team.py", "AAK_REVERSE_ATTEMPTS"),
)


def run(attempts: int = 120) -> dict:
    if type(attempts) is not int or not 1 <= attempts <= 10000:
        raise ValueError("attempts out of bounded range")
    findings = []
    for name, path, env_name in CAMPAIGNS:
        environment = {**os.environ, "PYTHONPATH": str(ROOT), env_name: str(attempts)}
        result = subprocess.run(
            [sys.executable, str(ROOT / path)],
            cwd=ROOT, env=environment, capture_output=True, text=True,
            timeout=60, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"{name} campaign failed: {result.stderr[-500:]}")
        try:
            payload = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as exc:
            raise RuntimeError(f"{name} campaign lacks verifiable JSON output") from exc
        if any(type(payload.get(k)) is not int for k in
               ("attempts", "unauthorized_acceptances", "provider_calls", "crashes")):
            raise RuntimeError(f"{name} missing integer counters")
        if (payload["attempts"] != attempts or payload["unauthorized_acceptances"] != 0
                or payload["provider_calls"] != 0 or payload["crashes"] != 0):
            raise RuntimeError(f"{name} unauthorized effects or incomplete attempts")
        findings.append({
            "name": name,
            "source_sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
            "attempts": attempts,
            "unauthorized_acceptances": payload["unauthorized_acceptances"],
            "provider_calls": payload["provider_calls"],
            "crashes": payload["crashes"],
        })
    return {"schema": "aak-local-denial-evidence-v1", "scope": "local_simulated_service_boundaries",
            "independent_remote_deployment_verified": False, "campaigns": findings}


if __name__ == "__main__":
    count = int(os.environ.get("AAK_EVIDENCE_ATTEMPTS", "120"))
    print(json.dumps(run(count), sort_keys=True, indent=2))
