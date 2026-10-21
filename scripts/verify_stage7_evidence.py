"""Fail-closed AAK–FORGE Stage 7 evidence validator.

Input is a locally reviewed JSON evidence manifest. This checks structure
and distinct, auditable artifact references, NOT the truth of those claims.
Real release requires independent verification of all supporting evidence.
"""
import argparse
import json
import sys
from pathlib import Path

REQUIRED = {
    "independent_hosts": "Separate broker, workers and coordinator hosts",
    "workload_identity": "Authenticated, rotated workload certificates",
    "database_security": "PostgreSQL TLS and least-privilege credentials",
    "partition_tests": "Real cross-host failure injection evidence",
    "provider_idempotency": "Sandbox duplicate-effect prevention",
    "provider_reconciliation": "Authenticated ambiguous-outcome lookup",
    "crash_recovery": "Broker/provider crash-point matrix",
    "security_review": "Independent signed security assessment",
    "audit_recovery": "Durable audit and backup/restore demonstration",
    "observability": "Alerts, traces and release runbook exercise",
}
def validate(data):
    if not isinstance(data,dict) or set(data)!={"commit","artifacts"}:
        raise ValueError("manifest_fields_invalid")
    if not isinstance(data["commit"],str) or len(data["commit"])!=40 or any(
            ch not in "0123456789abcdef" for ch in data["commit"]):
        raise ValueError("invalid_commit")
    records=data["artifacts"]
    if not isinstance(records,dict) or set(records)!=set(REQUIRED):
        raise ValueError("missing_or_unknown_release_evidence")
    seen=set()
    for key,item in records.items():
        if not isinstance(item,dict) or set(item)!={"status","evidence_uri","reviewer"}:
            raise ValueError("invalid_evidence_record:"+key)
        if item["status"]!="verified":
            raise ValueError("unverified_gate:"+key)
        uri=item["evidence_uri"]
        reviewer=item["reviewer"]
        if (not isinstance(uri,str) or not uri.startswith("https://")
                or len(uri)>2048 or uri in seen):
            raise ValueError("invalid_or_reused_evidence_uri:"+key)
        if not isinstance(reviewer,str) or len(reviewer.strip())<3:
            raise ValueError("missing_reviewer:"+key)
        seen.add(uri)
    return True

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("manifest",type=Path)
    args=parser.parse_args()
    data=json.loads(args.manifest.read_text(encoding="utf-8"))
    validate(data)
    print("Evidence manifest is structurally complete; independent review still required.")

if __name__=="__main__":
    try:
        main()
    except (ValueError,KeyError,OSError,json.JSONDecodeError) as exc:
        print("RELEASE_DENIED:",exc,file=sys.stderr)
        sys.exit(1)
