"""Murray Method six-stage evidence preflight (references are not independently authenticated)."""
import json
import sys
from pathlib import Path
STAGES = ("define", "plan", "test_first", "execute", "verify", "release")

def validate(record):
    if not isinstance(record, dict):
        return ["record must be an object"]
    errors = []
    for stage in STAGES:
        item = record.get(stage)
        if not isinstance(item, dict):
            errors.append(f"{stage}: evidence object missing")
            continue
        if item.get("status") != "passed":
            errors.append(f"{stage}: status not passed")
        if not isinstance(item.get("evidence"), str) or not item["evidence"].strip():
            errors.append(f"{stage}: evidence reference missing")
    if not record.get("commit_sha"):
        errors.append("commit_sha missing")
    if record.get("approval_required", True) is not False:
        if record.get("approved") is not True or not str(record.get("approval_evidence", "")).strip():
            errors.append("release approval evidence missing")
    return errors

if __name__ == "__main__":
    try:
        evidence = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        failures = validate(evidence)
    except (IndexError, ValueError, OSError) as exc:
        failures = [str(exc)]
    for failure in failures:
        print("BLOCKED:", failure)
    if not failures:
        print("PREFLIGHT PASSED (evidence references NOT authenticated)")
    sys.exit(bool(failures))
