"""Conservative path-based review tier hints; never grants merge permission."""
import sys
from pathlib import PurePosixPath

CRITICAL_PARTS = ("auth", "authority", "policy", "payment", "payments", "ledger",
                  "rls", "migration", "migrations", "security", "broker", "secrets")
HIGH_PARTS = ("api", "server", "workflow", "workflows", "deployment", "deploy",
              "integration", "integrations", "infra")
DOC_SUFFIXES = (".md", ".txt", ".rst")

def tier(paths):
    paths = list(paths)
    if not paths:
        return "BLOCKED"
    level = 0
    for raw in paths:
        if not isinstance(raw, str) or not raw.strip():
            return "BLOCKED"
        normalized = raw.replace("\\", "/").lower()
        if normalized.startswith("/"):
            return "BLOCKED"
        normalized = normalized.strip("/")
        parts = tuple(PurePosixPath(normalized).parts)
        if ".." in parts or normalized.startswith("/"):
            return "BLOCKED"
        if any(part in CRITICAL_PARTS for part in parts):
            level = max(level, 3)
        elif any(part in HIGH_PARTS for part in parts) or normalized.endswith((".yml", ".yaml", ".sql")):
            level = max(level, 2)
        elif not normalized.endswith(DOC_SUFFIXES):
            level = max(level, 1)
    return ("DOCS", "STANDARD", "HIGH", "CRITICAL")[level]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("BLOCKED: supply changed paths")
        sys.exit(2)
    result = tier(sys.argv[1:])
    print(result)
    sys.exit(2 if result == "BLOCKED" else 0)
