"""Offline advisory preflight for third-party agent skill folders.

Never executes skill files. Passing means manual review is still required.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 200
PATTERNS = {
    "credential_access": re.compile(r"(?i)(\\.ssh/|\\.aws/credentials|\\.env\\b|api[_ -]?key|private[_ -]?key)"),
    "remote_execution": re.compile(r"(?i)(curl\\s+[^\\n|]+\\|\\s*(?:ba)?sh|wget\\s+[^\\n|]+\\|\\s*(?:ba)?sh|invoke-expression|iex\\s*\\()"),
    "exfiltration_hint": re.compile(r"(?i)(upload|post|send|exfiltrat).{0,100}(secret|token|credential|password)"),
    "instruction_override": re.compile(r"(?i)(ignore (?:all )?(?:previous|prior) instructions|disable (?:security|safety) checks)"),
}
TEXT_SUFFIXES = {'.md', '.txt', '.py', '.sh', '.bash', '.js', '.ts', '.json', '.yaml', '.yml', '.toml', '.ps1'}

def inspect_skill(folder: Path) -> dict:
    root = folder.absolute()
    findings, evidence = [], []
    if not root.is_dir() or root.is_symlink():
        return {"decision": "block", "findings": ["invalid_or_symlinked_root"], "files": []}
    if not (root / 'SKILL.md').is_file() or (root / 'SKILL.md').is_symlink():
        findings.append('missing_regular_SKILL.md')
    paths = sorted(root.rglob('*'))
    if len(paths) > MAX_FILES:
        findings.append('file_count_limit_exceeded')
    for path in paths[:MAX_FILES]:
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append(f'symlink:{rel}')
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            findings.append(f'oversized_file:{rel}')
            continue
        raw = path.read_bytes()
        evidence.append({'path': rel, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': size})
        if path.suffix.lower() in TEXT_SUFFIXES or path.name == 'SKILL.md':
            content = raw.decode('utf-8', errors='replace')
            for name, pattern in PATTERNS.items():
                if pattern.search(content):
                    findings.append(f'{name}:{rel}')
    return {'decision': 'block' if findings else 'manual_review_required',
            'findings': sorted(set(findings)), 'files': evidence}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    args = parser.parse_args()
    result = inspect_skill(args.folder)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result['decision'] == 'block' else 0

if __name__ == '__main__':
    raise SystemExit(main())
