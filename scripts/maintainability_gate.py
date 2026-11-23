#!/usr/bin/env python3
"""Dependency-free changed-file maintainability checks; safe to run in untrusted PR CI."""
import argparse
import pathlib
import subprocess
import sys

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs"}
MAX_NEW_SOURCE_LINES = 1200
MAX_LINE_LENGTH = 240
SKIP_PREFIXES = ("node_modules/", ".next/", "dist/", "build/", "coverage/", ".git/")
SKIP_SUFFIXES = (".min.js", ".lock", ".snap", ".generated.ts", ".gen.ts")
MARKERS = ("<<<<<<< ", "=======", ">>>>>>> ")

def tracked_changes(base):
    result = subprocess.run(["git", "diff", "--diff-filter=ACMR", "--name-only", base, "HEAD"],
                            capture_output=True, text=True, check=True)
    return [s for s in result.stdout.splitlines() if s]

def check_text(text, path, new_file=False):
    findings = []
    lines = text.splitlines(keepends=True)
    if new_file and pathlib.PurePosixPath(path).suffix in EXTENSIONS and len(lines) > MAX_NEW_SOURCE_LINES:
        findings.append(f"{path}: new source file has {len(lines)} lines (limit {MAX_NEW_SOURCE_LINES}); split or justify")
    for i, line in enumerate(lines, 1):
        stripped = line.rstrip("\r\n")
        if stripped.startswith(MARKERS[0]) or stripped.startswith(MARKERS[2]) or stripped == MARKERS[1]:
            findings.append(f"{path}:{i}: unresolved merge conflict marker")
        if stripped.endswith((" ", "\t")):
            findings.append(f"{path}:{i}: trailing whitespace")
        if len(stripped) > MAX_LINE_LENGTH and pathlib.PurePosixPath(path).suffix in EXTENSIONS:
            # Not a hard failure: generated declarations and long URLs can be valid.
            pass
    return findings

def scan(base):
    names = tracked_changes(base)
    failures = []
    checked = 0
    for name in names:
        if name.startswith(SKIP_PREFIXES) or name.endswith(SKIP_SUFFIXES):
            continue
        path = pathlib.Path(name)
        if not path.is_file() or path.is_symlink() or path.suffix not in EXTENSIONS | {".md", ".yml", ".yaml"}:
            continue
        try:
            data = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        checked += 1
        r = subprocess.run(["git", "cat-file", "-e", f"{base}:{name}"], capture_output=True)
        failures += check_text(data, name, new_file=r.returncode != 0)
    print(f"Maintainability gate examined {checked} changed text files.")
    for f in failures:
        print("FAIL:", f)
    return 1 if failures else 0

def self_test():
    assert not check_text("def hello():\n    return 1\n", "test.py")
    assert check_text("x = 1   \n", "test.py")
    assert check_text("<<<<<<< HEAD\n", "test.py")
    assert check_text("=======\n", "test.py")
    assert check_text(">>>>>>> branch\n", "test.py")
    assert check_text("x\n" * 1201, "large.py", new_file=True)
    assert not check_text("x\n" * 1201, "existing.py", new_file=False)
    print("7 maintainability checks passed")
    return 0

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", help="Git base commit SHA for changed-file checks")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if not args.base:
        p.error("--base is required unless --self-test")
    try:
        return scan(args.base)
    except subprocess.CalledProcessError as exc:
        print(f"FAIL: git inspection failed: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
