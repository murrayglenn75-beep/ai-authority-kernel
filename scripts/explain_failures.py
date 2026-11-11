"""Summarize JUnit failures without inventing root causes."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

MAX_BYTES = 5_000_000
MAX_ITEMS = 100
MAX_TEXT = 1200

def analyze(path: Path) -> dict:
    if not path.is_file():
        raise ValueError("JUnit report does not exist")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("JUnit report exceeds the 5 MB limit")
    data = path.read_bytes()
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entities are not allowed in JUnit reports")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("Invalid JUnit XML") from exc
    if root.tag not in {"testsuite", "testsuites"}:
        raise ValueError("Expected JUnit testsuite/testsuites root")
    failures = []
    inspected = 0
    for case in root.iter("testcase"):
        inspected += 1
        for node in case:
            if node.tag not in {"failure", "error"}:
                continue
            if len(failures) >= MAX_ITEMS:
                break
            details = ((node.attrib.get("message") or "") + "\n" + (node.text or "")).strip()
            failures.append({
                "test": (case.attrib.get("classname", "") + "." + case.attrib.get("name", "unknown")).strip("."),
                "kind": node.tag,
                "evidence": details[:MAX_TEXT],
                "explanation": "Test reported an error" if node.tag == "error" else "Test assertion failed",
                "root_cause": "unverified",
            })
    return {
        "schema": "engineering.failure-report.v1",
        "source": str(path),
        "testcases_inspected": inspected,
        "failures_found": len(failures),
        "truncated": len(failures) >= MAX_ITEMS,
        "failures": failures,
        "status": "fail" if failures else "pass",
        "next_step": "Inspect the cited test and reproduce before attributing a root cause" if failures else "No failing testcases found in this report",
    }

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_xml", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = analyze(args.junit_xml)
    except (OSError, ValueError) as exc:
        print(f"Cannot analyze report: {exc}", file=sys.stderr)
        return 2
    data = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")
    return 1 if result["status"] == "fail" else 0

if __name__ == "__main__":
    raise SystemExit(main())
