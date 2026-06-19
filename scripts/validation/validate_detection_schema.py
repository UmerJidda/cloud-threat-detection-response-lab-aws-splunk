#!/usr/bin/env python3
"""
validate_detection_schema.py — Validate detection YAML files against required schema.

Checks that every detection.yaml has the required top-level fields and that
field values match allowed types/values.

Exit 0 if all detections pass. Exit 1 and print errors if any fail.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

REQUIRED_FIELDS = {
    "id": str,
    "name": str,
    "version": str,
    "status": str,
    "tactic": str,
    "technique": str,
    "severity": str,
    "data_sources": list,
    "splunk_index": str,
}

ALLOWED_SEVERITY = {"critical", "high", "medium", "low", "informational"}
ALLOWED_STATUS = {"active", "testing", "deprecated", "draft"}


def validate_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path}: YAML parse error: {exc}"]

    if not isinstance(doc, dict):
        return [f"{path}: expected a YAML mapping at top level"]

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in doc:
            errors.append(f"{path}: missing required field '{field}'")
        elif not isinstance(doc[field], expected_type):
            errors.append(f"{path}: field '{field}' must be {expected_type.__name__}, got {type(doc[field]).__name__}")

    if "severity" in doc and doc["severity"] not in ALLOWED_SEVERITY:
        errors.append(f"{path}: severity '{doc['severity']}' not in {sorted(ALLOWED_SEVERITY)}")

    if "status" in doc and doc["status"] not in ALLOWED_STATUS:
        errors.append(f"{path}: status '{doc['status']}' not in {sorted(ALLOWED_STATUS)}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate detection YAML schemas")
    parser.add_argument("--dir", default="detections", help="Root detection directory")
    args = parser.parse_args()

    root = Path(args.dir)
    if not root.is_dir():
        print(f"ERROR: directory not found: {root}", file=sys.stderr)
        return 1

    yaml_files = sorted(root.rglob("detection.yaml"))
    if not yaml_files:
        print(f"ERROR: no detection.yaml files found under {root}", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    for path in yaml_files:
        all_errors.extend(validate_file(path))

    if all_errors:
        print(f"SCHEMA VALIDATION FAILED — {len(all_errors)} error(s):")
        for err in all_errors:
            print(f"  {err}")
        return 1

    print(f"Schema validation passed: {len(yaml_files)} detection(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
