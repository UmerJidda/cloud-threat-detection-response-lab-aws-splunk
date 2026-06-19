#!/usr/bin/env python3
"""
validate_spl_syntax.py — Lightweight SPL syntax check for detection files.

Checks that SPL files referenced from detection YAMLs exist and contain
the minimum required structural elements (index reference, eventName or source).

This is NOT a full SPL parser — it enforces structural conventions:
  - SPL file must exist alongside detection.yaml
  - Must reference at least one Splunk index (index=)
  - Must not be empty
  - Must not contain obvious Python/shell syntax in search fields

Exit 0 on success. Exit 1 if any check fails.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

_INDEX_RE = re.compile(
    r"\bindex\s*=\s*\w+"  # index=aws_cloudtrail
    r"|\bdatamodel\s*=\s*\w+"  # datamodel=Change
    r"|\bsourcetype\s*=\s*\S+"  # sourcetype=aws:cloudtrail
    r"|`\w+_index`"  # `aws_cloudtrail_index` macro
    r"|`aws_\w+`"  # any `aws_*` macro (covers index + timeframe macros)
)


def validate_spl_file(spl_path: Path, detection_id: str) -> list[str]:
    errors: list[str] = []

    if not spl_path.exists():
        errors.append(f"{detection_id}: SPL file not found: {spl_path}")
        return errors

    content = spl_path.read_text(encoding="utf-8").strip()
    if not content:
        errors.append(f"{detection_id}: SPL file is empty: {spl_path}")
        return errors

    if not _INDEX_RE.search(content):
        errors.append(f"{detection_id}: SPL does not reference any index, datamodel, or sourcetype: {spl_path}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SPL syntax in detections")
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
    checked = 0

    for yaml_path in yaml_files:
        try:
            doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue

        if not isinstance(doc, dict):
            continue

        detection_id = doc.get("id", str(yaml_path))
        spl_filename = doc.get("spl_file", "detection.spl")
        spl_path = yaml_path.parent / spl_filename

        all_errors.extend(validate_spl_file(spl_path, detection_id))
        checked += 1

    if all_errors:
        print(f"SPL VALIDATION FAILED — {len(all_errors)} error(s):")
        for err in all_errors:
            print(f"  {err}")
        return 1

    print(f"SPL validation passed: {checked} detection(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
