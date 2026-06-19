#!/usr/bin/env python3
"""
check_detection_ids.py — Verify that every detection.yaml has a unique ID
and that the ID matches the CDET-NNN format.

Exit 0 if all IDs are unique and well-formed. Exit 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

_ID_RE = re.compile(r"^CDET-\d{3}$")


def main() -> int:
    root = Path("detections")
    yaml_files = sorted(root.rglob("detection.yaml"))
    if not yaml_files:
        print(f"ERROR: no detection.yaml files found under {root}", file=sys.stderr)
        return 1

    id_to_files: dict[str, list[str]] = defaultdict(list)
    errors: list[str] = []

    for path in yaml_files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path}: YAML parse error: {exc}")
            continue

        if not isinstance(doc, dict):
            errors.append(f"{path}: expected mapping at top level")
            continue

        detection_id = doc.get("id", "")
        if not detection_id:
            errors.append(f"{path}: missing 'id' field")
            continue

        if not _ID_RE.match(str(detection_id)):
            errors.append(f"{path}: id '{detection_id}' does not match CDET-NNN format")

        id_to_files[str(detection_id)].append(str(path))

    # Check uniqueness
    for detection_id, files in id_to_files.items():
        if len(files) > 1:
            errors.append(f"Duplicate detection ID '{detection_id}' in: {files}")

    if errors:
        print(f"DETECTION ID CHECK FAILED — {len(errors)} error(s):")
        for err in errors:
            print(f"  {err}")
        return 1

    print(f"Detection ID check passed: {len(yaml_files)} detection(s), all IDs unique and well-formed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
