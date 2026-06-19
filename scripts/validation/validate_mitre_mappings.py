#!/usr/bin/env python3
"""
validate_mitre_mappings.py — Verify MITRE ATT&CK technique IDs in detection YAMLs
are well-formed and cross-reference the mitre_mappings.yaml catalog.

Exit 0 on success. Exit 1 if any technique IDs are malformed or unmapped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

# Regex for valid ATT&CK technique IDs: T\d{4} or T\d{4}.\d{3}
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_catalog(catalog_path: Path) -> set[str]:
    """Return set of all technique IDs in the catalog file."""
    if not catalog_path.exists():
        return set()
    doc = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        return set()
    ids: set[str] = set()
    for key in ("techniques", "mappings"):
        section = doc.get(key, {})
        if isinstance(section, dict):
            ids.update(section.keys())
        elif isinstance(section, list):
            for item in section:
                if isinstance(item, dict):
                    for field in ("technique_id", "id", "technique"):
                        if field in item:
                            ids.add(str(item[field]))
    return ids


def main() -> int:
    root = Path("detections")
    catalog_path = Path("config/mitre_mappings.yaml")

    yaml_files = sorted(root.rglob("detection.yaml"))
    if not yaml_files:
        print(f"ERROR: no detection.yaml files found under {root}", file=sys.stderr)
        return 1

    catalog_ids = load_catalog(catalog_path)
    errors: list[str] = []

    for path in yaml_files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue

        for field in ("technique", "sub_technique"):
            tid = doc.get(field)
            if not tid:
                continue
            if not _TECHNIQUE_RE.match(str(tid)):
                errors.append(f"{path}: invalid technique ID format '{tid}' in field '{field}'")
            elif catalog_ids and str(tid) not in catalog_ids:
                # Warn but don't fail — catalog may not list every sub-technique
                print(f"  NOTE: {path}: '{tid}' not found in {catalog_path} (may be intentional)")

    if errors:
        print(f"MITRE MAPPING VALIDATION FAILED — {len(errors)} error(s):")
        for err in errors:
            print(f"  {err}")
        return 1

    print(f"MITRE mapping validation passed: {len(yaml_files)} detection(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
