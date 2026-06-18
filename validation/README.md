# Detection Validation Framework

## Overview

The validation framework runs each detection's test cases against sample NDJSON data to verify:

1. **Positive test** — the detection fires when it should
2. **Negative test** — the detection does NOT fire on suppressed/benign data
3. **Edge test** — boundary conditions behave correctly

The heuristic validator (`validator.py`) mirrors the SPL detection logic in Python. It is NOT a Splunk replacement — its purpose is pre-ingestion verification of sample data quality and detection logic correctness.

For true Splunk validation, load the sample data into Splunk and run the SPL queries directly.

---

## Directory Structure

```
validation/
├── __init__.py
├── schema.py           — Dataclasses: TestCase, ValidationResult, FieldAssertion
├── validator.py        — Main runner: load test cases → evaluate → report
├── README.md           — This file
└── test_cases/
    ├── CDET-001_iam_user_created_outside_pipeline/
    │   ├── expected_alert.json
    │   ├── positive_case.md
    │   ├── negative_case.md
    │   ├── edge_case.md
    │   └── checklist.md
    ├── CDET-002_*/
    │   └── ...
    └── CDET-014_*/
        └── ...
```

---

## Quick Start

```bash
# Run validation for a single detection
python -m validation.validator --detection CDET-001

# Run all detections
python -m validation.validator --all

# Run all and save report
python -m validation.validator --all --output-dir data/validation_results/
```

---

## Validation Workflow

```
1. Sample data in sample_logs/ (NDJSON)
        ↓
2. validator.py loads events from sample file
        ↓
3. Heuristic detection logic evaluates each event
        ↓
4. Compares output to expected_alert.json
        ↓
5. Reports PASS/FAIL per field assertion
        ↓
6. Writes JSON report to data/validation_results/
        ↓
7. Engineer loads same sample data into Splunk
        ↓
8. Runs SPL detection and compares to expected_alert.json
        ↓
9. Manual sign-off per checklist.md
        ↓
10. Update coverage_matrix.md status: Testing → Active
```

---

## Adding a New Test Case

1. Create `validation/test_cases/CDET-XXX_<name>/`
2. Write `expected_alert.json` with all output fields from the SPL `| table` statement
3. Write `positive_case.md`, `negative_case.md`, `edge_case.md`, `checklist.md`
4. Add sample NDJSON to `sample_logs/cloudtrail/malicious/CDET-XXX_*.ndjson`
5. Run `python -m validation.validator --detection CDET-XXX`

---

## Report Format

Reports are written to `data/validation_results/validation_run_<timestamp>.json`:

```json
{
  "run_id": "a1b2c3d4",
  "run_timestamp": "2024-01-15T15:00:00",
  "detections_tested": 14,
  "detections_passed": 12,
  "detections_failed": 2,
  "detections_skipped": 0,
  "coverage_percent": 85.7,
  "results": [
    {
      "detection_id": "CDET-001",
      "positive_result": {"result": "PASS", ...},
      "negative_result": {"result": "PASS", ...},
      "edge_result": null
    }
  ]
}
```

---

## Promotion Criteria

A detection is promoted from **Testing** to **Active** when:

| Requirement | Description |
|-------------|-------------|
| Positive test passes | Detection fires on malicious sample data |
| Negative test passes | Detection is suppressed on benign/approved data |
| FP rate < 5% | After 14-day soak on production CloudTrail |
| Splunk SPL validated | Query runs without parse errors |
| Second review | Detection reviewed by a second engineer |
| Lookups populated | All suppression lookup CSVs are populated |

See full criteria in [`docs/detection_engineering/tuning_guidelines.md`](../docs/detection_engineering/tuning_guidelines.md).
