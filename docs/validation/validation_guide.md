# Detection Validation Guide

## Overview

This guide describes how to validate each detection in the Cloud Threat Detection & Response Lab using the sample datasets and validation framework.

Validation proves three things:
1. The detection **fires** on malicious sample events (positive test)
2. The detection **does not fire** on suppressed/benign events (negative test)
3. The detection output **contains all required fields** at the correct values

---

## Validation Methods

### Method 1 — Python Heuristic Validator (offline)

The heuristic validator mirrors the SPL detection logic in Python. It does not require Splunk.

```bash
# Prerequisites
pip install structlog boto3

# Run all detections
python -m validation.validator --all --output-dir data/validation_results/

# Run a single detection
python -m validation.validator --detection CDET-001
```

**Output:**
```
  ✓ CDET-001 — positive case: PASS
  ✓ CDET-001 — negative case (suppression): PASS
  └─ CDET-001: ✓ Ready for promotion

  ✓ CDET-002 — positive case: PASS
  ✗ CDET-002 — negative case (suppression): FAIL
      → Expected NO alerts but got 1 (suppression may be incomplete)
  └─ CDET-002: ✗ Not ready for promotion

============================================================
Validation Run a1b2c3d4
Tested: 14  Passed: 13  Failed: 1
Coverage: 92.9%
============================================================
```

**Limitations:** The heuristic validator does not execute SPL. It validates that sample data contains the correct signals, not that the Splunk query is correctly written. Splunk validation (Method 2) is required before promotion.

---

### Method 2 — Splunk Validation (authoritative)

This is the authoritative validation method. The detection must fire correctly in Splunk before promotion.

#### Step 1: Load sample data into Splunk

```bash
# For each detection, load the malicious sample
/opt/splunk/bin/splunk add oneshot \
  sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson \
  -index aws_cloudtrail \
  -sourcetype aws:cloudtrail

# For CDET-007 GuardDuty branch
/opt/splunk/bin/splunk add oneshot \
  sample_logs/guardduty/malicious/CDET-007_instance_credential_exfiltration.ndjson \
  -index aws_security \
  -sourcetype aws:guardduty:finding
```

#### Step 2: Run the detection SPL

Open Splunk Search and run the detection query from `detections/<tactic>/CDET-XXX/detection.spl`. Extend the time range to cover when you loaded the sample data.

#### Step 3: Compare output to expected_alert.json

Open `validation/test_cases/CDET-XXX_<name>/expected_alert.json` and verify:
- All required fields are present
- `detection_id` matches
- `severity` matches
- `urgency` matches
- ATT&CK fields (`tactic`, `technique`, `technique_name`) are correct
- Detection-specific fields (e.g., `new_user_name`, `is_chained_assumption`) are populated

#### Step 4: Negative test

Load the benign sample data and verify the detection does NOT fire:

```bash
/opt/splunk/bin/splunk add oneshot \
  sample_logs/cloudtrail/benign/normal_iam_activity.ndjson \
  -index aws_cloudtrail \
  -sourcetype aws:cloudtrail
```

Confirm zero results from the detection SPL against the benign events.

---

## Validation Checklist Quick Reference

Each detection has a full checklist at `validation/test_cases/CDET-XXX_<name>/checklist.md`. The minimum gates for promotion are:

| Gate | Description |
|------|-------------|
| Positive test passes | Detection fires on malicious sample data in Splunk |
| Negative test passes | Detection suppressed on benign/approved data in Splunk |
| Expected fields present | All `expected_alert.json` fields appear in Splunk output |
| FP baseline complete | 14-day soak on production data; FP rate < 5% |
| Second review | A second engineer has reviewed the SPL |
| Lookups populated | All suppression lookup CSVs contain real environment data |

---

## Running Against Live AWS Data

After detections are promoted to Active in Splunk, they run continuously against live CloudTrail data collected by the AWS collectors.

To manually run a validation cycle against live data:

```bash
# 1. Collect recent CloudTrail events
python -m scripts.aws_collectors.collect_cli \
  --collector cloudtrail \
  --region us-east-1 \
  --output-dir data/collected/ \
  --lookback-hours 24

# 2. Load collected data into Splunk
/opt/splunk/bin/splunk add oneshot \
  data/collected/cloudtrail_*.ndjson \
  -index aws_cloudtrail \
  -sourcetype aws:cloudtrail:normalized

# 3. Run all detections and check for alerts in Splunk ES
```

---

## Validation Results

Validation run reports are stored in `data/validation_results/` (gitignored):

```
data/validation_results/
├── validation_run_20240115T150000.json
├── validation_run_20240116T090000.json
└── ...
```

Each report includes per-detection pass/fail, field assertion results, and overall coverage percentage. Share report summaries (not raw files) in PR descriptions when promoting detections.

---

## Troubleshooting

### Detection fires on negative test data
- Verify the suppression lookup CSV contains the test principal
- Confirm the lookup field name matches the SPL field name exactly
- Check if session_issuer_arn suppression is needed (AssumedRole sessions)

### Expected field is missing from alert output
- Verify the `| table` statement at the end of the SPL includes the field
- Check if the `| eval` earlier in the query computes the field correctly
- Confirm the field exists in the input event (check `requestParameters` structure)

### Heuristic validator reports SKIP
- Sample file not found — check the file path in `sample_logs/cloudtrail/malicious/`
- Confirm file naming matches pattern `CDET-XXX_*.ndjson`

### SPL macro not found
- Ensure `macros.conf` is installed in Splunk (see `docs/splunk/index_strategy.md`)
- Check the macro name matches exactly (case-sensitive)
