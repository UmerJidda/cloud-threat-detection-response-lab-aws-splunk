---
detection_id: CDET-010
detection_name: Mass_S3_Object_Deletion
tactic: Impact
technique: T1485
severity: critical
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-010 Validation Results

## Detection Overview
Detects when a large number of S3 objects are deleted in a short time window, which is indicative of a data destruction or ransomware-style attack. The detection triggers when the number of DeleteObjects API calls or the total object count deleted exceeds a defined threshold within a sliding time window, and is especially significant when versioning or MFA-delete is not configured on the bucket.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-010_mass_s3_object_deletion.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-010_routine_deletion.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-010_edge_partial_prefix_deletion.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-010 | alert enrichment |
| severity | critical | detection YAML |
| tactic | Impact | ATT&CK context |
| technique | T1485 | ATT&CK context |
| eventName | DeleteObjects | CloudTrail event |
| eventSource | s3.amazonaws.com | CloudTrail event |
| requestParameters.bucketName | (target bucket) | CloudTrail event |
| deleted_object_count | >= threshold (e.g., 100 in 10 min) | aggregation |
| userIdentity.arn | (deleting principal ARN) | CloudTrail event |
| errorCode | (absent — success) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-010_mass_s3_object_deletion.ndjson")))
result = run_validation("CDET-010", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-010_routine_deletion.ndjson")))
result = run_validation("CDET-010", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-010]`

The SPL aggregates `eventName=DeleteObjects` events, summing the `requestParameters.delete.objects{}` array lengths per principal per 10-minute bucket. It fires when `sum(object_count) >= 100` within the window. A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset contains a routine S3 lifecycle cleanup of fewer than the threshold number of objects and must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires when cumulative deleted object count exceeds threshold in the time window
- [ ] Negative test: detection does NOT fire for routine low-volume S3 object deletion
- [ ] Edge case: `CDET-010_edge_partial_prefix_deletion.ndjson` — large deletion but scoped to a single key prefix (e.g., /tmp/ cleanup); expected behaviour is **fire** if the count threshold is met regardless of prefix, or **suppress** if prefix-based exemptions are configured — document which applies
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-010_mass_s3_object_deletion/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
