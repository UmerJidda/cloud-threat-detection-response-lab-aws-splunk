---
detection_id: CDET-014
detection_name: CloudTrail_Log_Deletion
tactic: Defense Evasion
technique: T1070.004
severity: critical
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-014 Validation Results

## Detection Overview
Detects when S3 objects under the AWSLogs/ prefix (where CloudTrail delivers its log files) are deleted. This is distinct from CDET-003 (which detects disabling the trail itself): an attacker who cannot disable the trail may instead delete the already-delivered log files from S3 to destroy forensic evidence of earlier activity. The detection requires S3 data event logging to be enabled on the CloudTrail delivery bucket.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-014_cloudtrail_log_deleted.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-014_non_cloudtrail_deletion.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-014_edge_s3_object_version_delete.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-014 | alert enrichment |
| severity | critical | detection YAML |
| tactic | Defense Evasion | ATT&CK context |
| technique | T1070.004 | ATT&CK context |
| eventName | DeleteObject | CloudTrail event |
| eventSource | s3.amazonaws.com | CloudTrail event |
| requestParameters.bucketName | (CloudTrail delivery bucket) | CloudTrail event |
| requestParameters.key | (key starting with AWSLogs/) | CloudTrail event |
| userIdentity.arn | (caller ARN) | CloudTrail event |
| errorCode | (absent — success) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-014_cloudtrail_log_deleted.ndjson")))
result = run_validation("CDET-014", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-014_non_cloudtrail_deletion.ndjson")))
result = run_validation("CDET-014", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-014]`

The SPL searches S3 data events for `eventName=DeleteObject` where `requestParameters.key` matches `AWSLogs/*`. The source bucket must also match the known CloudTrail delivery bucket name (configured as a lookup or macro). A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset contains deletions from a non-CloudTrail bucket and must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires when a DeleteObject event targets an AWSLogs/ key in the CloudTrail delivery bucket
- [ ] Negative test: detection does NOT fire when DeleteObject targets a non-AWSLogs key or a non-CloudTrail bucket
- [ ] Edge case: `CDET-014_edge_s3_object_version_delete.ndjson` — S3 DeleteObjectVersion (versioned delete) on an AWSLogs/ key; expected behaviour is **fire** because even deleting a specific version of a log file is evidence tampering, regardless of whether the current version remains
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-014_cloudtrail_log_file_deleted/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
