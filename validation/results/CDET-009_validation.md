---
detection_id: CDET-009
detection_name: S3_Replication_External_Account
tactic: Exfiltration
technique: T1537
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-009 Validation Results

## Detection Overview
Detects when an S3 bucket replication rule is configured to replicate objects to a destination bucket in an AWS account that is not owned by the organisation. This is a stealthy long-running exfiltration technique: once configured, all new and existing objects are silently copied to an attacker-controlled bucket without further API calls.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-009_s3_replication_external_account.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-009_same_account_replication.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-009_edge_replication_same_org.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-009 | alert enrichment |
| severity | high | detection YAML |
| tactic | Exfiltration | ATT&CK context |
| technique | T1537 | ATT&CK context |
| eventName | PutBucketReplication | CloudTrail event |
| eventSource | s3.amazonaws.com | CloudTrail event |
| requestParameters.bucketName | (source bucket name) | CloudTrail event |
| destination_account_id | (external account ID extracted from rule) | parsed from requestParameters |
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
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-009_s3_replication_external_account.ndjson")))
result = run_validation("CDET-009", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-009_same_account_replication.ndjson")))
result = run_validation("CDET-009", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-009]`

The SPL searches for `eventName=PutBucketReplication` and parses the replication configuration XML/JSON from `requestParameters` to extract the destination bucket ARN. It extracts the account ID from the ARN and checks it against the approved account list. A result count >= 1 on the malicious dataset (external account destination) constitutes PASS.

## Pass Criteria
- [ ] Positive test: detection fires when replication destination is an external (unapproved) account
- [ ] Negative test: detection does NOT fire when replication destination is within the same account
- [ ] Edge case: `CDET-009_edge_replication_same_org.ndjson` — destination account is in the same AWS Organization but a different account ID; expected behaviour depends on whether the org account list is configured — **suppress** if the destination account is in the org allowlist, **fire** if only the exact account ID is checked
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-009_s3_replication_to_external_account/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
