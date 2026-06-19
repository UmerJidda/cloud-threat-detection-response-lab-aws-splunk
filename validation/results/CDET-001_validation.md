---
detection_id: CDET-001
detection_name: iam_user_created_outside_pipeline
tactic: Persistence
technique: T1136.003
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-001 Validation Results

## Detection Overview
Detects when an IAM user is created via the AWS API from a principal or source IP that does not match the approved CI/CD pipeline identity. Adversaries create IAM users to establish persistent access that survives credential rotation of compromised keys.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-001_pipeline_createuser.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-001_edge_approved_role_unusual_region.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-001 | alert enrichment |
| severity | high | detection YAML |
| tactic | Persistence | ATT&CK context |
| technique | T1136.003 | ATT&CK context |
| eventName | CreateUser | CloudTrail event |
| eventSource | iam.amazonaws.com | CloudTrail event |
| requestParameters.userName | (any new username) | CloudTrail event |
| userIdentity.type | IAMUser or AssumedRole | CloudTrail event |
| sourceIPAddress | (non-pipeline IP range) | CloudTrail event |
| errorCode | (absent — success) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson")))
result = run_validation("CDET-001", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-001_pipeline_createuser.ndjson")))
result = run_validation("CDET-001", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-001]`

The SPL searches the `cloudtrail` index for `eventName=CreateUser` events where `userIdentity.sessionContext.sessionIssuer.arn` does not match the approved pipeline role ARN pattern. A result count >= 1 constitutes a PASS for the positive test. For the negative test, run against the benign index partition and assert result count = 0.

## Pass Criteria
- [ ] Positive test: detection fires on malicious NDJSON (CreateUser from non-pipeline principal)
- [ ] Negative test: detection does NOT fire on benign NDJSON (CreateUser from approved pipeline role)
- [ ] Edge case: `CDET-001_edge_approved_role_unusual_region.ndjson` — approved pipeline role calling CreateUser from an unusual AWS region; expected behaviour is **suppress** if principal matches allowlist, **fire** if region-based anomaly scoring is enabled — document which branch applies
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-001_iam_user_created_outside_pipeline/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
