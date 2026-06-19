---
detection_id: CDET-003
detection_name: cloudtrail_logging_disabled
tactic: Defense Evasion
technique: T1562.008
severity: critical
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-003 Validation Results

## Detection Overview
Detects when CloudTrail logging is disabled or a trail is deleted, both of which are high-confidence indicators of an attacker attempting to blind defenders before performing additional malicious actions. The absence of audit logs is itself an attack signal and warrants immediate response.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-003_cloudtrail_logging_disabled.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-003_benign_updatetrail.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-003_edge_cloudtrail_update_not_disable.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-003 | alert enrichment |
| severity | critical | detection YAML |
| tactic | Defense Evasion | ATT&CK context |
| technique | T1562.008 | ATT&CK context |
| eventName | StopLogging or DeleteTrail | CloudTrail event |
| eventSource | cloudtrail.amazonaws.com | CloudTrail event |
| requestParameters.name | (trail ARN or name) | CloudTrail event |
| userIdentity.arn | (caller ARN) | CloudTrail event |
| awsRegion | (affected region) | CloudTrail event |
| errorCode | (absent — success) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-003_cloudtrail_logging_disabled.ndjson")))
result = run_validation("CDET-003", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-003_benign_updatetrail.ndjson")))
result = run_validation("CDET-003", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-003]`

The SPL searches for `eventSource=cloudtrail.amazonaws.com` AND `(eventName=StopLogging OR eventName=DeleteTrail)`. A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset contains only `UpdateTrail` events (e.g., changing S3 bucket destination), which must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires on StopLogging or DeleteTrail event
- [ ] Negative test: detection does NOT fire on benign UpdateTrail (e.g., log file prefix change)
- [ ] Edge case: `CDET-003_edge_cloudtrail_update_not_disable.ndjson` — UpdateTrail that changes settings but does not disable logging; expected behaviour is **suppress** since logging remains active
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-003_cloudtrail_logging_disabled/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
