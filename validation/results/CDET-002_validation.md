---
detection_id: CDET-002
detection_name: iam_access_key_created_for_existing_user
tactic: Persistence
technique: T1098.001
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-002 Validation Results

## Detection Overview
Detects when an IAM access key is created for a user account other than the caller's own account, which is a strong indicator that an attacker is adding a persistent backdoor credential to an existing identity. Legitimate key rotation typically targets only the caller's own user.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-002_iam_access_key_created_for_existing_user.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-002_self_key_creation.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-002_edge_key_rotation_same_day.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-002 | alert enrichment |
| severity | high | detection YAML |
| tactic | Persistence | ATT&CK context |
| technique | T1098.001 | ATT&CK context |
| eventName | CreateAccessKey | CloudTrail event |
| eventSource | iam.amazonaws.com | CloudTrail event |
| requestParameters.userName | (target user, differs from caller) | CloudTrail event |
| userIdentity.userName | (caller username or role) | CloudTrail event |
| sourceIPAddress | (non-AWS IP or unexpected IP) | CloudTrail event |
| responseElements.accessKey.status | Active | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-002_iam_access_key_created_for_existing_user.ndjson")))
result = run_validation("CDET-002", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-002_self_key_creation.ndjson")))
result = run_validation("CDET-002", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-002]`

The SPL searches for `eventName=CreateAccessKey` where `requestParameters.userName != userIdentity.userName`. A result count >= 1 on the malicious dataset constitutes PASS. For the negative test, assert result count = 0 on the benign dataset (self-rotation case where both usernames match).

## Pass Criteria
- [ ] Positive test: detection fires when caller creates a key for a different user
- [ ] Negative test: detection does NOT fire when caller rotates their own key
- [ ] Edge case: `CDET-002_edge_key_rotation_same_day.ndjson` — two keys created for the same user within minutes; expected behaviour is **fire** if the second key targets a different principal, **suppress** if it is the same user performing same-day rotation — document the threshold used
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-002_access_key_created_for_other_user/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
