---
detection_id: CDET-004
detection_name: admin_policy_attached_to_principal
tactic: Privilege Escalation
technique: T1078.004
severity: critical
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-004 Validation Results

## Detection Overview
Detects when the AdministratorAccess managed policy (or any policy granting `*:*`) is attached to an IAM user or role outside of an approved change-management pipeline. This is a direct privilege escalation vector that grants full AWS account control to the targeted principal.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-004_admin_policy_attached.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-004_benign_policy_attach.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-004_edge_readonly_policy_attached.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-004 | alert enrichment |
| severity | critical | detection YAML |
| tactic | Privilege Escalation | ATT&CK context |
| technique | T1078.004 | ATT&CK context |
| eventName | AttachUserPolicy or AttachRolePolicy | CloudTrail event |
| eventSource | iam.amazonaws.com | CloudTrail event |
| requestParameters.policyArn | arn:aws:iam::aws:policy/AdministratorAccess | CloudTrail event |
| requestParameters.userName or roleName | (target principal name) | CloudTrail event |
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
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-004_admin_policy_attached.ndjson")))
result = run_validation("CDET-004", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-004_benign_policy_attach.ndjson")))
result = run_validation("CDET-004", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-004]`

The SPL searches for `(eventName=AttachUserPolicy OR eventName=AttachRolePolicy)` AND `requestParameters.policyArn=*AdministratorAccess*`. A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset attaches a scoped read-only policy and must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires when AdministratorAccess is attached outside pipeline
- [ ] Negative test: detection does NOT fire when a scoped, non-admin policy is attached via approved pipeline
- [ ] Edge case: `CDET-004_edge_readonly_policy_attached.ndjson` — a read-only policy attached outside the pipeline; expected behaviour is **suppress** for CDET-004 (which targets admin-level policies), but may trigger a lower-severity rule
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-004_admin_policy_attached_outside_pipeline/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
