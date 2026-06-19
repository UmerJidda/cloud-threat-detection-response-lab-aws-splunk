---
detection_id: CDET-005
detection_name: cross_account_role_trust_modified
tactic: Privilege Escalation
technique: T1484.002
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-005 Validation Results

## Detection Overview
Detects when an IAM role's trust policy is modified to allow assumption from an external AWS account ID that is not in the approved cross-account allowlist. Adversaries modify trust policies to enable lateral movement from accounts they control into the target environment without creating new identities.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-005_cross_account_role_trust_modified.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-005_same_account_trust.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-005_edge_same_account_trust_update.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-005 | alert enrichment |
| severity | high | detection YAML |
| tactic | Privilege Escalation | ATT&CK context |
| technique | T1484.002 | ATT&CK context |
| eventName | UpdateAssumeRolePolicy | CloudTrail event |
| eventSource | iam.amazonaws.com | CloudTrail event |
| requestParameters.roleName | (modified role name) | CloudTrail event |
| requestParameters.policyDocument | (JSON containing external account ARN) | CloudTrail event |
| userIdentity.arn | (caller ARN) | CloudTrail event |
| awsRegion | us-east-1 or equivalent | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-005_cross_account_role_trust_modified.ndjson")))
result = run_validation("CDET-005", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-005_same_account_trust.ndjson")))
result = run_validation("CDET-005", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-005]`

The SPL searches for `eventName=UpdateAssumeRolePolicy` and parses `requestParameters.policyDocument` to extract AWS account IDs from Principal ARNs. It flags any account ID that does not match the current account ID or the approved cross-account partner list. A result count >= 1 on the malicious dataset constitutes PASS.

## Pass Criteria
- [ ] Positive test: detection fires when trust policy references an unapproved external account
- [ ] Negative test: detection does NOT fire when trust update references only the same account (e.g., service principal or same-account role)
- [ ] Edge case: `CDET-005_edge_same_account_trust_update.ndjson` — trust policy updated to reference a different role within the same account; expected behaviour is **suppress** since no external account is introduced
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-005_cross_account_trust_modified/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
