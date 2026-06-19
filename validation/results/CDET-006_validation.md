---
detection_id: CDET-006
detection_name: root_account_activity
tactic: Initial Access
technique: T1078.004
severity: critical
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-006 Validation Results

## Detection Overview
Detects any API call or console action made by the AWS root account. Root account usage is a high-fidelity signal because best practice mandates that the root user never be used for routine operations; any root activity therefore indicates either a serious misconfiguration or an active compromise of the account's most privileged credential.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-006_root_account_activity.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-006_non_root_activity.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-006_edge_root_account_read_only.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-006 | alert enrichment |
| severity | critical | detection YAML |
| tactic | Initial Access | ATT&CK context |
| technique | T1078.004 | ATT&CK context |
| userIdentity.type | Root | CloudTrail event |
| userIdentity.accountId | (AWS account ID) | CloudTrail event |
| eventName | (any — all root actions flagged) | CloudTrail event |
| eventSource | (any AWS service) | CloudTrail event |
| sourceIPAddress | (caller IP) | CloudTrail event |
| userAgent | (console or API client string) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-006_root_account_activity.ndjson")))
result = run_validation("CDET-006", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-006_non_root_activity.ndjson")))
result = run_validation("CDET-006", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-006]`

The SPL searches for `userIdentity.type=Root` across all eventNames. Any result on the malicious dataset constitutes PASS. The benign dataset contains only IAMUser and AssumedRole events and must return 0 results. This detection has no allowlist — all root activity is alerted without exception.

## Pass Criteria
- [ ] Positive test: detection fires on any event with userIdentity.type=Root
- [ ] Negative test: detection does NOT fire on non-root IAM or role activity
- [ ] Edge case: `CDET-006_edge_root_account_read_only.ndjson` — root account performs a read-only action (e.g., GetAccountSummary); expected behaviour is **fire** because even read-only root usage is forbidden and may indicate reconnaissance by a compromised root credential
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-006_root_account_activity/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
