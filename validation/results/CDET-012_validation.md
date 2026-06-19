---
detection_id: CDET-012
detection_name: Cross_Account_AssumeRole_Chain
tactic: Lateral Movement
technique: T1550.001
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-012 Validation Results

## Detection Overview
Detects multi-hop AssumeRole chains where a principal assumes a role in one account and then immediately uses those temporary credentials to assume another role in a different account. This hop-chaining pattern is a strong indicator of lateral movement through an AWS Organisation, as attackers traverse trust boundaries using a series of assumed roles to obscure their origin.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-012_cross_account_assumerole_chain.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-012_approved_assumerole.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-012_edge_single_hop_assumerole.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-012 | alert enrichment |
| severity | high | detection YAML |
| tactic | Lateral Movement | ATT&CK context |
| technique | T1550.001 | ATT&CK context |
| eventName | AssumeRole | CloudTrail event |
| eventSource | sts.amazonaws.com | CloudTrail event |
| userIdentity.type | AssumedRole | CloudTrail event |
| userIdentity.sessionContext.sessionIssuer.accountId | (intermediate hop account ID) | CloudTrail event |
| requestParameters.roleArn | (destination role in different account) | CloudTrail event |
| chain_depth | >= 2 | correlation logic |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-012_cross_account_assumerole_chain.ndjson")))
result = run_validation("CDET-012", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-012_approved_assumerole.ndjson")))
result = run_validation("CDET-012", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-012]`

The SPL correlates AssumeRole events by `userIdentity.principalId` session tokens, identifying cases where a session obtained via AssumeRole (userIdentity.type=AssumedRole) is then used to call AssumeRole again to a different account within a configurable time window (default: 15 minutes). A chain depth >= 2 with at least 2 distinct account IDs constitutes PASS. The benign dataset contains only single-hop, approved direct AssumeRole calls.

## Pass Criteria
- [ ] Positive test: detection fires on multi-hop cross-account AssumeRole chain (>= 2 hops, >= 2 accounts)
- [ ] Negative test: detection does NOT fire on a single direct AssumeRole from an approved baseline principal
- [ ] Edge case: `CDET-012_edge_single_hop_assumerole.ndjson` — single AssumeRole from Account A to Account B with no further chaining; expected behaviour is **suppress** for CDET-012 (chain depth = 1), though it may trigger CDET-005 if the trust policy is also new
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-012_cross_account_role_assumption/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
