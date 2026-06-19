---
detection_id: CDET-013
detection_name: Security_Group_Public_Internet
tactic: Defense Evasion
technique: T1562.007
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-013 Validation Results

## Detection Overview
Detects when an EC2 security group inbound rule is created that allows unrestricted access from the public internet (0.0.0.0/0 or ::/0) on any port. Attackers modify security groups to open inbound access to compromised instances, enabling direct command-and-control channels or to disable perimeter controls that would otherwise block their activity.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-013_security_group_public_internet.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-013_scoped_sg_rule.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-013_edge_security_group_internal_only.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-013 | alert enrichment |
| severity | high | detection YAML |
| tactic | Defense Evasion | ATT&CK context |
| technique | T1562.007 | ATT&CK context |
| eventName | AuthorizeSecurityGroupIngress | CloudTrail event |
| eventSource | ec2.amazonaws.com | CloudTrail event |
| requestParameters.groupId | (security group ID) | CloudTrail event |
| requestParameters.ipPermissions.items[].ipRanges | 0.0.0.0/0 or ::/0 | CloudTrail event |
| requestParameters.ipPermissions.items[].fromPort | (opened port) | CloudTrail event |
| userIdentity.arn | (caller ARN) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-013_security_group_public_internet.ndjson")))
result = run_validation("CDET-013", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-013_scoped_sg_rule.ndjson")))
result = run_validation("CDET-013", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-013]`

The SPL searches for `eventName=AuthorizeSecurityGroupIngress` and checks `requestParameters` for IP range values matching `0.0.0.0/0` or `::/0`. A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset contains a rule scoped to a specific corporate IP CIDR and must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires when 0.0.0.0/0 or ::/0 is used as the ingress source
- [ ] Negative test: detection does NOT fire when the ingress rule is scoped to a specific CIDR (e.g., corporate egress range)
- [ ] Edge case: `CDET-013_edge_security_group_internal_only.ndjson` — rule uses a security group reference (sg-xxxxxxxx) rather than a CIDR, which does not expose the instance to the public internet; expected behaviour is **suppress** since no public IP range is referenced
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-013_security_group_rule_opens_world/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
