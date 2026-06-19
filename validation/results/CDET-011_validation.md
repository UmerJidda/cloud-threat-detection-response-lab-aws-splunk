---
detection_id: CDET-011
detection_name: Unauthorized_Compute_Launch
tactic: Impact
technique: T1496
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-011 Validation Results

## Detection Overview
Detects when EC2 instances are launched by a principal that is not in the approved compute-provisioning group, or when the launched instance type, AMI, or region does not match approved baseline configurations. Attackers launch unauthorised compute to mine cryptocurrency, establish persistent command-and-control infrastructure, or pivot to other network segments.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-011_unauthorized_compute_launch.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-011_approved_launch.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-011_edge_approved_instance_type_approved_region.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-011 | alert enrichment |
| severity | high | detection YAML |
| tactic | Impact | ATT&CK context |
| technique | T1496 | ATT&CK context |
| eventName | RunInstances | CloudTrail event |
| eventSource | ec2.amazonaws.com | CloudTrail event |
| requestParameters.instanceType | (unapproved instance type, e.g., p3.16xlarge) | CloudTrail event |
| requestParameters.imageId | (AMI ID — check against approved list) | CloudTrail event |
| userIdentity.arn | (caller ARN — not in approved group) | CloudTrail event |
| awsRegion | (possibly unapproved region) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-011_unauthorized_compute_launch.ndjson")))
result = run_validation("CDET-011", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-011_approved_launch.ndjson")))
result = run_validation("CDET-011", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-011]`

The SPL searches for `eventName=RunInstances` where `userIdentity.arn` does NOT match the approved compute-provisioner role pattern OR where `requestParameters.instanceType` matches a blocklist of high-cost GPU/compute-optimised types. A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset uses an approved role launching a t3.micro and must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires when an unapproved principal or instance type triggers RunInstances
- [ ] Negative test: detection does NOT fire when an approved role launches an approved instance type in an approved region
- [ ] Edge case: `CDET-011_edge_approved_instance_type_approved_region.ndjson` — approved instance type and region but launched by an unapproved principal; expected behaviour is **fire** because principal validation takes precedence over resource attribute matching
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-011_unauthorized_ec2_instance_launch/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
