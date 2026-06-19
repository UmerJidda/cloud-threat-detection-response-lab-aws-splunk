---
detection_id: CDET-007
detection_name: ec2_instance_metadata_credential_abuse
tactic: Credential Access
technique: T1552.005
severity: high
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-007 Validation Results

## Detection Overview
Detects when credentials obtained from the EC2 Instance Metadata Service (IMDS) are used to call AssumeRole from an IP address that is not in the EC2 instance's known private IP range. This pattern indicates that IMDS credentials were exfiltrated from the instance and are being used from an external attacker-controlled host.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-007_ec2_metadata_credential_abuse.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-007_ec2_internal_api_call.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-007_edge_imds_v2_token_request.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-007 | alert enrichment |
| severity | high | detection YAML |
| tactic | Credential Access | ATT&CK context |
| technique | T1552.005 | ATT&CK context |
| eventName | AssumeRole | CloudTrail event |
| eventSource | sts.amazonaws.com | CloudTrail event |
| userIdentity.type | AssumedRole | CloudTrail event |
| userIdentity.sessionContext.sessionIssuer.type | Role (EC2 instance profile) | CloudTrail event |
| sourceIPAddress | (external / non-RFC1918 IP) | CloudTrail event |
| userAgent | (aws-cli or SDK — not ec2-metadata) | CloudTrail event |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-007_ec2_metadata_credential_abuse.ndjson")))
result = run_validation("CDET-007", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-007_ec2_internal_api_call.ndjson")))
result = run_validation("CDET-007", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-007]`

The SPL searches for `eventName=AssumeRole` where the role ARN contains `:instance-profile/` or the session issuer type is EC2, and `sourceIPAddress` does not match RFC1918 address space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or AWS service addresses. A result count >= 1 on the malicious dataset constitutes PASS.

## Pass Criteria
- [ ] Positive test: detection fires when EC2 instance role credentials are used from an external IP
- [ ] Negative test: detection does NOT fire when the same EC2 role calls APIs from an internal VPC IP
- [ ] Edge case: `CDET-007_edge_imds_v2_token_request.ndjson` — IMDSv2 token PUT request followed by credential retrieval; expected behaviour is **suppress** if the subsequent API calls originate from a private IP; **fire** if the token is used externally
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-007_ec2_metadata_credential_abuse/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
