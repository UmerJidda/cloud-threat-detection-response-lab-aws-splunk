---
detection_id: CDET-008
detection_name: Excessive_API_Enumeration
tactic: Discovery
technique: T1580
severity: medium
validation_status: Testing
last_validated: 2026-06-19
---

# CDET-008 Validation Results

## Detection Overview
Detects when a single IAM principal issues an unusually high volume of read-only API calls (Describe*, List*, Get*) across multiple AWS services within a short time window. This burst pattern is characteristic of automated cloud environment enumeration tools such as Pacu, ScoutSuite, or Prowler being run by an attacker to map the environment prior to exploitation.

## Telemetry Source
- **Positive test:** sample_logs/cloudtrail/malicious/CDET-008_excessive_api_enumeration.ndjson
- **Benign test:** sample_logs/cloudtrail/benign/CDET-008_below_threshold.ndjson
- **Edge case:** sample_logs/cloudtrail/edge_cases/CDET-008_edge_lambda_api_burst.ndjson

## Expected Alert Fields
| Field | Expected Value | Source |
|---|---|---|
| detection_id | CDET-008 | alert enrichment |
| severity | medium | detection YAML |
| tactic | Discovery | ATT&CK context |
| technique | T1580 | ATT&CK context |
| userIdentity.arn | (enumerating principal ARN) | CloudTrail event |
| api_call_count | >= threshold (e.g., 50 in 5 min) | aggregation |
| distinct_services_count | >= 3 distinct AWS services | aggregation |
| eventName_sample | Describe*, List*, Get* | CloudTrail event |
| sourceIPAddress | (consistent caller IP) | CloudTrail event |
| time_window_start | (start of burst window) | aggregation |

## Python Heuristic Validation
```python
from scripts.cloudtrail_parser import CloudTrailParser
from scripts.detection_validator import run_validation, load_all_validators
from pathlib import Path

parser = CloudTrailParser()
validators = load_all_validators()

# Positive test — should fire
pos_events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-008_excessive_api_enumeration.ndjson")))
result = run_validation("CDET-008", pos_events, validators, should_fire=True, test_name="positive")
assert result.passed, result.summary

# Benign test — should NOT fire
neg_events = list(parser.parse_file(Path("sample_logs/cloudtrail/benign/CDET-008_below_threshold.ndjson")))
result = run_validation("CDET-008", neg_events, validators, should_fire=False, test_name="negative")
assert result.passed, result.summary
```

## Splunk SPL Validation
Reference the exact search stanza name from splunk/savedsearches/detection_validation.conf:

`[CDET-ValidatePositive-008]`

The SPL uses a stats count by `userIdentity.arn` over a 5-minute bucket, filtering for `eventName` matching `Describe*`, `List*`, or `Get*`. It alerts when `count >= 50` AND `dc(eventSource) >= 3`. A result count >= 1 on the malicious dataset constitutes PASS. The benign dataset contains fewer than the threshold number of enumeration calls and must return 0 results.

## Pass Criteria
- [ ] Positive test: detection fires when enumeration burst exceeds count and service diversity thresholds
- [ ] Negative test: detection does NOT fire when API call volume is below the threshold (normal operations)
- [ ] Edge case: `CDET-008_edge_lambda_api_burst.ndjson` — Lambda function performing legitimate configuration checks at startup generates a burst of Describe* calls; expected behaviour is **suppress** if the principal is in the known-automation allowlist, **fire** if not — document the allowlist check
- [ ] All expected alert fields present and correct
- [ ] No errors in enrichment_errors field

## Validation Status
**Current status: Testing** — all telemetry, logic, and SPL exist; pending deployment to Splunk instance.

## Investigation Workflow
On alert, consult playbooks/CDET-008_api_enumeration_reconnaissance/:
- triage.md — first 10-minute response
- investigation.md — technical deep-dive
- containment.md — stop the attack
- recovery.md — restore and harden
