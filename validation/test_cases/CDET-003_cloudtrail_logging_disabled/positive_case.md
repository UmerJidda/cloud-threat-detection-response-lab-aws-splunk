# CDET-003 — Positive Test Case

**Purpose:** Verify the detection fires on any CloudTrail logging disruption event.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-003_cloudtrail_disabled.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — StopLogging
- eventName: StopLogging
- Any principal (non-pipeline)
- disable_reason: "StopLogging called directly"

### Scenario B — DeleteTrail
- eventName: DeleteTrail
- Any principal
- disable_reason: "Trail deleted"

### Scenario C — UpdateTrail (Log Degradation)
- eventName: UpdateTrail
- requestParameters contain: IsMultiRegionTrail=false OR IncludeGlobalServiceEvents=false OR EnableLogFileValidation=false
- disable_reason: "UpdateTrail degraded logging configuration"

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "StopLogging",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events-trail"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES for all three scenarios
- Expected severity: critical
- Expected urgency: 1
- Expected ATT&CK fields populated: tactic=Defense Evasion, technique=T1562.008

## Pass Criteria
- Alert is generated within one schedule period for each scenario
- alert_title equals "[CDET-003] CloudTrail Logging Disabled"
- disable_reason correctly reflects the event type
- trail_name and trail_arn are populated from the requestParameters
- principal_arn correctly reflects the acting user
- Severity is critical and urgency is 1 for all scenarios
