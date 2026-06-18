# CDET-006 — Positive Test Case

**Purpose:** Verify the detection fires on ANY API call made by the root account (userIdentity.type = Root).

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-006_root_account_activity.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions
- userIdentity.type: Root
- ANY eventName (no filter on specific API calls)
- mfa_used: derived from userIdentity.sessionContext.attributes.mfaAuthenticated

## Sample Events (Multiple Scenarios)

### Scenario A — Root Creates IAM User
```json
{
  "eventName": "CreateUser",
  "userIdentity": {
    "type": "Root",
    "arn": "arn:aws:iam::123456789012:root",
    "accountId": "123456789012"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

### Scenario B — Root Calls Billing API
```json
{
  "eventName": "ViewBilling",
  "userIdentity": {
    "type": "Root",
    "arn": "arn:aws:iam::123456789012:root",
    "accountId": "123456789012"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1"
}
```

### Scenario C — Root Console Sign-In
```json
{
  "eventName": "ConsoleLogin",
  "userIdentity": {
    "type": "Root",
    "arn": "arn:aws:iam::123456789012:root"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1"
}
```

## Expected Result
- Detection fires: YES for ALL root events regardless of eventName
- Expected severity: critical
- Expected urgency: 1
- Expected ATT&CK fields populated: tactic=Privilege Escalation, technique=T1078.004

## Pass Criteria
- Alert generated for every root event (no event name filtering)
- alert_title equals "[CDET-006] Root Account Activity"
- root_action_category correctly categorizes the event type (IAM Modification, Billing, Console Login, etc.)
- mfa_used correctly reflects session MFA status
- event_source_ip and region populated
- Severity is critical and urgency is 1 for all root events
