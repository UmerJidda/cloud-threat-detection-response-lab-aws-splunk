# CDET-012 — Positive Test Case

**Purpose:** Verify the detection fires when AssumeRole is called targeting an unapproved external account, and escalates to critical severity for chained role assumptions spanning multiple accounts.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-012_cross_account_assumerole.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — Single Cross-Account AssumeRole to Unapproved Account
- eventName: AssumeRole
- principal_arn: arn:aws:iam::123456789012:user/attacker
- requestParameters.roleArn contains account 999888777666 (not in approved_assume_targets)
- is_chained_assumption: false
- Severity: high, Urgency: 2

### Scenario B — Chained AssumeRole Across Multiple Accounts
- eventName: AssumeRole (multiple events within the lookback window)
- Same principal assumes roles across 2+ distinct external accounts
- Event 1: assume role in account 999888777666
- Event 2: assume role in account 777666555444 (using credentials from Event 1)
- is_chained_assumption: true
- total_assumes: 3+, distinct_target_accounts: 2+
- Severity escalates to critical, Urgency: 1

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "AssumeRole",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::999888777666:role/TargetRole",
    "roleSessionName": "attacker-session"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES for both scenarios
- Scenario A: severity=high, urgency=2
- Scenario B: severity=critical, urgency=1
- Expected ATT&CK fields populated: tactic=Lateral Movement, technique=T1550.001

## Pass Criteria
- Alert generated within one schedule period for both scenarios
- alert_title equals "[CDET-012] Cross-Account AssumeRole Chain"
- principal_arn reflects the assuming principal
- is_chained_assumption correctly distinguishes single vs. chained scenarios
- total_assumes and distinct_target_accounts accurately reflect the role chain depth
- target_accounts_str and target_roles_str list all targeted accounts and roles
- Severity escalates to critical for chained assumptions
