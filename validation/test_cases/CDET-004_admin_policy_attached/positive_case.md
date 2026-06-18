# CDET-004 — Positive Test Case

**Purpose:** Verify the detection fires when an admin-level policy is attached to an IAM principal or when an inline policy with wildcard permissions is applied.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-004_admin_policy_attached.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — Attach Managed Admin Policy to User
- eventName: AttachUserPolicy
- requestParameters.policyArn: arn:aws:iam::aws:policy/AdministratorAccess
- is_wildcard_inline: false
- policy_risk_level: critical

### Scenario B — Attach Admin Policy to Role
- eventName: AttachRolePolicy
- requestParameters.policyArn: arn:aws:iam::aws:policy/AdministratorAccess
- is_wildcard_inline: false
- policy_risk_level: critical

### Scenario C — PutUserPolicy with Wildcard Resource and Action
- eventName: PutUserPolicy
- requestParameters.policyDocument contains: "Action": "*", "Resource": "*", "Effect": "Allow"
- is_wildcard_inline: true
- policy_risk_level: critical

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "AttachUserPolicy",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "userName": "victim",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
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
- Expected ATT&CK fields populated: tactic=Privilege Escalation, technique=T1078.004

## Pass Criteria
- Alert generated within one schedule period for all scenarios
- alert_title equals "[CDET-004] Admin Policy Attached to Principal"
- attacher_arn reflects the acting principal
- target_principal is correctly extracted from requestParameters (userName or roleName)
- policy_arn populated for managed policy scenarios
- is_wildcard_inline correctly reflects inline wildcard scenario
- policy_risk_level is "critical" for all trigger scenarios
- Severity is critical and urgency is 1
