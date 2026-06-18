# CDET-005 — Positive Test Case

**Purpose:** Verify the detection fires when a role's trust policy is modified to allow an external (non-owned) AWS account to assume it, or when a new role is created with an external account in the trust.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-005_cross_account_role_trust.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — UpdateAssumeRolePolicy with External Account
- eventName: UpdateAssumeRolePolicy
- requestParameters.policyDocument contains a Principal with an account ID that is NOT the current account (123456789012)
- external_account_id: 999888777666

### Scenario B — CreateRole with External Account Trust
- eventName: CreateRole
- requestParameters.assumeRolePolicyDocument contains an external AWS account in Principal
- external_account_id: 999888777666

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "UpdateAssumeRolePolicy",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "roleName": "DataAccessRole",
    "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::999888777666:root\"},\"Action\":\"sts:AssumeRole\"}]}"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES for both scenarios
- Expected severity: high
- Expected urgency: 2
- Expected ATT&CK fields populated: tactic=Persistence, technique=T1098.003

## Pass Criteria
- Alert generated within one schedule period for both scenarios
- alert_title equals "[CDET-005] Cross-Account Role Trust Modified"
- principal_arn reflects the acting user
- role_name correctly extracted from requestParameters
- external_account_id correctly extracted from the trust policy Principal
- trust_policy_fragment contains the relevant trust policy snippet
- event_source_ip and region populated
