# CDET-001 — Positive Test Case

**Purpose:** Verify the detection fires when an IAM user is created by a principal that is not in the approved pipeline or automation role lookups.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions
- eventName: CreateUser
- userIdentity.arn is NOT present in approved_iam_principals lookup
- userIdentity.arn is NOT present in automation_role_arns lookup
- userIdentity.type: IAMUser (not DeploymentPipelineRole or TerraformExecutionRole session)

## Sample Event Fields
```json
{
  "eventName": "CreateUser",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "userName": "backdoor-user"
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES
- Expected severity: high
- Expected urgency: 2
- Expected ATT&CK fields populated: tactic=Persistence, technique=T1136.003

## Pass Criteria
- Alert is generated within one schedule period (default: 1 hour)
- alert_title equals "[CDET-001] IAM User Created Outside Pipeline"
- creator_arn matches the non-pipeline userIdentity.arn
- new_user_name matches the requestParameters.userName
- mfa_used reflects whether MFA was present in the session
- event_source_ip matches the sourceIPAddress in the raw event
- All fields listed in expected_alert.json are present and non-null (except session_issuer_arn, which is null for IAMUser type)
