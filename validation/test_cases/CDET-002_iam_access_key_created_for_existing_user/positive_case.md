# CDET-002 — Positive Test Case

**Purpose:** Verify the detection fires when an IAM access key is created for a different user (cross-user) or for a privileged user.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-002_iam_access_key_created.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — Cross-User Key Creation
- eventName: CreateAccessKey
- userIdentity.arn (creator): arn:aws:iam::123456789012:user/attacker
- requestParameters.userName (key owner): admin-service-account
- creator != key owner → is_cross_user = true

### Scenario B — Key Created for Privileged User
- eventName: CreateAccessKey
- requestParameters.userName: admin-service-account
- admin-service-account is present in the privileged_users lookup
- is_for_privileged_user = true
- creator may equal key owner in this scenario

## Sample Event Fields
```json
{
  "eventName": "CreateAccessKey",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "userName": "admin-service-account"
  },
  "responseElements": {
    "accessKey": {
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "status": "Active"
    }
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
- Expected ATT&CK fields populated: tactic=Persistence, technique=T1098.001

## Pass Criteria
- Alert is generated within one schedule period
- alert_title equals "[CDET-002] IAM Access Key Created for Existing User"
- creator_arn matches the userIdentity.arn
- key_owner_name matches requestParameters.userName
- new_access_key_id is populated from responseElements
- is_cross_user is "true" when creator differs from key owner
- is_for_privileged_user is "true" when key_owner_name is in privileged_users lookup
- Both scenarios independently trigger the detection
