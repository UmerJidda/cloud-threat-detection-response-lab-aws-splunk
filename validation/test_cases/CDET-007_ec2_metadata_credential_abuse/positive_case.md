# CDET-007 — Positive Test Case

**Purpose:** Verify the detection fires when EC2 instance role credentials are used from an external IP address, or when a GuardDuty InstanceCredentialExfiltration finding is present.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-007_metadata_credential_abuse.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — EC2 Role Used from External IP
- userIdentity.type: AssumedRole
- userIdentity.sessionContext.sessionIssuer.type: Role
- session_issuer_arn matches an EC2 instance role (not a user-assumed role)
- sourceIPAddress: 203.0.113.55 (NOT an AWS IP range or known EC2 internal IP)
- instance_id extracted from the assumed-role session ARN or EC2 metadata
- detection_source: CloudTrail

### Scenario B — GuardDuty InstanceCredentialExfiltration Finding
- GuardDuty finding type: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
- finding correlates to an EC2 instance role
- detection_source: GuardDuty

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "DescribeInstances",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/WebAppRole/i-0abcdef1234567890",
    "accountId": "123456789012",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "arn": "arn:aws:iam::123456789012:role/WebAppRole",
        "principalId": "AROAIOSFODNN7EXAMPLE"
      }
    }
  },
  "sourceIPAddress": "203.0.113.55",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES for both scenarios
- Expected severity: high
- Expected urgency: 2
- Expected ATT&CK fields populated: tactic=Credential Access, technique=T1552.005

## Pass Criteria
- Alert generated within one schedule period for both scenarios
- alert_title equals "[CDET-007] EC2 Metadata Credential Abuse"
- detection_source correctly reflects "CloudTrail" or "GuardDuty"
- principal_arn contains the assumed-role session ARN
- instance_id correctly extracted from session ARN or EC2 metadata
- session_issuer_arn reflects the underlying EC2 role
- event_source_ip reflects the external IP
- Severity is high and urgency is 2
