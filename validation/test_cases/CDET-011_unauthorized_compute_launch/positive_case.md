# CDET-011 — Positive Test Case

**Purpose:** Verify the detection fires when RunInstances or CreateFunction is called by a principal not in the approved compute launchers list, especially with suspicious instance types.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-011_unauthorized_compute_launch.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — Unauthorized EC2 Launch with Suspicious GPU Instance Type
- eventName: RunInstances
- principal_arn NOT in approved_compute_principals lookup
- instance_type: p3.16xlarge (GPU instance — suspicious, in suspicious_instance_types lookup)
- instance_count: 5
- is_suspicious_type: true
- abuse_category: crypto_mining

### Scenario B — Unauthorized Lambda Function Creation
- eventName: CreateFunction
- principal_arn NOT in approved_compute_principals lookup
- function_runtime: python3.9
- function_name: malicious-crypto-function

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "RunInstances",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "instanceType": "p3.16xlarge",
    "maxCount": 5,
    "minCount": 5
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
- Expected ATT&CK fields populated: tactic=Execution, technique=T1204.003

## Pass Criteria
- Alert generated within one schedule period
- alert_title equals "[CDET-011] Unauthorized Compute Resource Launch"
- eventName reflects RunInstances or CreateFunction
- principal_arn and principal_type correctly populated
- instance_type and instance_count populated for EC2 events
- is_suspicious_type correctly set based on instance type lookup
- abuse_category reflects the inferred abuse type
- function_name and function_runtime populated for Lambda events
- EC2 fields are null for Lambda events and vice versa
- Severity is high and urgency is 2
