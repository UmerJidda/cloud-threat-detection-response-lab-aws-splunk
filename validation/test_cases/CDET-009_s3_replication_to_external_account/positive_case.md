# CDET-009 — Positive Test Case

**Purpose:** Verify the detection fires when S3 bucket replication is configured with a destination bucket in an external (non-owned) AWS account.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-009_s3_replication_external.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions
- eventName: PutBucketReplication
- Replication rule destination bucket ARN contains an account ID that is NOT the current account (123456789012)
- destination_account_id: 999888777666 (external)

## Sample Event Fields
```json
{
  "eventName": "PutBucketReplication",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "bucketName": "sensitive-data-bucket",
    "ReplicationConfiguration": {
      "Rule": {
        "Destination": {
          "Bucket": "arn:aws:s3:::attacker-exfil-bucket",
          "Account": "999888777666"
        }
      }
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
- Expected ATT&CK fields populated: tactic=Exfiltration, technique=T1537

## Pass Criteria
- Alert generated within one schedule period
- alert_title equals "[CDET-009] S3 Replication to External Account"
- principal_arn reflects the acting user
- source_bucket matches the requestParameters.bucketName
- destination_account_id correctly extracted from the replication rule
- destination_bucket_arn matches the destination bucket ARN
- event_source_ip and region populated
- Severity is high and urgency is 2
