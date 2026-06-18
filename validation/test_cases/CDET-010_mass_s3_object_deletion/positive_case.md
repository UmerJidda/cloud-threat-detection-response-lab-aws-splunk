# CDET-010 — Positive Test Case

**Purpose:** Verify the detection fires when estimated_objects_deleted >= 100 OR total_delete_events >= 20 within the lookback window.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-010_mass_s3_deletion.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — Large Batch Deletion (estimated_objects_deleted >= 100)
- eventName: DeleteObjects (batch delete API — each call can delete up to 1000 objects)
- principal_arn: arn:aws:iam::123456789012:user/attacker
- 3 DeleteObjects calls, each deleting approximately 500 objects
- estimated_objects_deleted: ~1500 (>= 100 threshold)
- total_delete_events: 3 (below 20 threshold, but estimated_objects_deleted threshold met)

### Scenario B — Frequent Single Deletions (total_delete_events >= 20)
- eventName: DeleteObject (single-object delete API)
- principal_arn: arn:aws:iam::123456789012:user/attacker
- 25 DeleteObject events targeting different objects
- total_delete_events: 25 (>= 20 threshold)
- estimated_objects_deleted: 25 (below 100 threshold, but total_delete_events threshold met)

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "DeleteObjects",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "bucketName": "prod-data-bucket",
    "Delete": {
      "Objects": [
        {"Key": "file1.csv"},
        {"Key": "file2.csv"}
      ]
    }
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES for both scenarios
- Expected severity: critical
- Expected urgency: 1
- Expected ATT&CK fields populated: tactic=Impact, technique=T1485

## Pass Criteria
- Alert generated within one schedule period for both scenarios
- alert_title equals "[CDET-010] Mass S3 Object Deletion"
- principal_arn reflects the deleting user
- destruction_scope reflects scope (single-bucket or multi-bucket)
- total_delete_events reflects the API event count
- estimated_objects_deleted reflects the estimated total objects deleted
- buckets_targeted reflects the count of distinct buckets
- bucket_names_str lists the affected bucket names
- delete_operations lists the API names used
- Severity is critical and urgency is 1
