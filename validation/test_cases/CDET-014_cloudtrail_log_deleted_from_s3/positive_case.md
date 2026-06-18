# CDET-014 — Positive Test Case

**Purpose:** Verify the detection fires when CloudTrail log files are deleted from their S3 delivery bucket by a non-AWS-service principal.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-014_cloudtrail_logs_deleted.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — Bulk Log Deletion via DeleteObjects
- eventName: DeleteObjects
- bucket_name: aws-cloudtrail-logs-123456789012 (in cloudtrail_log_buckets lookup)
- principal is NOT an AWS service (userIdentity.type != AWSService)
- object_key: AWSLogs/123456789012/CloudTrail/us-east-1/2024/01/15/ (CloudTrail log prefix)
- deletion_type: bulk_log_deletion
- estimated_logs_deleted: 48 (number of objects in Delete request)

### Scenario B — Single Log File Deletion via DeleteObject
- eventName: DeleteObject
- bucket_name: aws-cloudtrail-logs-123456789012 (in cloudtrail_log_buckets lookup)
- object_key: AWSLogs/123456789012/CloudTrail/us-east-1/2024/01/15/123456789012_CloudTrail_us-east-1_20240115T143215Z_abc123.json.gz
- deletion_type: single_log_deletion
- estimated_logs_deleted: 1

### Scenario C — Entire CloudTrail Bucket Deleted
- eventName: DeleteBucket
- bucket_name: aws-cloudtrail-logs-123456789012 (in cloudtrail_log_buckets lookup)
- deletion_type: bucket_deletion
- estimated_logs_deleted: null (unknown — entire bucket)

## Expected Result
- Detection fires: YES for all three scenarios
- Expected severity: critical
- Expected urgency: 1
- Expected ATT&CK fields populated: tactic=Defense Evasion, technique=T1070.004

## Pass Criteria
- Alert generated within one schedule period for all scenarios
- alert_title equals "[CDET-014] CloudTrail Log Deleted from S3"
- deletion_type correctly categorizes the deletion event
- bucket_name matched against cloudtrail_log_buckets lookup
- trail_name correctly derived from the bucket name or object key prefix
- object_key populated for single-object and bulk-object deletions
- estimated_logs_deleted reflects the object count where applicable
- Severity is critical and urgency is 1 for all scenarios
