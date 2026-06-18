# CDET-014 — Edge Case

**Purpose:** Verify detection behavior when a CloudTrail log bucket is not in the lookup (newly created trail) and when an approved principal deletes logs from a CloudTrail bucket.

## Scenario: Newly Created CloudTrail Bucket Not Yet in Lookup

### Background
A new CloudTrail trail was created yesterday with a new delivery bucket (aws-cloudtrail-logs-123456789012-new-trail). The cloudtrail_log_buckets lookup has not been updated yet. An attacker deletes logs from this new bucket.

### Event Details
- eventName: DeleteObjects
- bucket_name: aws-cloudtrail-logs-123456789012-new-trail (NOT in cloudtrail_log_buckets)
- object_key: AWSLogs/123456789012/CloudTrail/us-west-2/2024/01/15/...
- principal_arn: arn:aws:iam::123456789012:user/attacker

### Expected Result
- Detection fires: NO (bucket not in lookup — this is a detection gap)
- Document the operational requirement: cloudtrail_log_buckets lookup must be updated whenever a new trail is created
- Recommend: CDET-003 (CloudTrail Logging Disabled) should be used as a complementary control
- Consider adding an auto-discovery mechanism that populates cloudtrail_log_buckets from DescribeTrails API responses

## Scenario: Authorized S3 Administrator Deletes Old CloudTrail Logs

### Event Details
- eventName: DeleteObjects
- bucket_name: aws-cloudtrail-logs-123456789012 (in cloudtrail_log_buckets)
- principal_arn: arn:aws:iam::123456789012:role/S3AdminRole
- object_key: AWSLogs/123456789012/CloudTrail/us-east-1/2020/01/15/ (4-year-old logs being archived)
- estimated_logs_deleted: 1440 (full day of 4-year-old logs)

### Expected Result
- Detection fires: YES (by design — any non-AWS-service deletion from CloudTrail bucket triggers the alert)
- Even authorized S3 admins should not be silently deleting CloudTrail logs
- This may generate a false positive for legitimate log retention management
- Recommend: add S3AdminRole to a cloudtrail_deletion_exceptions lookup for the retention management use case, and verify the suppression in the negative case
- If the organization has a log retention policy requiring deletion, document it and evaluate whether suppression is appropriate

## Scenario: DeleteObjects Request Targeting Non-Log-Path Objects in CloudTrail Bucket

### Event Details
- eventName: DeleteObjects
- bucket_name: aws-cloudtrail-logs-123456789012 (in cloudtrail_log_buckets)
- object_key: config/old-config.json (not a CloudTrail log path — no AWSLogs/ prefix)
- principal_arn: arn:aws:iam::123456789012:user/developer

### Expected Result
- Detection behavior depends on whether the SPL filters on the AWSLogs/ object key prefix or triggers on any deletion from the bucket
- If SPL uses bucket-only matching: fires (may be FP for non-log objects in the bucket)
- If SPL uses bucket + key prefix matching: does NOT fire (correct — non-log object)
- Document which approach is used and the trade-offs

## Pass Criteria
- Document the detection gap for newly created buckets not in the lookup
- Confirm the operational process for maintaining cloudtrail_log_buckets
- Confirm detection fires for authorized admin deletions (document FP potential)
- Document SPL behavior for non-log-path object deletions in the CloudTrail bucket
