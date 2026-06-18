# CDET-014 — Negative Test Case

**Purpose:** Verify the detection does NOT fire for deletions from non-CloudTrail S3 buckets, for AWS service-initiated deletions, or for legitimate lifecycle expiration on CloudTrail buckets.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-014_non_cloudtrail_deletion.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Deletion from Non-CloudTrail S3 Bucket
- eventName: DeleteObjects
- bucket_name: application-data-bucket (NOT in cloudtrail_log_buckets lookup)
- principal: arn:aws:iam::123456789012:user/developer
- Should NOT fire

### Scenario B — AWS Service Lifecycle Expiration on CloudTrail Bucket
- eventName: DeleteObjects
- bucket_name: aws-cloudtrail-logs-123456789012 (in cloudtrail_log_buckets)
- userIdentity.type: AWSService
- invokedBy: s3.amazonaws.com (S3 lifecycle management)
- Should NOT fire (AWS service-initiated lifecycle deletions are expected and excluded by design)

### Scenario C — DeleteObject on CloudTrail Bucket by AWS CloudTrail Service
- eventName: DeleteObject
- bucket_name: aws-cloudtrail-logs-123456789012
- userIdentity.type: AWSService
- invokedBy: cloudtrail.amazonaws.com
- Should NOT fire

### Scenario D — GetObject from CloudTrail Bucket (Read, Not Delete)
- eventName: GetObject
- bucket_name: aws-cloudtrail-logs-123456789012
- Read-only operation, not a deletion
- Should NOT fire

## Expected Result
- Detection fires: NO for all four scenarios

## Pass Criteria
- Load all scenario events into the test index
- Confirm zero alerts for non-CloudTrail bucket deletions
- Confirm zero alerts for AWS service-initiated deletions on CloudTrail buckets
- Confirm zero alerts for read operations on CloudTrail buckets
- Verify cloudtrail_log_buckets lookup is correctly applied
- Verify AWSService principal type exclusion is working
