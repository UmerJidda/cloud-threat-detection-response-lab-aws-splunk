# CDET-009 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when S3 replication is configured to a same-account destination or to an approved partner account.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-009_same_account_replication.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Replication to Same-Account Destination
- eventName: PutBucketReplication
- Destination bucket ARN: arn:aws:s3:::backup-bucket-same-account
- Account field in replication rule: 123456789012 (same as source account)
- destination_account_id matches the current account
- Should NOT fire

### Scenario B — Replication to Approved Partner Account
- eventName: PutBucketReplication
- Destination account: 111222333444
- 111222333444 is present in the approved_replication_accounts lookup
- Should NOT fire

### Scenario C — DeleteBucketReplication (Removing Replication)
- eventName: DeleteBucketReplication
- Removing existing replication configuration, not creating new exfiltration
- Should NOT fire

## Expected Result
- Detection fires: NO for all three scenarios

## Pass Criteria
- Load all scenario events into the test index
- Run CDET-009 SPL manually in Splunk
- Confirm zero alerts for same-account and approved-partner scenarios
- Confirm detection does not fire for replication deletion events
- Verify approved_replication_accounts lookup is correctly applied
