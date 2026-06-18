# CDET-010 — Negative Test Case

**Purpose:** Verify the detection does NOT fire for routine S3 deletions below both thresholds or for approved principals performing bulk lifecycle operations.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-010_routine_deletion.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Small Batch Deletion Below Both Thresholds
- eventName: DeleteObjects
- principal_arn: arn:aws:iam::123456789012:user/developer
- 2 DeleteObjects calls, each deleting 10 objects
- estimated_objects_deleted: 20 (below 100 threshold)
- total_delete_events: 2 (below 20 threshold)
- Should NOT fire

### Scenario B — Single Object Deletion (Routine Maintenance)
- eventName: DeleteObject
- principal_arn: arn:aws:iam::123456789012:user/developer
- 5 DeleteObject calls
- total_delete_events: 5 (below 20 threshold)
- estimated_objects_deleted: 5 (below 100 threshold)
- Should NOT fire

### Scenario C — Approved Lifecycle Automation Principal
- eventName: DeleteObjects (bulk lifecycle cleanup)
- principal_arn: arn:aws:iam::123456789012:role/S3LifecycleRole
- total_delete_events: 50, estimated_objects_deleted: 5000
- S3LifecycleRole is in deletion_suppression_arns lookup
- Should NOT fire

### Scenario D — AWS S3 Lifecycle Service Deleting Objects
- eventName: DeleteObjects
- userIdentity.type: AWSService
- invokedBy: s3.amazonaws.com (lifecycle expiration)
- Should NOT fire (AWS service-initiated lifecycle deletions are expected)

## Expected Result
- Detection fires: NO for all four scenarios

## Pass Criteria
- Confirm zero alerts for all below-threshold and approved-principal scenarios
- Verify deletion_suppression_arns lookup is correctly applied
- Confirm AWS service-initiated deletions are excluded from the detection scope
