# CDET-010 — Edge Case

**Purpose:** Test the exact threshold boundaries — exactly 100 estimated objects deleted (fires) vs. 99 (does not), and exactly 20 delete events (fires) vs. 19 (does not).

## Scenario: Exactly 100 Estimated Objects Deleted (Should Fire)

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/boundary-tester
- 2 DeleteObjects calls:
  - Call 1: 50 objects
  - Call 2: 50 objects
- estimated_objects_deleted: 100 (exactly at threshold)
- total_delete_events: 2 (below 20 threshold, but objects threshold met)

### Expected Result
- Detection fires: YES (>= 100)
- Verify SPL uses >= not > for the estimated_objects_deleted threshold

## Scenario: 99 Estimated Objects and 19 Delete Events (Should NOT Fire)

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/boundary-tester-2
- 19 DeleteObject calls, each deleting one object + one failed call
- estimated_objects_deleted: 99 (one below objects threshold)
- total_delete_events: 19 (one below event threshold)

### Expected Result
- Detection fires: NO
- Both thresholds are below the firing condition

## Scenario: Exactly 20 Delete Events, 19 Objects Deleted (Should Fire via Event Count)

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/boundary-tester-3
- 20 DeleteObject calls (some returning AccessDenied, some deleting 1 object each)
- total_delete_events: 20 (exactly at event threshold)
- estimated_objects_deleted: 19 (below object threshold, but event threshold met)

### Expected Result
- Detection fires: YES (total_delete_events threshold is an OR condition with estimated_objects_deleted)
- Verify SPL applies OR logic between the two threshold conditions

## Scenario: DeleteBucket (Entire Bucket Deletion)

### Event Details
- eventName: DeleteBucket
- principal_arn: arn:aws:iam::123456789012:user/attacker
- requestParameters.bucketName: prod-data-bucket
- Bucket contained ~10,000 objects (inferred from prior inventory)

### Expected Result
- Detection fires: YES (if DeleteBucket is included in the detection scope)
- Document whether DeleteBucket is included as a delete_operations type
- estimated_objects_deleted may be 0 or undefined for bucket deletion (no per-object count)
- If estimated_objects_deleted is 0 and total_delete_events is 1 (below thresholds), this is a detection gap

## Pass Criteria
- Confirm detection fires at exactly 100 estimated objects
- Confirm detection fires at exactly 20 delete events (OR condition)
- Confirm detection does NOT fire at 99 objects + 19 events
- Document DeleteBucket handling and any gap in estimated_objects_deleted for bucket-level deletion
