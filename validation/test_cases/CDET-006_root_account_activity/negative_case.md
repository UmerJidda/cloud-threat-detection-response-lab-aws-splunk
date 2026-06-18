# CDET-006 — Negative Test Case

**Purpose:** Verify the detection does NOT fire for non-root principal types making the same API calls.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-006_non_root_activity.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — IAMUser Makes Same API Call
- eventName: CreateUser
- userIdentity.type: IAMUser (NOT Root)
- userIdentity.arn: arn:aws:iam::123456789012:user/admin-user
- Should NOT fire (CDET-001 handles this, not CDET-006)

### Scenario B — AssumedRole Makes Same API Call
- eventName: CreateUser
- userIdentity.type: AssumedRole (NOT Root)
- Should NOT fire

### Scenario C — AWS Service Makes API Call
- eventName: CreateUser
- userIdentity.type: AWSService
- Should NOT fire

### Scenario D — Federated Identity
- eventName: ListUsers
- userIdentity.type: FederatedUser
- Should NOT fire

## Expected Result
- Detection fires: NO for all scenarios (only fires on Root type)

## Pass Criteria
- Load all scenario events into the test index
- Run CDET-006 SPL manually in Splunk
- Confirm zero alerts for all non-Root principal types
- Verify the SPL filter on userIdentity.type = "Root" is exact match
- Confirm no wildcard matching that could catch AssumedRole or other types
