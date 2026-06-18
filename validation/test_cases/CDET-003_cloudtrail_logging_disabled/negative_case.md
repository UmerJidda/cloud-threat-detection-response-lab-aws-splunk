# CDET-003 — Negative Test Case

**Purpose:** Verify the detection does NOT fire on benign CloudTrail UpdateTrail calls that do not degrade logging.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-003_benign_updatetrail.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — UpdateTrail That Enhances or Preserves Logging
- eventName: UpdateTrail
- requestParameters: IsMultiRegionTrail=true, IncludeGlobalServiceEvents=true, EnableLogFileValidation=true
- No log degradation fields present
- Should NOT fire — this is a legitimate configuration improvement

### Scenario B — UpdateTrail Changing Only the S3 Bucket (Logging Intact)
- eventName: UpdateTrail
- requestParameters: S3BucketName=new-cloudtrail-bucket
- IsMultiRegionTrail and IncludeGlobalServiceEvents not changed (remain true)
- Should NOT fire — logging capability is not degraded

### Scenario C — Unrelated CloudTrail API
- eventName: GetTrailStatus
- Any principal
- Read-only API call, not a logging disruption
- Should NOT fire

## Expected Result
- Detection fires: NO for all three scenarios

## Pass Criteria
- Load all three scenario events into the test index
- Run the CDET-003 SPL manually in Splunk
- Confirm zero alerts are generated
- Verify UpdateTrail degradation logic only triggers when disabling features (IsMultiRegionTrail=false, IncludeGlobalServiceEvents=false, or EnableLogFileValidation=false)
- Confirm read-only CloudTrail APIs are not in the detection scope
