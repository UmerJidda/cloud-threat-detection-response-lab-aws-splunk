# CDET-008 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when a principal exceeds total calls but not unique API threshold, or vice versa, or when a principal is in the suppression lookup.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-008_below_threshold.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — High Volume, Low Unique APIs (Monitoring Tool)
- principal_arn: arn:aws:iam::123456789012:user/monitoring-service
- total_calls: 200 (exceeds 50 threshold)
- unique_api_calls: 2 (only calls DescribeInstances and GetMetricStatistics)
- unique_api_calls < 5 threshold — does NOT meet both conditions
- Should NOT fire

### Scenario B — Many Unique APIs, Low Total Calls
- principal_arn: arn:aws:iam::123456789012:user/developer
- total_calls: 30 (below 50 threshold)
- unique_api_calls: 8 (exceeds unique threshold)
- total_calls < 50 — does NOT meet both conditions
- Should NOT fire

### Scenario C — Approved High-Volume Principal in Suppression Lookup
- principal_arn: arn:aws:iam::123456789012:role/SecurityScannerRole
- total_calls: 500
- unique_api_calls: 25
- Both thresholds exceeded, BUT SecurityScannerRole is in the enumeration_suppression_arns lookup
- Should NOT fire

### Scenario D — 49 Total Calls and 5 Unique APIs (Just Below Total Threshold)
- total_calls: 49 (one below the 50 threshold)
- unique_api_calls: 5 (exactly at unique threshold)
- Should NOT fire — total threshold not met

## Expected Result
- Detection fires: NO for all four scenarios

## Pass Criteria
- Load all scenario events into the test index
- Run CDET-008 SPL manually in Splunk
- Confirm zero alerts for all below-threshold and suppressed scenarios
- Verify both thresholds are enforced with AND logic (not OR)
- Confirm suppression lookup is correctly applied
