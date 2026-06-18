# CDET-008 — Edge Case

**Purpose:** Test the exact threshold boundary conditions — exactly 50 total API calls with exactly 5 unique APIs should fire; 50 calls with 4 unique APIs should not; 49 calls with 5 unique APIs should not.

## Scenario: Exactly At Both Thresholds (Should Fire)

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/boundary-tester
- Events within the 2-hour window:
  - DescribeInstances: 20 calls
  - ListBuckets: 15 calls
  - ListFunctions: 8 calls
  - GetCallerIdentity: 5 calls
  - ListRoles: 2 calls
- total_calls: 50 (exactly at threshold)
- unique_api_calls: 5 (exactly at threshold)

### Expected Result
- Detection fires: YES (threshold is >=50 AND >=5, so exactly 50 and 5 should trigger)
- Verify SPL uses >= not > for both threshold conditions

## Scenario: Total At Threshold, Unique One Below (Should NOT Fire)

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/boundary-tester-2
- Events within the 2-hour window:
  - DescribeInstances: 35 calls
  - ListBuckets: 15 calls
- total_calls: 50 (at threshold)
- unique_api_calls: 4 (one below unique threshold)

### Expected Result
- Detection fires: NO
- 4 unique APIs is below the >=5 threshold

## Scenario: Total One Below, Unique At Threshold (Should NOT Fire)

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/boundary-tester-3
- Events within the 2-hour window spread across 5 unique APIs
- total_calls: 49 (one below total threshold)
- unique_api_calls: 5 (at threshold)

### Expected Result
- Detection fires: NO
- 49 total calls is below the >=50 threshold

## Scenario: Events Spanning Across the 2-Hour Window Boundary

### Event Details
- principal_arn: arn:aws:iam::123456789012:user/window-boundary
- 30 calls from 12:30 - 13:00 (in the first half of an older window)
- 30 calls from 13:00 - 13:30 (spanning into the next window)
- 6 unique APIs across both windows

### Expected Result
- The 2-hour sliding window should capture the combined 60 calls
- Detection behavior depends on whether the SPL uses a fixed or sliding window
- Document the windowing behavior and confirm the lookback period is consistent

## Pass Criteria
- Confirm detection fires at exactly 50 total and 5 unique (boundary at threshold)
- Confirm detection does NOT fire at 49 total / 5 unique
- Confirm detection does NOT fire at 50 total / 4 unique
- Document windowing behavior for events spanning the lookback boundary
