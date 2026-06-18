# CDET-008 — Positive Test Case

**Purpose:** Verify the detection fires when a principal exceeds the threshold of 50 total API calls AND 5 unique API names within a 2-hour window.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-008_api_enumeration.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions
- Same principal_arn across all events
- total_calls >= 50 within a 2-hour window
- unique_api_calls >= 5 within the same 2-hour window
- Both thresholds must be exceeded simultaneously

## Sample Event Volume
Generate 87 events for principal arn:aws:iam::123456789012:user/attacker across the following APIs:
- ListBuckets (20 calls)
- DescribeInstances (15 calls)
- ListFunctions (15 calls)
- GetCallerIdentity (12 calls)
- ListRoles (10 calls)
- ListUsers (5 calls)
- DescribeSecurityGroups (4 calls)
- ListPolicies (3 calls)
- DescribeVpcs (2 calls)
- GetAccountAuthorizationDetails (1 call)

Total: 87 calls, 10 unique APIs — both thresholds exceeded.

## Expected Result
- Detection fires: YES
- Expected severity: medium
- Expected urgency: 3
- Expected ATT&CK fields populated: tactic=Discovery, technique=T1526

## Pass Criteria
- Alert generated within one schedule period
- alert_title equals "[CDET-008] Excessive API Enumeration"
- principal_arn matches the high-volume caller
- total_calls reflects the count within the 2-hour window (87)
- unique_api_calls reflects the number of distinct API names (10)
- enumeration_intensity is populated (e.g., "high" for >75 calls, "medium" for 50-74)
- top_apis lists the most-called API names
- event_source_ip reflects the source IP
