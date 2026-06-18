# CDET-014 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] cloudtrail_log_buckets lookup exists and contains ALL active CloudTrail delivery buckets
- [ ] Operational process documented for updating cloudtrail_log_buckets when new trails are created
- [ ] Schedule and lookback window are appropriate (recommended: real-time or every 15m, lookback 30m)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for DeleteObjects on a CloudTrail log bucket
- [ ] Detection fires for DeleteObject on a CloudTrail log bucket
- [ ] Detection fires for DeleteBucket on a CloudTrail log bucket
- [ ] All expected_alert.json fields are present in the alert output
- [ ] deletion_type correctly categorizes the event (bulk_log_deletion, single_log_deletion, bucket_deletion)
- [ ] bucket_name matched against cloudtrail_log_buckets lookup
- [ ] trail_name correctly derived
- [ ] object_key populated where applicable
- [ ] estimated_logs_deleted populated for object-level deletions
- [ ] Severity is critical and urgency is 1 for all scenarios
- [ ] ATT&CK mapping fields are populated (tactic=Defense Evasion, technique=T1070.004)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for deletions from non-CloudTrail buckets
- [ ] Detection does NOT fire for AWS service lifecycle expirations on CloudTrail buckets
- [ ] Detection does NOT fire for CloudTrail service deleting objects
- [ ] Detection does NOT fire for read operations (GetObject) on CloudTrail buckets
- [ ] cloudtrail_log_buckets lookup correctly applied
- [ ] AWSService principal type exclusion verified

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Document and confirm the detection gap for newly created buckets not in the lookup
- [ ] Confirm operational process for maintaining cloudtrail_log_buckets lookup is in place
- [ ] Confirm detection fires for authorized admin deletions (FP potential documented)
- [ ] Document SPL behavior for non-log-path object deletions in CloudTrail bucket
- [ ] Update cloudtrail_log_buckets to include all trails discovered during FP review

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Add any legitimate log management principals to exception lookup if applicable
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
