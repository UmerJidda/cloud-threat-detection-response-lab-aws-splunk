# CDET-010 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] deletion_suppression_arns lookup exists for approved lifecycle/automation principals
- [ ] Threshold values (estimated_objects_deleted >= 100 OR total_delete_events >= 20) documented in detection.yaml
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for large batch deletion (estimated_objects_deleted >= 100)
- [ ] Detection fires for frequent single deletions (total_delete_events >= 20)
- [ ] All expected_alert.json fields are present in the alert output
- [ ] principal_arn correctly reflects the deleting user
- [ ] destruction_scope populated (single-bucket or multi-bucket)
- [ ] total_delete_events reflects API event count
- [ ] estimated_objects_deleted reflects object count estimate
- [ ] buckets_targeted and bucket_names_str populated
- [ ] delete_operations lists API types used
- [ ] Severity is critical and urgency is 1
- [ ] ATT&CK mapping fields are populated (tactic=Impact, technique=T1485)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire below both thresholds (99 objects, 19 events)
- [ ] Detection does NOT fire for approved lifecycle automation principals
- [ ] Detection does NOT fire for AWS service-initiated lifecycle deletions
- [ ] deletion_suppression_arns lookup correctly applied

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires at exactly 100 estimated objects (boundary)
- [ ] Confirm detection fires at exactly 20 delete events (boundary)
- [ ] Confirm detection does NOT fire at 99 objects + 19 events
- [ ] Verify OR logic between the two threshold conditions
- [ ] Document DeleteBucket handling and any detection gap for bucket-level deletion

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Add legitimate high-volume deletion principals to deletion_suppression_arns
- [ ] Consider adjusting thresholds based on FP analysis
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
