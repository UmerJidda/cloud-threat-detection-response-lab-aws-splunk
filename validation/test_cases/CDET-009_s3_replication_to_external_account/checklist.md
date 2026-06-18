# CDET-009 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] approved_replication_accounts lookup exists with correct column names
- [ ] SPL correctly parses the nested ReplicationConfiguration JSON in requestParameters
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for PutBucketReplication with external account destination
- [ ] All expected_alert.json fields are present in the alert output
- [ ] principal_arn reflects the acting user
- [ ] source_bucket correctly extracted from requestParameters.bucketName
- [ ] destination_account_id correctly extracted from replication rule
- [ ] destination_bucket_arn correctly extracted from replication rule
- [ ] Severity is high and urgency is 2
- [ ] ATT&CK mapping fields are populated (tactic=Exfiltration, technique=T1537)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for same-account replication
- [ ] Detection does NOT fire for approved partner account replication
- [ ] Detection does NOT fire for DeleteBucketReplication events
- [ ] approved_replication_accounts lookup correctly applied

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Document SPL behavior when Account field is absent (account extracted from ARN or gap noted)
- [ ] Confirm detection fires when any rule in a multi-rule config has external destination
- [ ] Confirm detection fires after account is removed from approved lookup
- [ ] Update SPL to handle missing Account field if gap is found

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Add legitimate partner accounts to approved_replication_accounts lookup
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
