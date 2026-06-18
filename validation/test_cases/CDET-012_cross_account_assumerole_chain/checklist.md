# CDET-012 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] approved_assume_targets lookup exists with all approved cross-account role ARNs and account IDs
- [ ] Severity escalation logic for chained assumptions is documented in detection.yaml
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for single cross-account AssumeRole to unapproved account (severity=high)
- [ ] Detection fires for chained AssumeRole across multiple accounts (severity=critical)
- [ ] All expected_alert.json fields are present in the alert output
- [ ] principal_arn and principal_type correctly populated
- [ ] is_chained_assumption correctly distinguishes single vs. chained
- [ ] total_assumes and distinct_target_accounts accurately reflect chain depth
- [ ] target_accounts_str and target_roles_str list all targets
- [ ] Severity escalates to critical for chained assumptions (urgency=1)
- [ ] ATT&CK mapping fields are populated (tactic=Lateral Movement, technique=T1550.001)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for same-account AssumeRole
- [ ] Detection does NOT fire for AssumeRole to approved cross-account target
- [ ] Detection does NOT fire for CI/CD pipeline cross-account deployments
- [ ] Detection does NOT fire for AWS service-initiated AssumeRole
- [ ] approved_assume_targets lookup correctly applied

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires for boomerang role chain (external hop detected even if chain returns)
- [ ] Confirm detection fires when approved principal targets unapproved account
- [ ] Confirm severity escalation at is_chained_assumption=true threshold
- [ ] Verify severity escalation logic is correctly implemented in SPL

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Update approved_assume_targets with any legitimate cross-account patterns found
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
