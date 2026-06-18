# CDET-005 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] approved_external_accounts lookup exists with correct column names
- [ ] SPL correctly extracts account IDs from JSON trust policy documents
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for UpdateAssumeRolePolicy with external account
- [ ] Detection fires for CreateRole with external account in trust
- [ ] All expected_alert.json fields are present in the alert output
- [ ] principal_arn reflects the acting user
- [ ] role_name correctly extracted
- [ ] external_account_id correctly extracted from trust policy
- [ ] trust_policy_fragment contains the relevant snippet
- [ ] Severity is high and urgency is 2
- [ ] ATT&CK mapping fields are populated (tactic=Persistence, technique=T1098.003)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for same-account principal in trust
- [ ] Detection does NOT fire for AWS service principal in trust
- [ ] Detection does NOT fire for approved external account in trust
- [ ] approved_external_accounts lookup correctly matched

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires for mixed trust policy (same-account + external)
- [ ] Confirm detection fires (or documents behavior) for wildcard Principal
- [ ] Confirm detection does NOT fire when external account is removed from trust
- [ ] Verify SPL correctly parses multi-value Principal arrays
- [ ] Document wildcard principal handling in data/validation_results/

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Update approved_external_accounts lookup for any legitimate partner accounts found
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
