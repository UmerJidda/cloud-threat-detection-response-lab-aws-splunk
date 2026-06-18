# CDET-001 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] All referenced lookup tables exist with correct column names (approved_iam_principals, automation_role_arns)
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires within one schedule period
- [ ] All expected_alert.json fields are present in the alert output
- [ ] creator_arn correctly reflects the non-pipeline principal
- [ ] new_user_name and new_user_arn are populated from requestParameters
- [ ] mfa_used field is correctly derived
- [ ] session_issuer_arn is null for IAMUser type events
- [ ] Severity is high and urgency is 2
- [ ] ATT&CK mapping fields are populated (tactic=Persistence, technique=T1136.003)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire when creator is DeploymentPipelineRole
- [ ] Detection does NOT fire when creator is TerraformExecutionRole
- [ ] Detection does NOT fire when creator_arn is in approved_iam_principals
- [ ] Confirm suppression lookup matched correctly on creator_arn
- [ ] Verify both lookup tables (approved_iam_principals, automation_role_arns) are evaluated

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection does NOT fire when session_issuer_arn is in automation_role_arns (role-level suppression)
- [ ] Confirm detection does NOT fire when only approved_iam_principals matches
- [ ] Document detection gap: geographic/region anomaly not covered by CDET-001
- [ ] Note in data/validation_results/ that CDET-012 should be reviewed as a complementary detection

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Update suppression lookups based on FP analysis (add any legitimate IAM-user-creating principals)
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
