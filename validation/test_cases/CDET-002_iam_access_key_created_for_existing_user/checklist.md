# CDET-002 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] All referenced lookup tables exist with correct column names (privileged_users, automation_role_arns)
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires within one schedule period
- [ ] All expected_alert.json fields are present in the alert output
- [ ] creator_arn correctly populated from userIdentity.arn
- [ ] key_owner_name correctly populated from requestParameters.userName
- [ ] new_access_key_id populated from responseElements.accessKey.accessKeyId
- [ ] is_cross_user is "true" when creator differs from key owner
- [ ] is_for_privileged_user is "true" when key_owner_name is in privileged_users lookup
- [ ] Both cross-user and privileged-user scenarios independently fire the detection
- [ ] Severity is high and urgency is 2
- [ ] ATT&CK mapping fields are populated (tactic=Persistence, technique=T1098.001)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for self-service key creation by non-privileged user
- [ ] Detection does NOT fire for automation role creating key for non-privileged user
- [ ] Confirm is_cross_user is correctly computed as false for same-user creation
- [ ] Confirm privileged_users lookup correctly excludes non-privileged users

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Verify behavior when automation role creates key for privileged user (fire or suppress — document outcome)
- [ ] Verify detection fires when privileged user creates own new key
- [ ] Document any detection gap if automation_role_arns suppression overrides privileged target check

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Update suppression lookups based on FP analysis
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
