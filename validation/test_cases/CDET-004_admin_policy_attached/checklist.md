# CDET-004 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] admin_policy_arns lookup exists and contains AdministratorAccess and other known admin policy ARNs
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for AttachUserPolicy with AdministratorAccess
- [ ] Detection fires for AttachRolePolicy with AdministratorAccess
- [ ] Detection fires for PutUserPolicy with Action=* and Resource=* and Effect=Allow
- [ ] All expected_alert.json fields are present in the alert output
- [ ] attacher_arn correctly populated from userIdentity.arn
- [ ] target_principal correctly extracted from requestParameters
- [ ] policy_arn populated for managed policy events
- [ ] is_wildcard_inline correctly set for PutUserPolicy inline scenario
- [ ] policy_risk_level is "critical" for all triggering events
- [ ] Severity is critical and urgency is 1
- [ ] ATT&CK mapping fields are populated (tactic=Privilege Escalation, technique=T1078.004)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for ReadOnlyAccess attachment
- [ ] Detection does NOT fire for custom non-admin policy attachment
- [ ] Detection does NOT fire for scoped inline policy (no wildcard)
- [ ] admin_policy_arns lookup verified to exclude non-admin policies

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires even for approved principals attaching admin policy
- [ ] Confirm detection does NOT fire for inline policies with Effect=Deny
- [ ] Confirm detection does NOT fire for PowerUserAccess
- [ ] Document PowerUserAccess detection gap in data/validation_results/
- [ ] Verify SPL correctly validates Effect=Allow for inline wildcard policy detection

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Update admin_policy_arns lookup based on FP analysis
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
