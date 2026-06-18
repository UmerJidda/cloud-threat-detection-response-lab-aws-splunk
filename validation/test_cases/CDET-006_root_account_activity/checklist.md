# CDET-006 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] No lookup tables required (root activity is always suspicious — no suppression by design)
- [ ] Schedule and lookback window are appropriate (recommended: real-time or every 15m, lookback 30m)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for root CreateUser event
- [ ] Detection fires for root Billing API event
- [ ] Detection fires for root ConsoleLogin event
- [ ] All expected_alert.json fields are present in the alert output
- [ ] root_action_category correctly categorizes each event type
- [ ] mfa_used correctly reflects session MFA authentication status
- [ ] event_source_ip and region are populated
- [ ] Severity is critical and urgency is 1 for all root events
- [ ] ATT&CK mapping fields are populated (tactic=Privilege Escalation, technique=T1078.004)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for IAMUser type making the same API calls
- [ ] Detection does NOT fire for AssumedRole type
- [ ] Detection does NOT fire for AWSService type
- [ ] Detection does NOT fire for FederatedUser type
- [ ] Confirm SPL filter is exact match on userIdentity.type = "Root"

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires for root events even when MFA is enabled
- [ ] Confirm mfa_used field correctly reports "Yes" for MFA-authenticated root sessions
- [ ] Document behavior for AWS internal root service events
- [ ] Document alert deduplication behavior for burst root activity

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (all root events are high-fidelity; FP rate should be near 0%)
- [ ] Identify any legitimate scheduled root activities (e.g., billing reviews) and document
- [ ] Consider adding a root activity runbook reference to the detection description

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
