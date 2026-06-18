# CDET-003 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] No lookup-table suppression for this detection (by design — all callers are in scope)
- [ ] Schedule and lookback window are appropriate (recommended: real-time or every 15m, lookback 30m)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for StopLogging event
- [ ] Detection fires for DeleteTrail event
- [ ] Detection fires for UpdateTrail with IsMultiRegionTrail=false
- [ ] Detection fires for UpdateTrail with IncludeGlobalServiceEvents=false
- [ ] Detection fires for UpdateTrail with EnableLogFileValidation=false
- [ ] All expected_alert.json fields are present in the alert output
- [ ] disable_reason correctly reflects the triggering condition
- [ ] trail_name and trail_arn are populated
- [ ] Severity is critical and urgency is 1
- [ ] ATT&CK mapping fields are populated (tactic=Defense Evasion, technique=T1562.008)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for UpdateTrail that preserves or improves logging
- [ ] Detection does NOT fire for UpdateTrail changing only non-logging attributes (e.g., S3 bucket)
- [ ] Detection does NOT fire for read-only CloudTrail APIs (GetTrailStatus, DescribeTrails, etc.)

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires for single-field degradation (only one parameter set to false)
- [ ] Confirm detection fires even when caller is an automation role
- [ ] Confirm detection fires for non-primary trail deletion
- [ ] Document known legitimate use cases in data/validation_results/

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Identify any legitimate UpdateTrail events that degrade logging and document them
- [ ] Re-run positive test to confirm no suppression broke the detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
