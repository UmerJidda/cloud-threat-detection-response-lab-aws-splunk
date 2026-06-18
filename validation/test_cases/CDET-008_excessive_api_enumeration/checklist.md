# CDET-008 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] enumeration_suppression_arns lookup exists for known high-volume automation principals
- [ ] Threshold values (total_calls >= 50, unique_api_calls >= 5) are documented in detection.yaml
- [ ] Lookback window is 2 hours and schedule is appropriate (recommended: every 1h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index (87 events, 10 unique APIs)
- [ ] Detection fires within one schedule period
- [ ] All expected_alert.json fields are present in the alert output
- [ ] principal_arn correctly identifies the high-volume caller
- [ ] total_calls reflects accurate count within the 2-hour window
- [ ] unique_api_calls reflects the correct count of distinct API names
- [ ] enumeration_intensity is populated with an appropriate category
- [ ] top_apis lists the most frequent API names
- [ ] Severity is medium and urgency is 3
- [ ] ATT&CK mapping fields are populated (tactic=Discovery, technique=T1526)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for high volume with low unique APIs (monitoring tools)
- [ ] Detection does NOT fire for many unique APIs with low total calls
- [ ] Detection does NOT fire for principals in enumeration_suppression_arns lookup
- [ ] Detection does NOT fire for exactly 49 total calls + 5 unique APIs
- [ ] Confirm both thresholds use AND logic and >= comparison

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires at exactly 50 total + 5 unique (boundary condition)
- [ ] Confirm detection does NOT fire at 49 total + 5 unique
- [ ] Confirm detection does NOT fire at 50 total + 4 unique
- [ ] Document windowing behavior for events near the lookback boundary

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Add legitimate high-volume principals to enumeration_suppression_arns lookup
- [ ] Consider adjusting thresholds based on FP analysis
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
