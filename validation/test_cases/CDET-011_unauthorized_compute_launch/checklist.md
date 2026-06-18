# CDET-011 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] approved_compute_principals lookup exists with correct column names
- [ ] suspicious_instance_types lookup exists (GPU, large metal, high-memory types)
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for unauthorized RunInstances with suspicious GPU instance type
- [ ] Detection fires for unauthorized CreateFunction
- [ ] All expected_alert.json fields are present in the alert output
- [ ] eventName correctly reflects RunInstances or CreateFunction
- [ ] principal_arn and principal_type correctly populated
- [ ] instance_type and instance_count populated for EC2 events
- [ ] is_suspicious_type correctly derived from suspicious_instance_types lookup
- [ ] abuse_category populated with appropriate category
- [ ] function_name and function_runtime populated for Lambda events
- [ ] EC2-specific fields are null for Lambda events and vice versa
- [ ] Severity is high and urgency is 2
- [ ] ATT&CK mapping fields are populated (tactic=Execution, technique=T1204.003)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for approved principal launching standard instance
- [ ] Detection does NOT fire for approved principal launching GPU instance (legitimate ML)
- [ ] Detection does NOT fire for approved Lambda deployment role
- [ ] Detection does NOT fire for instance lifecycle events (Terminate, Stop, Start)
- [ ] Confirm principal approval lookup overrides instance type suspicion

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires for unapproved principal with non-suspicious instance type
- [ ] Confirm detection does NOT fire for approved principal in unusual region
- [ ] Confirm detection fires for unapproved Lambda creation with custom runtime
- [ ] Document region anomaly gap in data/validation_results/

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Add legitimate compute-launching principals to approved_compute_principals lookup
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
