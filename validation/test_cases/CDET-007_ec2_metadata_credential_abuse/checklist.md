# CDET-007 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] approved_egress_ips lookup exists with all NAT gateway and known egress IPs
- [ ] AWS IP range list or lookup is configured for suppression of internal AWS calls
- [ ] Schedule and lookback window are appropriate (recommended: every 1h, lookback 2h)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for EC2 role used from external IP (CloudTrail source)
- [ ] Detection fires for GuardDuty InstanceCredentialExfiltration finding
- [ ] All expected_alert.json fields are present in the alert output
- [ ] detection_source correctly reflects "CloudTrail" or "GuardDuty"
- [ ] instance_id correctly extracted from session ARN
- [ ] session_issuer_arn reflects the underlying EC2 role
- [ ] Severity is high and urgency is 2
- [ ] ATT&CK mapping fields are populated (tactic=Credential Access, technique=T1552.005)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for EC2 role used from AWS Internal IP
- [ ] Detection does NOT fire for EC2 role used from private RFC1918 IP
- [ ] Detection does NOT fire for non-EC2 role assumed from external IP

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection does NOT fire for approved NAT gateway IPs (if lookup populated)
- [ ] Document behavior for cross-region AWS IP usage (fire or suppress)
- [ ] Confirm detection correctly excludes Lambda execution role sessions
- [ ] approved_egress_ips lookup verified to include all known egress IPs

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Update approved_egress_ips lookup based on FP analysis
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
