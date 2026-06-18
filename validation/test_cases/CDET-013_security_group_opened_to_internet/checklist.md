# CDET-013 Validation Checklist

## Pre-Deployment Checks
- [ ] detection.yaml is complete and all required fields are present
- [ ] SPL syntax has been verified in Splunk Search (no parse errors)
- [ ] All referenced macros exist in macros.conf
- [ ] high_risk_ports lookup exists (should include: 22, 23, 25, 53, 3306, 3389, 5432, 5900, 6379, 27017)
- [ ] approved_sg_principals lookup exists for known infrastructure management principals
- [ ] approved_public_sg lookup exists for known public-facing security groups (ALB, etc.)
- [ ] Schedule and lookback window are appropriate (recommended: real-time or every 15m, lookback 30m)

## Positive Test (must fire)
- [ ] Positive case sample data loaded into Splunk test index
- [ ] Detection fires for SSH (22) opened to 0.0.0.0/0 — severity=critical
- [ ] Detection fires for RDP (3389) opened to ::/0 — severity=critical
- [ ] Detection fires for non-high-risk port opened to 0.0.0.0/0 — severity=high
- [ ] All expected_alert.json fields are present in the alert output
- [ ] group_id correctly extracted
- [ ] from_port, to_port, ip_protocol, cidr_range correctly populated
- [ ] high_risk_port correctly set based on port lookup
- [ ] Severity correctly escalates to critical for high-risk ports
- [ ] ATT&CK mapping fields are populated (tactic=Defense Evasion, technique=T1562.007)

## Negative Test (must NOT fire)
- [ ] Negative case sample data loaded
- [ ] Detection does NOT fire for scoped CIDR range (10.0.0.0/8, etc.)
- [ ] Detection does NOT fire for corporate IP-scoped rules
- [ ] Detection does NOT fire for RevokeSecurityGroupIngress events
- [ ] Detection does NOT fire when both principal and security group are in approved lookups
- [ ] Verify CIDR filter is exact match on 0.0.0.0/0 and ::/0

## Edge Case Test
- [ ] Edge case sample data loaded
- [ ] Confirm detection fires for all-port range (0-65535) to 0.0.0.0/0
- [ ] Confirm high_risk_port=true when range includes a high-risk port
- [ ] Confirm detection fires for ICMP rules to 0.0.0.0/0
- [ ] Confirm detection fires when only the security group is approved but principal is not
- [ ] Verify from_port/to_port range check for high-risk port detection

## False Positive Baseline
- [ ] Run detection against 14 days of production CloudTrail data
- [ ] Document FP count and rate (target: <5% FP rate)
- [ ] Add legitimate public-facing security groups to approved_public_sg lookup
- [ ] Add authorized principals to approved_sg_principals lookup
- [ ] Re-run positive test to confirm suppression did not break detection

## Sign-off
- [ ] Detection reviewed by second engineer
- [ ] All test cases documented in data/validation_results/
- [ ] coverage_matrix.md updated to Testing status
- [ ] detection_catalog.md updated
