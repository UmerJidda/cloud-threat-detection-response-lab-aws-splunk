# CDET-013 — Edge Case

**Purpose:** Verify detection behavior for rules with a port range spanning a high-risk port (e.g., 0-65535 or 20-25), and for security groups in approved public-facing stacks that are managed by unapproved principals.

## Scenario: Port Range That Includes a High-Risk Port (All Ports Open)

### Event Details
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 0.0.0.0/0
- from_port: 0
- to_port: 65535
- ip_protocol: tcp

### Expected Result
- Detection fires: YES
- high_risk_port should be "true" because the range 0-65535 includes all high-risk ports (22, 23, 3389, etc.)
- Verify SPL checks whether any high-risk port falls within the from_port to to_port range, not just exact port matches
- Severity: critical (high-risk ports are included)

## Scenario: ICMP Rule Opened to Internet

### Event Details
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 0.0.0.0/0
- ip_protocol: icmp
- from_port: -1 (all ICMP types)
- to_port: -1

### Expected Result
- Detection fires: YES (cidr_range is 0.0.0.0/0)
- high_risk_port: may be "false" for ICMP (depends on high_risk_ports lookup contents)
- Severity: high (not critical if ICMP is not in high_risk_ports)
- Verify ICMP is handled correctly when from_port and to_port are -1

## Scenario: Security Group in Approved Public ALB Lookup — but Opened by Unapproved Principal

### Event Details
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 0.0.0.0/0
- from_port: 443, to_port: 443
- group_id: sg-approved-public-alb (in approved_public_sg lookup)
- principal_arn: arn:aws:iam::123456789012:user/attacker (NOT in approved_sg_principals)

### Expected Result
- Detection fires: YES
- The security group is approved, but the modifier is not
- Suppression requires BOTH the principal AND the group to be in approved lookups
- This tests that partial lookup match does not suppress

## Pass Criteria
- Confirm detection fires for all-port rules (0-65535) with cidr_range 0.0.0.0/0
- Confirm high_risk_port is "true" when range includes high-risk ports
- Confirm detection fires (with appropriate severity) for ICMP rules to internet
- Confirm detection fires when only the group is approved but the principal is not
