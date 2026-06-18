# CDET-007 — Edge Case

**Purpose:** Verify detection behavior when the session issuer is an EC2 role but the call originates from an approved NAT gateway or egress IP that is shared with external traffic.

## Scenario: EC2 Role Used from Corporate NAT Gateway (Shared Egress IP)

### Background
The company's NAT gateway has a static Elastic IP (203.0.113.100) used by both EC2 instances and corporate employees. From a CloudTrail perspective, API calls from EC2 instances routed through NAT appear to come from an external IP.

### Event Details
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/InternalAppRole
- sourceIPAddress: 203.0.113.100 (NAT gateway EIP — in approved_egress_ips lookup)
- instance_id: i-0abcdef1234567890

### Expected Result
- Detection fires: NO (NAT gateway IP is in approved_egress_ips lookup)
- Verify the approved_egress_ips lookup exists and contains all NAT gateway EIPs
- If the lookup does NOT exist, this becomes a false positive scenario

## Scenario: EC2 Role Used from New Region (Instance Migrated)

### Event Details
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/WebAppRole
- sourceIPAddress: 54.239.28.85 (AWS IP in a different region — us-west-2)
- instance_id: i-0xyz9876543210abc

### Expected Result
- Detection fires: YES (or NO if AWS IPs in all regions are suppressed)
- The EC2 instance role is being used from a different AWS region, which may indicate credential exfiltration to another EC2 instance
- Document whether the suppression covers all AWS IP ranges or only the home region

## Scenario: Lambda Function Using EC2-Role-Style Session Naming

### Event Details
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/LambdaExecutionRole
- sessionContext.sessionIssuer.type: Role
- Session name looks like an instance ID pattern but is actually a Lambda request ID
- sourceIPAddress: 54.239.28.85 (AWS Lambda IP)

### Expected Result
- Detection fires: NO (Lambda execution role, not EC2 metadata abuse)
- Verify the detection correctly distinguishes EC2 instance roles from Lambda execution roles

## Pass Criteria
- Confirm detection does NOT fire for approved NAT gateway IPs (if lookup exists)
- Document behavior for cross-region AWS IP usage
- Confirm detection correctly excludes Lambda execution role sessions
- Update approved_egress_ips lookup with all known NAT gateway EIPs before production deployment
