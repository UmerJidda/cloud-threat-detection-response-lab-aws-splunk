# CDET-013 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when security group rules are scoped to specific IPs or when rules are added by approved principals for known-good purposes.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-013_scoped_sg_rule.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Ingress Rule Scoped to Specific IP Range
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 10.0.0.0/8 (internal RFC1918 range, not internet-accessible)
- Not 0.0.0.0/0 or ::/0
- Should NOT fire

### Scenario B — Ingress Rule Scoped to Corporate IP
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 203.0.113.0/24 (corporate office IP block — not wildcard)
- Not 0.0.0.0/0 or ::/0
- Should NOT fire

### Scenario C — RevokeSecurityGroupIngress (Removing a Rule)
- eventName: RevokeSecurityGroupIngress
- Removing an existing rule, not adding a permissive one
- Should NOT fire

### Scenario D — AuthorizeSecurityGroupIngress for Approved Security Group by Approved Principal
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 0.0.0.0/0
- principal_arn: arn:aws:iam::123456789012:role/InfrastructureRole (in approved_sg_principals lookup)
- group_id: sg-approved-public-alb (in approved_public_sg lookup)
- Known public-facing ALB security group managed by approved infrastructure team
- Should NOT fire

## Expected Result
- Detection fires: NO for all four scenarios

## Pass Criteria
- Confirm zero alerts for scoped CIDR ranges (not 0.0.0.0/0 or ::/0)
- Confirm zero alerts for revoke operations
- Confirm suppression works when both principal and security group are in approved lookups
- Verify cidr_range filter strictly matches 0.0.0.0/0 and ::/0 only
