# CDET-007 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when EC2 role credentials are used from an internal AWS IP or a known EC2 instance IP.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-007_ec2_internal_api_call.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — EC2 Role Used from AWS Internal IP
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/WebAppRole
- sourceIPAddress: "AWS Internal" (or within AWS IP ranges)
- Normal EC2 instance API call from within AWS infrastructure
- Should NOT fire

### Scenario B — EC2 Role Used from Known EC2 Private IP
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/WebAppRole
- sourceIPAddress: 10.0.1.45 (private RFC1918 range, known VPC CIDR)
- Instance calling from within its VPC
- Should NOT fire

### Scenario C — User-Assumed Role from External IP (Not an EC2 Role)
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/DeveloperRole (not an EC2 instance role)
- sourceIPAddress: 198.51.100.77 (external IP)
- This is a human assuming a role from their laptop — handled by CDET-012
- Should NOT fire for CDET-007

## Expected Result
- Detection fires: NO for all three scenarios

## Pass Criteria
- Load all scenario events into the test index
- Run CDET-007 SPL manually in Splunk
- Confirm zero alerts for all internal/expected IP scenarios
- Confirm CDET-007 correctly identifies EC2 instance roles vs. human-assumed roles
- Verify AWS IP range list or lookup is correctly configured for suppression
