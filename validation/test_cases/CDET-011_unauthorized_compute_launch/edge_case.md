# CDET-011 — Edge Case

**Purpose:** Verify detection behavior when the calling principal is an AssumedRole session from an approved role but launching in an unusual region, and when a non-suspicious instance type is launched by an unapproved principal.

## Scenario: Unapproved Principal Launches a Non-Suspicious Instance Type

### Event Details
- eventName: RunInstances
- principal_arn: arn:aws:iam::123456789012:user/rogue-developer (NOT in approved_compute_principals)
- instance_type: t3.micro (not in suspicious_instance_types)
- instance_count: 1
- is_suspicious_type: false

### Expected Result
- Detection fires: YES
- The principal is unapproved regardless of instance type
- The primary detection trigger is unauthorized principal, not suspicious instance type
- is_suspicious_type=false and abuse_category may be "unauthorized_launch" rather than "crypto_mining"
- Verify SPL fires on unapproved principal alone, without requiring is_suspicious_type=true

## Scenario: Approved Role Session Launching from Unusual Region

### Event Details
- eventName: RunInstances
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/EC2ProvisioningRole (in approved_compute_principals)
- region: ap-east-1 (Hong Kong — atypical for this organization)
- instance_type: c5.xlarge

### Expected Result
- Detection fires: NO (principal is approved — CDET-011 does not filter by region)
- Unusual region for an approved principal is a detection gap for CDET-011
- Recommend layering with a separate geo-anomaly detection or adding region filters to the detection
- Document this gap in data/validation_results/

## Scenario: CreateFunction with Suspicious Runtime (Obfuscated Code)

### Event Details
- eventName: CreateFunction
- principal_arn: arn:aws:iam::123456789012:user/attacker (NOT in approved_compute_principals)
- function_runtime: provided.al2 (custom runtime — may indicate obfuscation or evasion)
- function_name: update-handler (innocuous name)

### Expected Result
- Detection fires: YES (unapproved principal)
- is_suspicious_type determination for Lambda may differ from EC2 — document what criteria mark a Lambda function as suspicious
- abuse_category may reflect "unauthorized_function" or similar

## Pass Criteria
- Confirm detection fires for unapproved principal with non-suspicious instance type
- Confirm detection does NOT fire for approved principal in unusual region
- Confirm detection fires for unapproved principal creating Lambda with custom runtime
- Document region anomaly as a gap and reference complementary detections
