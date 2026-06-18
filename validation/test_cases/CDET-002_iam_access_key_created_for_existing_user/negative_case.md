# CDET-002 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when a user creates an access key for themselves and is not a privileged user.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-002_self_key_creation.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Self-Service Key Creation (Non-Privileged User)
- eventName: CreateAccessKey
- userIdentity.arn: arn:aws:iam::123456789012:user/regular-developer
- requestParameters.userName: regular-developer (same as creator)
- is_cross_user = false
- regular-developer is NOT in privileged_users lookup
- is_for_privileged_user = false

### Scenario B — Automation Role Creates Key for Automation User
- eventName: CreateAccessKey
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/TerraformExecutionRole
- requestParameters.userName: terraform-svc-account
- terraform-svc-account is NOT in privileged_users lookup
- creator ARN is in automation_role_arns lookup

## Expected Result
- Detection fires: NO
- Splunk search returns 0 results for the suppressed events

## Pass Criteria
- Load both scenario events into the test index
- Run the CDET-002 SPL manually in Splunk
- Confirm zero alerts are generated
- Verify is_cross_user is correctly computed as false for Scenario A
- Verify privileged_users lookup correctly returns no match for non-privileged users
- Confirm automation role suppression is working in Scenario B
