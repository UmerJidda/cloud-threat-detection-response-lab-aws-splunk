# CDET-004 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when non-admin policies are attached or inline policies do not contain full wildcards.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-004_benign_policy_attach.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Attach Read-Only Policy
- eventName: AttachUserPolicy
- requestParameters.policyArn: arn:aws:iam::aws:policy/ReadOnlyAccess
- Policy ARN is NOT in the admin_policy_arns lookup
- is_wildcard_inline: false
- Should NOT fire

### Scenario B — Attach Custom Non-Admin Managed Policy
- eventName: AttachRolePolicy
- requestParameters.policyArn: arn:aws:iam::123456789012:policy/S3ReadBucketPolicy
- Custom policy not in admin_policy_arns lookup
- Should NOT fire

### Scenario C — PutUserPolicy with Scoped Actions (No Wildcard)
- eventName: PutUserPolicy
- requestParameters.policyDocument:
  - "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*", "Effect": "Allow"
- is_wildcard_inline: false (Action is scoped, not "*")
- Should NOT fire

### Scenario D — PutUserPolicy with Wildcard Action but Scoped Resource
- eventName: PutUserPolicy
- requestParameters.policyDocument:
  - "Action": "*", "Resource": "arn:aws:s3:::my-specific-bucket", "Effect": "Allow"
- Confirm whether the detection fires on Action=* with a non-wildcard resource
- Document behavior — this is a gray area depending on SPL logic

## Expected Result
- Detection fires: NO for Scenarios A, B, C
- Scenario D behavior should be documented

## Pass Criteria
- Load all scenario events into the test index
- Confirm zero alerts for Scenarios A, B, C
- Confirm admin_policy_arns lookup does not include non-admin ARNs
- Document Scenario D behavior explicitly in data/validation_results/
