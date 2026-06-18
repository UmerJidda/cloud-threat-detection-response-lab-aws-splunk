# CDET-012 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when AssumeRole targets an approved account or when assuming roles within the same account.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-012_approved_assumerole.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — AssumeRole Within Same Account
- eventName: AssumeRole
- requestParameters.roleArn: arn:aws:iam::123456789012:role/DeploymentRole (same account: 123456789012)
- Target account matches the caller's account
- Should NOT fire

### Scenario B — AssumeRole to Approved Cross-Account Target
- eventName: AssumeRole
- requestParameters.roleArn: arn:aws:iam::111222333444:role/PartnerRole
- Account 111222333444 is in the approved_assume_targets lookup
- Should NOT fire

### Scenario C — CI/CD Pipeline Cross-Account Deployment Role
- eventName: AssumeRole
- principal_arn contains DeploymentPipelineRole session
- roleArn: arn:aws:iam::444333222111:role/ProdDeployRole
- Both the caller and the target are in approved_assume_targets or automation_role_arns
- Should NOT fire

### Scenario D — AWS Service AssumeRole (Service-Linked Role)
- eventName: AssumeRole
- userIdentity.type: AWSService
- Initiated by an AWS service (e.g., CodePipeline, Lambda)
- Should NOT fire

## Expected Result
- Detection fires: NO for all four scenarios

## Pass Criteria
- Load all scenario events into the test index
- Confirm zero alerts for same-account, approved, and service-initiated assumptions
- Verify approved_assume_targets lookup is correctly applied
- Confirm AWS service-initiated AssumeRole events are excluded
