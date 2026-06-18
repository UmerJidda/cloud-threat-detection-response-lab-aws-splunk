# CDET-001 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when an IAM user is created by an approved pipeline or automation role.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-001_pipeline_createuser.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions
The detection must NOT fire under any of the following conditions:

### Scenario A — DeploymentPipelineRole
- eventName: CreateUser
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/DeploymentPipelineRole
- This ARN is present in the automation_role_arns lookup

### Scenario B — TerraformExecutionRole
- eventName: CreateUser
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/TerraformExecutionRole
- This ARN is present in the automation_role_arns lookup

### Scenario C — Approved IAM Principal
- eventName: CreateUser
- userIdentity.type: IAMUser
- userIdentity.arn is present in the approved_iam_principals lookup

## Expected Result
- Detection fires: NO
- Splunk search returns 0 results for the suppressed events

## Pass Criteria
- Load all three scenario events into the test index
- Run the CDET-001 SPL manually in Splunk
- Confirm zero alerts are generated
- Verify the lookup join correctly matched on the creator_arn field
- Confirm suppression is working for both approved_iam_principals and automation_role_arns lookups
