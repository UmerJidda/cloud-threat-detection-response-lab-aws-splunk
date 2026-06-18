# CDET-005 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when a role trust policy only includes principals from the same account, or when the external account is in the approved_external_accounts lookup.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-005_same_account_trust.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — UpdateAssumeRolePolicy with Same-Account Principal
- eventName: UpdateAssumeRolePolicy
- requestParameters.policyDocument Principal: arn:aws:iam::123456789012:role/SomeInternalRole
- Account ID in trust (123456789012) matches the current account
- Should NOT fire

### Scenario B — CreateRole with AWS Service Principal
- eventName: CreateRole
- requestParameters.assumeRolePolicyDocument Principal: {"Service": "ec2.amazonaws.com"}
- Trust is for an AWS service, not an external account
- No account ID extracted
- Should NOT fire

### Scenario C — UpdateAssumeRolePolicy for Approved Partner Account
- eventName: UpdateAssumeRolePolicy
- requestParameters.policyDocument Principal: arn:aws:iam::111222333444:role/PartnerRole
- 111222333444 is present in approved_external_accounts lookup
- Should NOT fire (approved cross-account trust)

## Expected Result
- Detection fires: NO for all three scenarios

## Pass Criteria
- Load all three scenario events into the test index
- Run CDET-005 SPL manually in Splunk
- Confirm zero alerts for same-account and AWS service trust scenarios
- Confirm zero alerts when external account is in approved_external_accounts lookup
- Verify the account ID extraction logic correctly differentiates own account from external accounts
