# CDET-005 — Edge Case

**Purpose:** Verify detection behavior when a trust policy includes both same-account and external-account principals in the same statement.

## Scenario: Mixed Trust Policy (Same-Account + External Account)

### Event Details
- eventName: UpdateAssumeRolePolicy
- requestParameters.policyDocument:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::123456789012:role/InternalRole",
          "arn:aws:iam::999888777666:root"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```
- The policy contains one internal principal and one external account

### Expected Result
- Detection fires: YES
- The presence of ANY external account ID in the trust policy should trigger the detection
- The SPL must correctly parse multi-value Principal arrays and extract external accounts

## Scenario: Trust Policy with Wildcard Principal

### Event Details
- eventName: CreateRole
- requestParameters.assumeRolePolicyDocument:
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "sts:AssumeRole"
  }]
}
```
- Principal is "*" (allows any AWS principal to assume the role)

### Expected Result
- Detection fires: YES
- Wildcard principal is even more dangerous than a specific external account
- Verify SPL handles the "*" principal case — it may not extract a specific external_account_id
- external_account_id may be set to "*" or "any" for this case

## Scenario: UpdateAssumeRolePolicy Removing External Account (Trust Cleanup)

### Event Details
- eventName: UpdateAssumeRolePolicy
- New policyDocument contains ONLY same-account principals (cleaning up a previous external trust)
- No external account in the updated policy

### Expected Result
- Detection fires: NO
- The detection should only fire on the presence of external accounts, not on their removal
- Verify SPL evaluates the new/updated policy document, not historical state

## Pass Criteria
- Confirm detection fires for mixed trust policy containing external account
- Confirm detection fires (or generates appropriate alert) for wildcard Principal
- Confirm detection does NOT fire when updating a trust policy to remove external accounts
- Document wildcard principal handling in data/validation_results/
