# CDET-004 — Edge Case

**Purpose:** Verify detection behavior when a principal is in approved_iam_principals but attaches an admin policy — and when an inline policy has wildcard action but deny effect.

## Scenario: Approved Principal Attaches Admin Policy

### Event Details
- eventName: AttachUserPolicy
- userIdentity.arn: arn:aws:iam::123456789012:user/approved-admin (in approved_iam_principals)
- requestParameters.policyArn: arn:aws:iam::aws:policy/AdministratorAccess
- is_wildcard_inline: false
- policy_risk_level: critical

### Expected Result
- Detection fires: YES
- CDET-004 intentionally does NOT suppress on approved_iam_principals for policy attachment events
- Even approved principals should not be silently attaching AdministratorAccess — this warrants review
- If suppression is needed, it should be handled via a separate exception lookup scoped to specific attacher+target combinations

## Scenario: PutUserPolicy with Wildcard Action and Explicit Deny

### Event Details
- eventName: PutUserPolicy
- requestParameters.policyDocument:
  - "Action": "*", "Resource": "*", "Effect": "Deny"
- is_wildcard_inline: depends on SPL parsing of Effect field

### Expected Result
- Detection fires: NO (Deny effect does not grant admin access)
- Verify SPL correctly checks for Effect=Allow alongside Action=* and Resource=*
- If SPL only checks Action=* and Resource=* without validating Effect=Allow, this is a false positive bug — document and fix

## Scenario: AttachRolePolicy for PowerUserAccess (Near-Admin)

### Event Details
- eventName: AttachRolePolicy
- requestParameters.policyArn: arn:aws:iam::aws:policy/PowerUserAccess
- PowerUserAccess is NOT in admin_policy_arns (does not include IAM write actions)

### Expected Result
- Detection fires: NO (PowerUserAccess is not in the admin_policy_arns lookup)
- This is a known detection gap — PowerUserAccess can be nearly equivalent to admin in many environments
- Recommend adding PowerUserAccess to admin_policy_arns lookup after review

## Pass Criteria
- Confirm detection fires even for approved principals attaching AdministratorAccess
- Confirm detection does NOT fire for Deny-effect wildcard inline policies
- Confirm detection does NOT fire for PowerUserAccess (and document the gap)
- Fix SPL if Effect is not being validated in PutUserPolicy logic
