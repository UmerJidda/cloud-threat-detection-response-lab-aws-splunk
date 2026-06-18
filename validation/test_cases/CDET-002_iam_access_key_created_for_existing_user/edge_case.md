# CDET-002 — Edge Case

**Purpose:** Verify detection behavior when a principal is an AssumedRole session from an approved role (session_issuer_arn in automation_role_arns) but creates a key for a privileged user.

## Scenario: Approved Role Creates Key for Privileged User

### Background
The `automation_role_arns` lookup contains `TerraformExecutionRole`. Terraform is creating an access key for `admin-service-account`, which is a privileged user. The creator is suppressed at the role level, but the target is privileged — this tests whether the is_for_privileged_user flag overrides the role suppression.

### Event Details
- eventName: CreateAccessKey
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/TerraformExecutionRole (in automation_role_arns)
- requestParameters.userName: admin-service-account (in privileged_users lookup)
- is_cross_user: true (role session != key owner)
- is_for_privileged_user: true

### Expected Result
- Detection fires: YES (privileged target overrides automation suppression)
- If the SPL does NOT apply suppression when is_for_privileged_user=true, this is correct behavior
- If the SPL suppresses entirely on automation_role_arns membership, this is a detection gap — document it

## Scenario: Same-User Key Creation for Privileged User

### Event Details
- eventName: CreateAccessKey
- userIdentity.type: IAMUser
- userIdentity.arn: arn:aws:iam::123456789012:user/admin-service-account
- requestParameters.userName: admin-service-account (same user, also in privileged_users)
- is_cross_user: false
- is_for_privileged_user: true

### Expected Result
- Detection fires: YES
- Even though the user is creating a key for themselves, the privileged user flag should cause the detection to fire
- This covers the scenario where a privileged account may be compromised and re-arming itself with new credentials

## Pass Criteria
- Load both edge case events into the test index
- Confirm detection fires for the privileged target scenario
- Confirm detection fires for the self-key/privileged-user scenario
- If automation suppression takes precedence over privileged target, document as detection gap in data/validation_results/
