# CDET-001 — Edge Case

**Purpose:** Verify detection behavior when an AssumedRole session uses an approved ROLE but the session name is not recognized — the role is in automation_role_arns but the calling principal (session ARN) is not in approved_iam_principals.

## Scenario: Approved Role, Unrecognized Session Principal

### Background
The `automation_role_arns` lookup contains the base role ARN:
```
arn:aws:iam::123456789012:role/DeploymentPipelineRole
```

An attacker has compromised a host that is allowed to assume `DeploymentPipelineRole`. They assume the role and create a new IAM user. The session issuer ARN matches the lookup, so this event is suppressed — this is expected behavior and documents a known detection gap.

### Alternate Edge: Role in approved list, action from unexpected region
- session_issuer_arn: arn:aws:iam::123456789012:role/DeploymentPipelineRole (in lookup)
- event_source_ip: 203.0.113.99 (unusual geography for pipeline)
- region: ap-southeast-1 (pipeline normally runs in us-east-1)

### Expected Result
- Detection fires: NO (suppressed because session_issuer_arn is in automation_role_arns)
- This is a documented detection gap — geographic anomaly is not part of CDET-001 logic
- Recommend layering with CDET-012 (Cross-Account AssumeRole) or a separate geo-anomaly detection

## Scenario: Principal in approved_iam_principals but NOT in automation_role_arns

### Event Details
- eventName: CreateUser
- userIdentity.type: IAMUser
- userIdentity.arn: arn:aws:iam::123456789012:user/approved-admin (in approved_iam_principals)
- session_issuer_arn: null

### Expected Result
- Detection fires: NO
- Suppressed because the principal is in approved_iam_principals
- This is correct behavior — the principal is explicitly authorized

## Pass Criteria
- Load both edge case events into the test index
- Confirm detection does NOT fire for the session-issuer match scenario
- Confirm detection does NOT fire for the approved-principal-only scenario
- Document the detection gap regarding geographic/region anomalies in data/validation_results/
