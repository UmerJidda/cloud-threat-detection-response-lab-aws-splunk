# CDET-004 — Simulation Steps: Admin Policy Attached to IAM Principal

## Prerequisites

### Required AWS Permissions
- `iam:AttachUserPolicy` — for managed policy attachment
- `iam:PutUserPolicy` — for inline policy attachment
- `iam:DetachUserPolicy` — for cleanup
- `iam:DeleteUserPolicy` — for cleanup
- `iam:ListUsers` — to identify target principals
- The target IAM user must already exist (create one with CDET-001 simulation or use an existing test user)

### Pre-flight Check
```bash
# Verify identity
aws sts get-caller-identity

# Check you have policy attachment permissions
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names iam:AttachUserPolicy iam:PutUserPolicy \
  --resource-arns "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):user/test-user" \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table

# Identify a test user (or create one with CDET-001 simulation first)
export TARGET_USER="svc-cdet001-simulation-user"  # Use your test user
aws iam get-user --user-name "$TARGET_USER"
```

---

## Variant A: AttachUserPolicy — AWS Managed AdministratorAccess (Loud)

This is the most common and most detectable escalation method.

```bash
# Step 1: Verify current user has no admin permissions
aws iam list-attached-user-policies \
  --user-name "$TARGET_USER" \
  --query 'AttachedPolicies[].PolicyName' \
  --output table

# Step 2: Attach AdministratorAccess managed policy
# WARNING: This grants full AWS administrative access to the target user.
aws iam attach-user-policy \
  --user-name "$TARGET_USER" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Expected output: (no output on success — exit code 0)

# Step 3: Verify policy is attached
aws iam list-attached-user-policies \
  --user-name "$TARGET_USER"

# Expected output:
# {
#     "AttachedPolicies": [
#         {
#             "PolicyName": "AdministratorAccess",
#             "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
#         }
#     ]
# }
```

**CloudTrail event generated**: `AttachUserPolicy`

---

## Variant B: AttachRolePolicy — Admin Access to a Role (Common in Privilege Escalation)

```bash
export TARGET_ROLE="TestSimulationRole"  # Replace with your test role

# Verify current role policies
aws iam list-attached-role-policies \
  --role-name "$TARGET_ROLE"

# Attach AdministratorAccess to a role
# WARNING: This grants full AWS administrative access to any principal that can assume this role.
aws iam attach-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
```

**CloudTrail event generated**: `AttachRolePolicy`

---

## Variant C: PutUserPolicy — Inline Wildcard Policy (Stealthiest)

This variant generates a `PutUserPolicy` event rather than `AttachUserPolicy`. Detection requires parsing the policy document within the CloudTrail event.

```bash
# Create an inline policy with full wildcard access
# WARNING: This creates an inline policy granting full administrative access.
# The inline policy will NOT appear in list-attached-user-policies — only list-user-policies.
aws iam put-user-policy \
  --user-name "$TARGET_USER" \
  --policy-name "cdet004-sim-inline-admin" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "FullAccess",
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  }'

# Verify the inline policy exists (note: different command than list-attached-user-policies)
aws iam list-user-policies --user-name "$TARGET_USER"
# Expected output:
# {
#     "PolicyNames": ["cdet004-sim-inline-admin"]
# }

# View the inline policy document
aws iam get-user-policy \
  --user-name "$TARGET_USER" \
  --policy-name "cdet004-sim-inline-admin"
```

**CloudTrail event generated**: `PutUserPolicy`  
**Note**: The full policy document JSON is logged in `requestParameters.policyDocument` within CloudTrail.

---

## Variant D: PutRolePolicy — Inline Wildcard Policy on a Role

```bash
export TARGET_ROLE="TestSimulationRole"

# WARNING: This grants full wildcard access via inline policy on a role.
aws iam put-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-name "cdet004-sim-inline-admin" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
  }'
```

**CloudTrail event generated**: `PutRolePolicy`

---

## Step: Verify Detection Trigger

```bash
# Check for AttachUserPolicy events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --output table

# Check for PutUserPolicy events (inline policy variant)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutUserPolicy \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --output table
```

---

## Cleanup

```bash
# Variant A cleanup — detach managed policy
aws iam detach-user-policy \
  --user-name "$TARGET_USER" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Variant B cleanup — detach from role
aws iam detach-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null || true

# Variant C cleanup — delete inline policy from user
aws iam delete-user-policy \
  --user-name "$TARGET_USER" \
  --policy-name "cdet004-sim-inline-admin" 2>/dev/null || true

# Variant D cleanup — delete inline policy from role
aws iam delete-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-name "cdet004-sim-inline-admin" 2>/dev/null || true

echo "Cleanup complete"
```
