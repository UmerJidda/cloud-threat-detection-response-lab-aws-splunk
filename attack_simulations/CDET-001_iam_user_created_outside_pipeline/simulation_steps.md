# CDET-001 — Simulation Steps: IAM User Created Outside Pipeline

## Prerequisites

### Required AWS Permissions
Your current principal must have the following IAM permissions:
- `iam:CreateUser`
- `iam:CreateLoginProfile`
- `iam:AttachUserPolicy`
- `iam:AddUserToGroup` (optional, for group-based variant)
- `iam:DeleteUser` (for cleanup)
- `iam:DeleteLoginProfile` (for cleanup)
- `iam:DetachUserPolicy` (for cleanup)

### Pre-flight Check: Verify Your Permissions
```bash
# Check your current identity
aws sts get-caller-identity

# Expected output:
# {
#     "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/your-username"
# }

# Verify iam:CreateUser permission (dry-run simulation)
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names iam:CreateUser iam:CreateLoginProfile iam:AttachUserPolicy \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table
```

Expected output shows `allowed` for each action. If any show `implicitDeny` or `explicitDeny`, you lack the required permissions.

---

## Step 1: Create the Backdoor IAM User

```bash
# Set your test username (use a name that mimics your org's naming convention for realism)
export BACKDOOR_USER="svc-backup-agent-test"
export AWS_REGION="us-east-1"

# Create the IAM user
aws iam create-user \
  --user-name "$BACKDOOR_USER" \
  --tags Key=CreatedBy,Value=SimulationTest Key=CDET,Value=001

# Expected output:
# {
#     "User": {
#         "Path": "/",
#         "UserName": "svc-backup-agent-test",
#         "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#         "Arn": "arn:aws:iam::123456789012:user/svc-backup-agent-test",
#         "CreateDate": "2026-06-16T00:00:00+00:00"
#     }
# }
```

**CloudTrail event generated**: `CreateUser`

---

## Step 2: Enable Console Access (Create Login Profile)

```bash
# Add a console password (this enables AWS Console access)
# WARNING: Use a strong temporary password; this is a simulation only
aws iam create-login-profile \
  --user-name "$BACKDOOR_USER" \
  --password "Temp@Pass1234!" \
  --no-password-reset-required

# Expected output:
# {
#     "LoginProfile": {
#         "UserName": "svc-backup-agent-test",
#         "CreateDate": "2026-06-16T00:00:00+00:00",
#         "PasswordResetRequired": false
#     }
# }
```

**CloudTrail event generated**: `CreateLoginProfile`

---

## Step 3A: Attach Admin Policy Directly (Noisy Variant)

```bash
# Attach AWS managed AdministratorAccess policy
aws iam attach-user-policy \
  --user-name "$BACKDOOR_USER" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

# Expected output: (no output on success, exit code 0)

# Verify the attachment
aws iam list-attached-user-policies \
  --user-name "$BACKDOOR_USER"

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

## Step 3B: Add to Existing Admin Group (Stealthier Variant)

```bash
# Alternative: add to an existing privileged group (replace 'Administrators' with your group name)
export ADMIN_GROUP="Administrators"

aws iam add-user-to-group \
  --user-name "$BACKDOOR_USER" \
  --group-name "$ADMIN_GROUP"

# Expected output: (no output on success, exit code 0)

# Verify
aws iam list-groups-for-user \
  --user-name "$BACKDOOR_USER"
```

**CloudTrail event generated**: `AddUserToGroup`

---

## Step 4: Create Access Keys (Programmatic Access)

```bash
# Create access keys for programmatic access
aws iam create-access-key \
  --user-name "$BACKDOOR_USER"

# Expected output:
# {
#     "AccessKey": {
#         "UserName": "svc-backup-agent-test",
#         "AccessKeyId": "AKIAXXXXXXXXXXXXXXXXX",
#         "Status": "Active",
#         "SecretAccessKey": "REDACTED",
#         "CreateDate": "2026-06-16T00:00:00+00:00"
#     }
# }
# WARNING: The SecretAccessKey is only shown once. In a real attack, this would be exfiltrated.
```

**CloudTrail event generated**: `CreateAccessKey`

---

## Step 5: Verify Detection Trigger

After completing steps 1-4, wait 1-5 minutes for CloudTrail events to appear in your SIEM. Then verify detection:

```bash
# Query recent IAM CreateUser events via CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,User:Username,Event:EventName}' \
  --output table
```

---

## Step 6: Cleanup

```bash
# IMPORTANT: Always clean up simulation artifacts

# Detach the admin policy
aws iam detach-user-policy \
  --user-name "$BACKDOOR_USER" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null || true

# Remove from group if added
aws iam remove-user-from-group \
  --user-name "$BACKDOOR_USER" \
  --group-name "$ADMIN_GROUP" 2>/dev/null || true

# Delete access keys
for KEY_ID in $(aws iam list-access-keys --user-name "$BACKDOOR_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name "$BACKDOOR_USER" --access-key-id "$KEY_ID"
done

# Delete login profile
aws iam delete-login-profile \
  --user-name "$BACKDOOR_USER" 2>/dev/null || true

# Delete the user
aws iam delete-user \
  --user-name "$BACKDOOR_USER"

echo "Cleanup complete: $BACKDOOR_USER deleted"
```

---

## Observed SIEM Alert

In Splunk, the CDET-001 detection rule should fire within the lookup window. Look for:
```
index=aws_cloudtrail eventName=CreateUser
| where userIdentity.arn != "arn:aws:iam::*:role/PipelineRole"
```
