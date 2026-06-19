---
detection_id: CDET-006
detection_name: Root Account Activity Detected
tactic: Initial Access
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-006 — Root Account Activity Detected: Containment

> **Audience:** Tier-2 SOC analyst with AWS experience.
> **Prerequisites:** Investigation complete; attack confirmed or strongly suspected.
> **Credential rule:** Use the boto3 default credential chain only (`aws configure` / IAM role / environment). Never hardcode credentials.

---

## Approval Requirements

| Action | Approval Required From |
|---|---|
| Disable/delete root access keys | Security Lead |
| Disable IAM users (potential persistence accounts) | Security Lead + Account Owner |
| Enable SCP to block root API calls | Security Lead + Cloud Platform Team |
| Revoke active sessions (invalidate all credentials) | IR Manager |
| Delete newly created IAM entities | Security Lead + Account Owner (for production) |
| Any action affecting billing or account management | Account Owner + CISO |

**Do not proceed with destructive actions without the approvals above. Log all approvals in the incident ticket with approver name and timestamp.**

---

## Containment Actions (Priority Order)

### Step 1 — Delete Root Access Keys (Highest Priority)

Root access keys provide persistent programmatic access that survives a password reset. Remove them immediately if any exist.

```bash
# List root access keys (run as a privileged IAM user or assumed role — not as root)
aws iam list-access-keys
# For each root key returned (AccessKeyId):
aws iam update-access-key \
  --access-key-id <KEYID> \
  --status Inactive
# After confirmation, delete:
aws iam delete-access-key \
  --access-key-id <KEYID>
```

Record the `AccessKeyId` and deletion timestamp in the incident ticket before deleting.

### Step 2 — Change the Root Account Password

1. Log in to the AWS Management Console as root (using a break-glass procedure with a trusted team member present).
2. Navigate to: Account menu > Security credentials > Password.
3. Generate a new strong password (minimum 20 characters, mixed case, numbers, symbols).
4. Store the new password in the organization's approved secrets vault (e.g., AWS Secrets Manager, HashiCorp Vault) — not in email or chat.

This invalidates any active console sessions for root.

### Step 3 — Enable or Re-enforce Root MFA

If MFA was absent or if the existing MFA device may be compromised:

```bash
# Check MFA status
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```

If `0`, enable hardware MFA immediately via the AWS Console (IAM > Security credentials > MFA). Do not use a virtual MFA app on a device that may be compromised.

### Step 4 — Disable Suspicious IAM Entities Created During the Incident

For each user, role, or access key identified in the investigation as adversary-created:

```bash
# Disable access key
aws iam update-access-key \
  --user-name <USERNAME> \
  --access-key-id <KEYID> \
  --status Inactive

# Disable console login
aws iam update-login-profile \
  --user-name <USERNAME> \
  --password "$(openssl rand -base64 32)" \
  --no-password-reset-required
# Note: This sets an unknown random password, effectively locking console access.

# Detach all managed policies
aws iam list-attached-user-policies --user-name <USERNAME> \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -I {} aws iam detach-user-policy --user-name <USERNAME> --policy-arn {}

# Delete inline policies
aws iam list-user-policies --user-name <USERNAME> \
  --query 'PolicyNames[*]' --output text | \
  xargs -I {} aws iam delete-user-policy --user-name <USERNAME> --policy-name {}
```

For suspicious roles:

```bash
# List role policies and detach
aws iam list-attached-role-policies --role-name <ROLENAME> \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -I {} aws iam detach-role-policy --role-name <ROLENAME> --policy-arn {}

# Delete the role trust policy by replacing with deny-all (preserve for evidence before deletion)
aws iam get-role --role-name <ROLENAME> > evidence_role_<ROLENAME>.json
```

### Step 5 — Invalidate Active Sessions (Revoke Temporary Credentials)

To invalidate all sessions issued before a given time (use the attack start time):

```bash
# Attach a policy to the Root-sourced user/role that denies all actions before the cut-off time
# This is the AWS-recommended approach using aws:TokenIssueTime condition
```

For IAM roles assumed during the incident, revoke active sessions via the console:
IAM > Roles > `<ROLE>` > Revoke active sessions.

For the root account, there is no API to revoke sessions — changing the password (Step 2) is sufficient.

### Step 6 — Restore CloudTrail Logging (If Tampered)

If `StopLogging` or `DeleteTrail` was observed during the investigation:

```bash
# Re-enable a stopped trail
aws cloudtrail start-logging --name <TRAIL_NAME>

# Re-create a deleted trail (requires S3 bucket to exist)
aws cloudtrail create-trail \
  --name <TRAIL_NAME> \
  --s3-bucket-name <BUCKET_NAME> \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name <TRAIL_NAME>
```

Verify log file validation is enabled — this detects tampering with existing log files.

### Step 7 — Apply SCP to Block Root API Calls (Preventive Containment)

If your organization uses AWS Organizations and has not already done so, apply an SCP to deny root API actions across member accounts. This requires coordination with the Cloud Platform Team.

Example SCP (apply via AWS Organizations console or CLI — requires management account):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAPICalls",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

> Note: This SCP will not prevent console login to the root account — root console access requires a separate control (hardware MFA enforcement).

---

## What NOT to Do

| Do NOT | Reason |
|---|---|
| Delete CloudTrail S3 logs | Destroys forensic evidence; violates chain of custody |
| Terminate EC2 instances without snapshotting | Destroys memory and disk evidence |
| Delete IAM users before preserving their policy attachments | Irreversibly removes configuration evidence |
| Reset the root password from a potentially compromised device | Attacker may have access to the same device/email |
| Use root credentials to perform containment | Adds more root events that complicate forensics |
| Disable GuardDuty findings during incident | Removes real-time detection during active attack |
| Revoke all IAM users in the account (scorched earth) | Causes full account outage; use targeted revocation |

---

## Rollback / Undo Steps (If Containment Is a False Positive)

If a confirmed FP is identified after containment actions have been taken:

### Restore an Inactivated Access Key

```bash
aws iam update-access-key \
  --access-key-id <KEYID> \
  --status Active
```

Note: Deleted keys cannot be restored. A new key must be created, and all consumers updated.

### Re-attach Policies to a User

```bash
aws iam attach-user-policy \
  --user-name <USERNAME> \
  --policy-arn <POLICY_ARN>
```

### Re-enable Console Login

```bash
# Reset to a known password stored in the secrets vault
aws iam update-login-profile \
  --user-name <USERNAME> \
  --password "<NEW_STRONG_PASSWORD>" \
  --password-reset-required
```

### Re-enable a Stopped CloudTrail Trail

```bash
aws cloudtrail start-logging --name <TRAIL_NAME>
```

For each rollback action, record: who authorized, who executed, timestamp, and reason in the incident ticket.
