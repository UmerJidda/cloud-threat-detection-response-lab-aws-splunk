---
detection_id: CDET-001
detection_name: IAM User Created Outside Pipeline
tactic: Persistence
technique: T1136.003
last_updated: 2026-06-18
---

# CDET-001 — Containment Playbook
**IAM User Created Outside Pipeline**

> **Audience:** Tier-2 SOC Analyst with AWS IAM experience
> **Prerequisites:** Investigation complete; blast radius and attack chain confirmed
> **Goal:** Stop the attacker's access without destroying evidence or causing outage

---

## Approval Requirements

| Action | Approval needed before executing |
|---|---|
| Deactivate access keys on the backdoor user | IR lead or on-call security manager |
| Disable console login profile | IR lead or on-call security manager |
| Detach all policies / remove from groups | IR lead or on-call security manager |
| Delete the backdoor IAM user | IR lead + account owner sign-off |
| Disable or revoke the **calling identity** (compromised credential) | IR lead + account owner sign-off |
| SCPs / permission boundary changes affecting prod | Change Advisory Board (CAB) or equivalent |

**Do not skip approvals to save time.** If the threat is active, page the IR lead while preparing the containment commands.

---

## Step 1 — Deactivate All Access Keys on the Backdoor User

This is the highest-priority action. Deactivating (not deleting) preserves evidence while immediately blocking programmatic access.

```bash
# List all keys first
aws iam list-access-keys --user-name "<NEW_USERNAME>" --output json

# Deactivate each key (repeat for every AccessKeyId returned)
aws iam update-access-key \
  --user-name "<NEW_USERNAME>" \
  --access-key-id "<KEY_ID>" \
  --status Inactive
```

**Verify:**

```bash
aws iam list-access-keys --user-name "<NEW_USERNAME>" --output json
# Confirm Status is "Inactive" for all keys
```

---

## Step 2 — Disable Console Login Profile

Prevents the attacker from using password-based console access.

```bash
# Check if a login profile exists first
aws iam get-login-profile --user-name "<NEW_USERNAME>" --output json 2>&1

# If it exists, update the password to a random unguessable string
# (Do NOT delete — deletion destroys evidence of when it was created)
aws iam update-login-profile \
  --user-name "<NEW_USERNAME>" \
  --password "$(openssl rand -base64 32)" \
  --no-password-reset-required
```

> Note: There is no native AWS "disable login profile" API; overwriting with an unknown password is the safe equivalent that preserves the `CreateLoginProfile` event in CloudTrail.

---

## Step 3 — Detach All Policies and Remove from Groups

Remove permissions so the account has no effective access even if keys are somehow re-activated.

```bash
# Detach all managed policies
aws iam list-attached-user-policies --user-name "<NEW_USERNAME>" --output json
# For each policyArn:
aws iam detach-user-policy \
  --user-name "<NEW_USERNAME>" \
  --policy-arn "<POLICY_ARN>"

# Delete all inline policies
aws iam list-user-policies --user-name "<NEW_USERNAME>" --output json
# For each policyName:
aws iam delete-user-policy \
  --user-name "<NEW_USERNAME>" \
  --policy-name "<POLICY_NAME>"

# Remove from all groups
aws iam list-groups-for-user --user-name "<NEW_USERNAME>" --output json
# For each GroupName:
aws iam remove-user-from-group \
  --user-name "<NEW_USERNAME>" \
  --group-name "<GROUP_NAME>"
```

---

## Step 4 — Attach an Explicit Deny Permission Boundary

As a belt-and-suspenders measure, attach a deny-all permission boundary to the user. This blocks all API calls even if a new policy is later attached.

```bash
# Use your pre-existing DenyAll managed policy, or create one:
aws iam put-user-permissions-boundary \
  --user-name "<NEW_USERNAME>" \
  --permissions-boundary "arn:aws:iam::<ACCOUNT_ID>:policy/DenyAllPolicy"
```

If you do not have a `DenyAllPolicy`, create it:

```bash
aws iam create-policy \
  --policy-name DenyAllPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }' \
  --output json
```

---

## Step 5 — Contain the Calling (Compromised) Identity

The caller's credential is the root cause. Contain it based on its type:

### If caller is an IAM user:

```bash
# Deactivate all access keys
aws iam list-access-keys --user-name "<CALLER_USERNAME>" --output json
aws iam update-access-key \
  --user-name "<CALLER_USERNAME>" \
  --access-key-id "<KEY_ID>" \
  --status Inactive

# Disable console access
aws iam update-login-profile \
  --user-name "<CALLER_USERNAME>" \
  --password "$(openssl rand -base64 32)"
```

### If caller is an IAM role (AssumedRole):

```bash
# Revoke all active sessions by updating the role's trust policy to deny sts:AssumeRole
# First, export current trust policy for evidence
aws iam get-role --role-name "<ROLE_NAME>" --output json > role_trust_policy_backup.json

# Then attach a DenyAll inline policy to the role
aws iam put-role-policy \
  --role-name "<ROLE_NAME>" \
  --policy-name "INCIDENT-CDET-001-ContainmentDeny" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {}}]
  }'
```

> AssumedRole sessions that are already in use will **not** be immediately invalidated; the deny policy takes effect on the **next** API call. If the role is actively being used by an attacker, consider using AWS IAM Identity Center session revocation or the `aws iam delete-role-policy` + role trust policy approach to force all sessions to expire.

---

## Step 6 — Capture a Final Evidence Snapshot

Before any deletion, save the complete state:

```bash
aws iam get-user --user-name "<NEW_USERNAME>" --output json > evidence_user.json
aws iam list-access-keys --user-name "<NEW_USERNAME>" --output json > evidence_access_keys.json
aws iam list-attached-user-policies --user-name "<NEW_USERNAME>" --output json > evidence_managed_policies.json
aws iam list-user-policies --user-name "<NEW_USERNAME>" --output json > evidence_inline_policies.json
aws iam list-groups-for-user --user-name "<NEW_USERNAME>" --output json > evidence_groups.json
```

Upload these files to the case management system or incident S3 bucket.

---

## What NOT to Do

- **Do NOT delete access keys** before deactivating and recording them — deletion removes the key ID from CloudTrail lookup.
- **Do NOT delete the IAM user** until the investigation is complete and IR lead approves — the user object and its creation timestamp are evidence.
- **Do NOT rotate the compromised identity's credentials** without approval — the legitimate owner may be mid-session and a forced rotation could cause an outage.
- **Do NOT detach CloudTrail logging SCPs** or modify logging configurations — this would destroy the audit trail.
- **Do NOT notify the compromised identity's owner via email or Slack** if you suspect an insider threat; use out-of-band communication.

---

## Rollback Steps (If Containment Was Applied to a False Positive)

If the investigation later confirms the alert was a benign FP and access was incorrectly revoked:

### Re-activate access keys:

```bash
aws iam update-access-key \
  --user-name "<USERNAME>" \
  --access-key-id "<KEY_ID>" \
  --status Active
```

### Re-attach policies:

```bash
aws iam attach-user-policy \
  --user-name "<USERNAME>" \
  --policy-arn "<POLICY_ARN>"
```

### Re-add to groups:

```bash
aws iam add-user-to-group \
  --user-name "<USERNAME>" \
  --group-name "<GROUP_NAME>"
```

### Remove permission boundary:

```bash
aws iam delete-user-permissions-boundary --user-name "<USERNAME>"
```

### Remove containment deny policy from role:

```bash
aws iam delete-role-policy \
  --role-name "<ROLE_NAME>" \
  --policy-name "INCIDENT-CDET-001-ContainmentDeny"
```

Document all rollback actions in the incident ticket with timestamps and approver names.
