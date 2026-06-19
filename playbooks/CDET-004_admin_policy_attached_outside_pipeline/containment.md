---
detection_id: CDET-004
detection_name: Admin Policy Attached Outside Pipeline
tactic: Privilege Escalation
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-004 — Containment Playbook

## Purpose
Stop the active threat by removing unauthorized access while preserving evidence and avoiding collateral damage to production systems.

---

## Approval Requirements

| Action | Required Approval |
|---|---|
| Detach admin policy from target user | Tier-2 analyst self-authorized if confirmed real alert |
| Disable access keys on target user | Tier-2 analyst self-authorized |
| Disable console login (delete login profile) | Tier-2 analyst self-authorized |
| Disable calling actor's access keys | Tier-2 + direct manager of key owner |
| Delete IAM user | Security Manager + team lead — **do not do without approval** |
| Attach an explicit `Deny *` permissions boundary | Tier-2 analyst self-authorized as emergency measure |
| Revoke active sessions (attach deny-all policy to role) | Tier-2 analyst self-authorized |

All containment actions must be logged in the incident ticket with the exact command run, timestamp, and analyst name before execution.

---

## Priority Order of Containment Actions

### Action 1 — Detach the Unauthorized Admin Policy (Highest Priority)

This directly removes the escalated privilege.

```bash
aws iam detach-user-policy \
  --user-name "<target_username>" \
  --policy-arn "<policy_arn>"
```

Verify removal:

```bash
aws iam list-attached-user-policies --user-name "<target_username>"
```

The admin policy ARN must no longer appear in the output.

---

### Action 2 — Disable or Delete Active Access Keys on the Target User

If the attacker has created or is using access keys for the target user, disable them immediately. Disable rather than delete to preserve evidence.

```bash
# List all keys first
aws iam list-access-keys --user-name "<target_username>"

# Disable each active key (do NOT delete yet)
aws iam update-access-key \
  --user-name "<target_username>" \
  --access-key-id "<key_id>" \
  --status Inactive
```

---

### Action 3 — Revoke Console Access on the Target User

If the target user has a console login profile, delete it to prevent password-based access.

```bash
# Check if login profile exists
aws iam get-login-profile --user-name "<target_username>"

# If it exists, delete it
aws iam delete-login-profile --user-name "<target_username>"
```

---

### Action 4 — Contain the Calling Actor (if not an authorized service account)

If the actor that performed `AttachUserPolicy` is a compromised user or role, contain it as well.

**If IAM user:**

```bash
# Disable all access keys
aws iam list-access-keys --user-name "<caller_username>"
aws iam update-access-key \
  --user-name "<caller_username>" \
  --access-key-id "<key_id>" \
  --status Inactive

# Attach an explicit deny-all permissions boundary as emergency measure
aws iam put-user-permissions-boundary \
  --user-name "<caller_username>" \
  --permissions-boundary "arn:aws:iam::aws:policy/AWSDenyAll"
```

**If assumed role (revoke active sessions):**

Attach an inline deny policy to the role to invalidate all current sessions. AWS STS tokens are valid until expiry, but an explicit deny overrides them at evaluation time.

```bash
aws iam put-role-policy \
  --role-name "<role_name>" \
  --policy-name "INCIDENT-CDET-004-EmergencyDeny" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "<current_utc_timestamp_iso8601>"
        }
      }
    }]
  }'
```

Replace `<current_utc_timestamp_iso8601>` with the current UTC time, e.g. `2026-06-18T14:00:00Z`. This denies all actions for tokens issued before now.

---

### Action 5 — Remove Any Attacker-Created Persistence (if found in investigation)

If the investigation (Step 7 of investigation.md) found attacker-created access keys, users, or login profiles:

```bash
# Disable attacker-created access keys
aws iam update-access-key \
  --user-name "<attacker_created_user>" \
  --access-key-id "<attacker_key_id>" \
  --status Inactive

# If an attacker-created user was found, disable all their keys before deletion approval
aws iam list-access-keys --user-name "<attacker_created_user>"
```

Do not delete the user until approved — the user object preserves attribution evidence.

---

## What NOT to Do

- **Do not `DeleteUser` on the target or calling actor** without manager/security lead approval — user deletion destroys IAM policy history and may break existing workloads.
- **Do not `DeleteAccessKey`** during active incident — disable only. Deleted keys cannot be recovered for forensics.
- **Do not rotate the target user's credentials before extracting evidence** — rotation can overwrite key metadata.
- **Do not disable service-linked roles** without confirming they are not used by active AWS services — this can cause immediate service outages.
- **Do not modify S3 bucket policies or KMS keys** that the actor may have changed without first taking a snapshot of current state.
- **Do not close the incident** until recovery steps are complete and a post-incident review is scheduled.

---

## Rollback Steps (If Action Turns Out to Be a False Positive)

If containment was applied and the alert is subsequently confirmed benign:

### Re-attach the policy (if it was an authorized actor):

```bash
aws iam attach-user-policy \
  --user-name "<target_username>" \
  --policy-arn "<policy_arn>"
```

### Re-enable access keys:

```bash
aws iam update-access-key \
  --user-name "<username>" \
  --access-key-id "<key_id>" \
  --status Active
```

### Restore console access:

```bash
aws iam create-login-profile \
  --user-name "<username>" \
  --password "<temporary_password>" \
  --password-reset-required
```

Notify the affected user and their team immediately. Document the FP determination, root cause, and corrective action in the incident ticket. Reference CDET-004 and the `eventID` of the triggering event.

### Remove the emergency deny policy from a role:

```bash
aws iam delete-role-policy \
  --role-name "<role_name>" \
  --policy-name "INCIDENT-CDET-004-EmergencyDeny"
```

---

## Containment Completion Checklist

- [ ] Admin policy detached from target user and verified
- [ ] Target user access keys disabled
- [ ] Target user console login profile removed (if applicable)
- [ ] Calling actor contained (keys disabled or deny policy applied)
- [ ] Attacker-created persistence objects disabled (if any found)
- [ ] All actions logged in incident ticket with timestamps and ARNs
- [ ] Affected service owners notified if containment may impact workloads
- [ ] Proceed to recovery.md
