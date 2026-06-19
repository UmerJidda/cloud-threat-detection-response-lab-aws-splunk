---
detection_id: CDET-012
detection_name: Cross-Account Role Assumption
tactic: Lateral Movement
technique: T1550.001
last_updated: 2026-06-18
---

# CDET-012 — Containment Playbook
**Cross-Account Role Assumption**

> **Audience:** Tier-2 SOC Analyst with IAM write permissions (or access to request them)
> **Prerequisites:** Investigation complete; blast radius assessed; evidence preserved.
> **Approval gate:** Steps 4 and 5 (role policy modification and access key deletion) require IR lead sign-off unless the session is still active and data exfiltration is in progress.

---

## Containment Priority Order

1. Revoke the active assumed-role session (lowest blast radius, reversible).
2. Block the source principal in Account A from making further cross-account calls.
3. Restrict the target role's trust policy in Account B.
4. (If warranted) Revoke or disable the compromised credential in Account A.
5. (If warranted) Delete or quarantine newly created IAM resources in Account B.

---

## Step 1 — Revoke All Active Sessions for the Target Role

STS sessions cannot be individually revoked, but you can attach an inline deny policy to the role that invalidates all sessions issued before the current time. This is the fastest way to terminate an active attacker session.

**Approval required: No — this is reversible (see rollback section).**

```bash
# Set the current time in ISO-8601 format
REVOKE_TIME=$(python3 -c "from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")

# Attach an inline policy that denies all actions for sessions issued before now
aws iam put-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --policy-name "INCIDENT-CDET-012-RevokeSessions" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"${REVOKE_TIME}\"
        }
      }
    }]
  }" \
  --profile <ACCOUNT_B_PROFILE>
```

Verify the policy is attached:

```bash
aws iam list-role-policies \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --profile <ACCOUNT_B_PROFILE>
```

---

## Step 2 — Restrict the Source Principal in Account A

If the caller in Account A is an IAM user or role that should not be making cross-account calls, attach a deny policy to block `sts:AssumeRole` to external accounts.

**Approval required: Yes if this is a service account used by production workloads. No if it is a known compromised or decommissioned identity.**

```bash
# For an IAM role in Account A
aws iam put-role-policy \
  --role-name <COMPROMISED_ROLE_IN_ACCOUNT_A> \
  --policy-name "INCIDENT-CDET-012-BlockCrossAccountAssumeRole" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*"
    }]
  }' \
  --profile <ACCOUNT_A_PROFILE>

# For an IAM user in Account A
aws iam put-user-policy \
  --user-name <COMPROMISED_USERNAME> \
  --policy-name "INCIDENT-CDET-012-BlockCrossAccountAssumeRole" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*"
    }]
  }' \
  --profile <ACCOUNT_A_PROFILE>
```

---

## Step 3 — Tighten the Target Role's Trust Policy in Account B

Remove or restrict the trust policy entry that permitted the attacker's principal to assume the role. Replace the existing trust policy with a corrected version that removes the offending principal or adds compensating conditions.

**Approval required: Yes — confirm the correct trust policy with the role owner before applying.**

```bash
# First, capture the current trust policy as backup evidence
aws iam get-role \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --query 'Role.AssumeRolePolicyDocument' \
  --profile <ACCOUNT_B_PROFILE> \
  --output json > /tmp/CDET-012-trust-policy-backup.json

# Apply a corrected trust policy (edit the JSON file first to remove the offending principal)
aws iam update-assume-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --policy-document file:///tmp/CDET-012-corrected-trust-policy.json \
  --profile <ACCOUNT_B_PROFILE>
```

---

## Step 4 — Disable or Rotate the Compromised Credential in Account A

If the source credential is an IAM access key:

**Approval required: Yes for production service accounts. Proceed immediately for interactive user credentials confirmed compromised.**

```bash
# Disable the access key (reversible — preferred over deletion during investigation)
aws iam update-access-key \
  --user-name <USERNAME> \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive \
  --profile <ACCOUNT_A_PROFILE>

# Verify
aws iam list-access-keys \
  --user-name <USERNAME> \
  --profile <ACCOUNT_A_PROFILE>
```

If the source credential is an IAM role session that was itself obtained via another `AssumeRole`, revoke the parent role's sessions using the same `DateLessThan` deny policy pattern from Step 1, applied in the account where that parent role lives.

---

## Step 5 — Quarantine New IAM Resources Created in Account B

If the investigation (query 3d/3f) revealed that the attacker created new IAM users, roles, access keys, or policies in Account B, disable them before deletion to preserve evidence.

**Approval required: Yes — IR lead must confirm before deletion.**

```bash
# Disable any access keys created by the attacker session
aws iam update-access-key \
  --user-name <NEW_USER_CREATED_BY_ATTACKER> \
  --access-key-id <NEW_KEY_ID> \
  --status Inactive \
  --profile <ACCOUNT_B_PROFILE>

# Detach managed policies from attacker-created role
aws iam detach-role-policy \
  --role-name <ATTACKER_CREATED_ROLE> \
  --policy-arn <POLICY_ARN> \
  --profile <ACCOUNT_B_PROFILE>
```

Do not delete these resources yet — preservation for forensics takes priority. Mark them for deletion in the recovery phase.

---

## What NOT to Do

| Action | Why to avoid it |
|---|---|
| **Delete the target role immediately** | Destroys the trust policy evidence and may break legitimate workloads depending on the role. Use the session-revocation deny policy instead. |
| **Delete the CloudTrail trail or S3 log bucket** | Eliminates evidence; this is a criminal offence in some jurisdictions and violates your incident response policy. |
| **Rotate all IAM keys organisation-wide immediately** | Causes a mass outage. Scope the rotation to the confirmed compromised credential only. |
| **Delete the attacker-created IAM resources before forensics** | Removes evidence needed for root-cause analysis and potential legal proceedings. Disable first, preserve, then delete in recovery. |
| **Modify the trust policy of the target role without capturing the original** | Makes it impossible to determine exactly what the attacker exploited. Always backup first (Step 3). |
| **Terminate EC2 instances that used the assumed-role credentials** | Destroys in-memory forensic artifacts. Isolate via security groups instead; involve a forensic analyst. |

---

## Approval Requirements

| Action | Approver |
|---|---|
| Steps 1–2 (session revocation, source principal block) | IR lead or on-call SOC manager |
| Step 3 (trust policy change) | IR lead + role owner (cloud platform team) |
| Step 4 (access key disable) | IR lead (immediate approval if active exfiltration confirmed) |
| Step 5 (quarantine new resources) | IR lead + IR manager |
| Any deletion action | IR manager + legal sign-off if litigation hold is active |

---

## Rollback / Undo Steps (False Positive Confirmed)

If containment actions were taken and the alert is subsequently confirmed as a false positive:

### Undo Step 1 — Remove session-revocation deny policy

```bash
aws iam delete-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --policy-name "INCIDENT-CDET-012-RevokeSessions" \
  --profile <ACCOUNT_B_PROFILE>
```

### Undo Step 2 — Remove cross-account block from source principal

```bash
# For a role
aws iam delete-role-policy \
  --role-name <COMPROMISED_ROLE_IN_ACCOUNT_A> \
  --policy-name "INCIDENT-CDET-012-BlockCrossAccountAssumeRole" \
  --profile <ACCOUNT_A_PROFILE>

# For a user
aws iam delete-user-policy \
  --user-name <USERNAME> \
  --policy-name "INCIDENT-CDET-012-BlockCrossAccountAssumeRole" \
  --profile <ACCOUNT_A_PROFILE>
```

### Undo Step 3 — Restore original trust policy

```bash
aws iam update-assume-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --policy-document file:///tmp/CDET-012-trust-policy-backup.json \
  --profile <ACCOUNT_B_PROFILE>
```

### Undo Step 4 — Re-enable access key

```bash
aws iam update-access-key \
  --user-name <USERNAME> \
  --access-key-id <ACCESS_KEY_ID> \
  --status Active \
  --profile <ACCOUNT_A_PROFILE>
```

After each rollback, verify functionality with the system or team that owns the affected identity before closing the containment ticket.
