---
detection_id: CDET-002
detection_name: Access Key Created for Another User
tactic: Persistence
technique: T1098.001
last_updated: 2026-06-18
---

# CDET-002 — Containment Playbook
# Access Key Created for Another User

**Prerequisites:** Investigation complete. Evidence preserved. Incident ticket updated.  
**Goal:** Stop the threat actor's access without destroying evidence or causing an unplanned outage.

---

## Approval Requirements

| Action | Approval required before executing |
|---|---|
| Disable the newly created access key | Tier-3 / on-call Cloud Security Engineer |
| Disable or delete the actor's credentials | Tier-3 + Service Owner notification |
| Attach a deny policy to the target user | Tier-3 + Change Management ticket |
| Revoke active IAM role sessions | Tier-3 + impacted team lead (outage risk) |
| Delete the access key | Post-incident only; requires CISO or delegate sign-off |

Do not skip approvals even if the key is actively in use. A 2-minute notification is sufficient for a genuine emergency.

---

## Priority Order of Containment Actions

### Step 1 — Disable the Newly Created Access Key (HIGHEST PRIORITY)

Disabling is reversible. **Do not delete the key at this stage** — deletion destroys the audit trail linking the key ID to events.

```bash
aws iam update-access-key \
  --user-name "<target_username>" \
  --access-key-id "<new_key_id>" \
  --status Inactive
```

Verify the key is now inactive:

```bash
aws iam list-access-keys \
  --user-name "<target_username>" \
  --output json
```

Confirm `Status` is `Inactive` for `<new_key_id>`.

---

### Step 2 — Confirm No Active Sessions Are Using the Key

After disabling, any in-flight API calls using the key will fail. Verify in Splunk that no new events appear after disable time:

```spl
index=aws_cloudtrail userIdentity.accessKeyId="<new_key_id>"
    earliest=<disable_timestamp>
| table _time, eventName, sourceIPAddress, errorCode
```

If events continue after disable (possible in some edge cases with cached credentials), proceed to step 3 immediately.

---

### Step 3 — Disable or Invalidate the Actor's Credentials

Choose the appropriate action based on actor type.

**If actor is an IAM user with a static key:**

```bash
# Disable the actor's key (do not delete yet)
aws iam update-access-key \
  --user-name "<actor_username>" \
  --access-key-id "<actor_key_id>" \
  --status Inactive
```

**If actor used an assumed role session:**

Revoke all active sessions for the role by attaching an inline deny policy with a condition on session issue time. This is a broad action — get approval and notify impacted teams first.

```bash
# Record the exact CreateAccessKey eventTime as the cutoff
# Replace <epoch_time> with the Unix timestamp of the event

aws iam put-role-policy \
  --role-name "<compromised_role_name>" \
  --policy-name "DenyAllBefore-CDET-002-Incident" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "<ISO8601_cutoff_time>"
        }
      }
    }]
  }'
```

This denies all actions for sessions issued before the cutoff. New legitimate sessions issued after this time are unaffected.

---

### Step 4 — Restrict the Target User's Permissions (Quarantine)

If the investigation shows the backdoor key was used to access resources, or if the scope of the target user's permissions is high, attach a quarantine deny policy to the target user:

```bash
aws iam put-user-policy \
  --user-name "<target_username>" \
  --policy-name "CDET-002-Quarantine" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

This does not delete the user or their existing keys — it simply blocks all actions until investigation is complete.

---

### Step 5 — Preserve CloudTrail and S3 Access Logs

Ensure the CloudTrail S3 bucket containing evidence has:
- Object lock or versioning enabled (verify, do not enable mid-incident as this can alter objects).
- No delete lifecycle rules that would purge evidence.

```bash
aws s3api get-bucket-versioning \
  --bucket "<cloudtrail_bucket_name>"

aws s3api get-object-lock-configuration \
  --bucket "<cloudtrail_bucket_name>"
```

If neither is enabled, flag this in the incident ticket as a gap but do not modify the bucket configuration mid-incident.

---

### Step 6 — Notify Stakeholders

- Service owner of the target IAM user (their service may be impacted by the quarantine policy).
- Security leadership if this is a confirmed breach.
- Legal / Compliance if data exfiltration occurred (check S3 GetObject events in investigation).

---

## What NOT to Do

- **Do not delete the access key** during active investigation. Deletion removes the key from `list-access-keys` output and makes it harder to trace subsequent activity.
- **Do not delete the actor's IAM user** before forensic data is collected. Deletion is irreversible and destroys metadata.
- **Do not modify or delete CloudTrail logs** or S3 access logs — this constitutes evidence destruction.
- **Do not revoke all role sessions** without notifying impacted teams — this causes outages for all users of that role, including legitimate ones.
- **Do not rotate all keys in the account** as a precaution without scoping the incident first — mass rotation causes service disruptions and may mask the attacker's activity in the noise.
- **Do not block the source IP at the VPC level** without recording it first — IP blocking alone does not remove the access key.

---

## Rollback / Undo Steps (If Containment Was a False Positive)

If investigation is re-evaluated and the action is determined to be benign (e.g., a newly onboarded automation pipeline not yet in the allowlist):

### Undo: Re-enable a disabled key

```bash
aws iam update-access-key \
  --user-name "<target_username>" \
  --access-key-id "<new_key_id>" \
  --status Active
```

### Undo: Remove the role session-revocation policy

```bash
aws iam delete-role-policy \
  --role-name "<compromised_role_name>" \
  --policy-name "DenyAllBefore-CDET-002-Incident"
```

### Undo: Remove the user quarantine policy

```bash
aws iam delete-user-policy \
  --user-name "<target_username>" \
  --policy-name "CDET-002-Quarantine"
```

After rollback, document the false positive in the incident ticket and proceed to `recovery.md` for tuning recommendations.
