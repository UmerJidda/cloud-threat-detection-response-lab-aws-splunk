---
detection_id: CDET-014
detection_name: CloudTrail Log File Deleted
tactic: Defense Evasion
technique: T1070.004
last_updated: 2026-06-18
---

# CDET-014 — CloudTrail Log File Deleted: Containment

**Prerequisite:** CDET-014 investigation is underway. The incident ticket is open with the triggering event and collected evidence attached. All containment actions use `aws configure` credentials — no hardcoded credentials.

**Before any action:** Confirm with your IR lead that the alert is not a false positive. Containment steps that revoke access or modify bucket policies are disruptive and require the approval checkpoints noted below.

---

## Priority Order Overview

| Priority | Action | Risk Level |
|---|---|---|
| 1 | Preserve all surviving evidence | None |
| 2 | Identify and revoke the compromised credential | Medium — may break legitimate services |
| 3 | Block further access to the CloudTrail log bucket | Low–Medium |
| 4 | Re-enable / verify CloudTrail logging is active | Low |
| 5 | Notify downstream consumers of the log gap | None |

---

## Step 1 — Preserve Surviving Evidence (Do This First)

Before making any changes that could alter state:

1.1. Export the full raw CloudTrail event for the CDET-014 trigger to a local file and attach to ticket.

1.2. Snapshot the current bucket policy and versioning configuration:

```bash
aws s3api get-bucket-policy \
  --bucket <bucket_name> \
  --output json > /tmp/cdet014_bucket_policy_snapshot.json

aws s3api get-bucket-versioning \
  --bucket <bucket_name> > /tmp/cdet014_bucket_versioning_snapshot.json

aws s3api get-bucket-acl \
  --bucket <bucket_name> > /tmp/cdet014_bucket_acl_snapshot.json
```

1.3. Save the full list of delete markers (confirms which objects are gone):

```bash
aws s3api list-object-versions \
  --bucket <bucket_name> \
  --prefix "AWSLogs/" \
  --query "DeleteMarkers[*].[Key,VersionId,LastModified]" \
  --output json > /tmp/cdet014_delete_markers.json
```

1.4. Save the IAM actor's current policy state:

```bash
aws iam get-role --role-name <role_name> \
  --output json > /tmp/cdet014_actor_role_snapshot.json

aws iam list-attached-role-policies --role-name <role_name> \
  --output json > /tmp/cdet014_actor_attached_policies.json
```

Attach all snapshots to the incident ticket. These are your before-state for any rollback.

---

## Step 2 — Revoke the Compromised Credential

**Approval required: IR Lead or Security Manager before revoking production IAM credentials.**

Determine the credential type from `userIdentity.type`:

### 2a. Compromised IAM User Access Key

```bash
# Deactivate the specific access key immediately
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <accessKeyId_from_alert> \
  --status Inactive

# Verify the key is now inactive
aws iam list-access-keys \
  --user-name <username>
```

Do **not** delete the access key yet — it is evidence. Deactivating it stops further use while preserving the record.

### 2b. Compromised AssumedRole Session

If the actor is an assumed role, the session token is typically short-lived, but the underlying role may be compromised. Revoke all active sessions for the role by attaching a deny-all inline policy with a condition based on session creation time:

```bash
# Save the current time as the cutoff
CUTOFF=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Attach a time-based deny policy to revoke all sessions issued before now
aws iam put-role-policy \
  --role-name <role_name> \
  --policy-name CDET014-EmergencyRevoke \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"${CUTOFF}\"
        }
      }
    }]
  }"
```

This inline policy invalidates all sessions created before the current moment without permanently breaking the role.

### 2c. Root Account

If `userIdentity.type = "Root"` triggered this alert, escalate to your CISO immediately. Root access cannot be revoked programmatically — actions required are:

1. Change root account password immediately (requires console access to root).
2. Verify root MFA is configured and not compromised.
3. Review and rotate all IAM user credentials in the account as a precaution.

---

## Step 3 — Block Further Access to the CloudTrail Log Bucket

**Approval required: IR Lead before modifying the bucket policy in production.**

3.1. Remove the compromised principal's explicit permissions from the bucket policy. First inspect the current policy:

```bash
aws s3api get-bucket-policy \
  --bucket <bucket_name>
```

Edit the returned policy to remove any `Statement` entries that grant `s3:DeleteObject` or `s3:*` to the compromised principal, then apply:

```bash
aws s3api put-bucket-policy \
  --bucket <bucket_name> \
  --policy file:///tmp/cdet014_updated_bucket_policy.json
```

3.2. As an additional safeguard, add an explicit deny for `DeleteObject` and `DeleteObjects` on the `AWSLogs/` prefix for all principals except a narrow approved set:

```bash
# Retrieve the current policy, add a Deny statement, and re-apply
# Edit /tmp/cdet014_deny_delete_policy.json to include your specific allowed principals
aws s3api put-bucket-policy \
  --bucket <bucket_name> \
  --policy file:///tmp/cdet014_deny_delete_policy.json
```

Example Deny statement to add to the policy (replace `ACCOUNT_ID` and `BUCKET_NAME`):

```json
{
  "Sid": "CDET014-DenyLogDeletion",
  "Effect": "Deny",
  "Principal": "*",
  "Action": [
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:DeleteObjects"
  ],
  "Resource": "arn:aws:s3:::BUCKET_NAME/AWSLogs/*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": [
        "arn:aws:iam::ACCOUNT_ID:role/approved-log-rotation-role"
      ]
    }
  }
}
```

3.3. Enable S3 Object Lock on the bucket if it is not already enabled (requires bucket versioning to be active). **Note:** enabling Object Lock on an existing bucket requires AWS Support involvement — file an urgent support case if this is needed.

---

## Step 4 — Re-Enable and Verify CloudTrail Logging

If the attacker also disabled the CloudTrail trail (correlated CDET-003 event), re-enable it now:

```bash
# Check current trail status
aws cloudtrail get-trail-status \
  --name <trail_name_or_arn>

# Re-enable logging if it was stopped
aws cloudtrail start-logging \
  --name <trail_name_or_arn>

# Verify logging is now active
aws cloudtrail get-trail-status \
  --name <trail_name_or_arn> \
  --query "IsLogging"
```

Confirm that log delivery is healthy by checking `LatestDeliveryTime` and `LatestDeliveryError` in the trail status output.

---

## Step 5 — Notify Downstream Log Consumers

5.1. Notify the SIEM/Splunk team that there is a confirmed log gap for:
- Account: `<recipientAccountId>`
- Region: `<awsRegion>`
- Time range: `<evidence gap window from investigation>`

5.2. Notify threat hunting and any automated detection pipelines that rely on this log source — alert suppression during the gap window should be reviewed manually.

5.3. Document the gap in the incident ticket so the post-incident review can assess what the attacker may have done undetected.

---

## What NOT to Do

- **Do not delete the compromised IAM access key** — deactivate it only. The key ID is evidence tied to the CloudTrail record and may be needed for legal/forensic review.
- **Do not delete the IAM user or role** — policy revocation is sufficient for containment and preserves the audit trail.
- **Do not wipe or overwrite the S3 bucket** — even partially empty buckets contain surviving log objects and delete markers that are critical evidence.
- **Do not re-enable logging and then immediately run cleanup scripts** — your first priority is evidence preservation, not hygiene.
- **Do not modify the CloudTrail trail configuration** (change S3 bucket, change event selectors) — this can disrupt ongoing delivery and alter evidence about the trail's state at the time of the incident.
- **Do not revoke credentials without IR Lead approval** — revoking a role used by production automation can cause an outage that may be worse than the threat impact.

---

## Rollback / Undo Steps if This Is a False Positive

If containment actions were taken and investigation subsequently confirms a FP:

### Undo Step 2a (re-activate access key):

```bash
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <accessKeyId> \
  --status Active
```

### Undo Step 2b (remove emergency role revocation policy):

```bash
aws iam delete-role-policy \
  --role-name <role_name> \
  --policy-name CDET014-EmergencyRevoke
```

### Undo Step 3 (restore original bucket policy):

```bash
# Re-apply the snapshot saved in Step 1
aws s3api put-bucket-policy \
  --bucket <bucket_name> \
  --policy file:///tmp/cdet014_bucket_policy_snapshot.json
```

### Undo Step 3.2 (remove the deny-delete statement added during containment):

Edit the bucket policy to remove the `CDET014-DenyLogDeletion` Sid and re-apply.

After rollback, document in the ticket why the containment actions were reversed and what evidence confirmed the FP. Update suppression logic to prevent recurrence of the FP.
