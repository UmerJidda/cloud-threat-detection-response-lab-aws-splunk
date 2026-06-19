---
detection_id: CDET-010
detection_name: Mass S3 Object Deletion
tactic: Impact
technique: T1485
last_updated: 2026-06-18
---

# CDET-010 — Mass S3 Object Deletion: Containment Playbook

**Audience:** Tier-2 SOC Analyst  
**Prerequisites:** Investigation complete. Blast radius known. Evidence preserved.  
**Critical rule:** Do not take containment actions that destroy evidence or cause service outages without explicit approval from the SOC Lead and Cloud Security Engineer.

---

## Approval Requirements

| Action | Approval Required |
|---|---|
| Disable/delete IAM access key | SOC Lead (verbal or ticketed OK) |
| Detach IAM policy from user or role | SOC Lead + Cloud Security Engineer |
| Apply deny-all bucket policy | SOC Lead + Bucket Owner / App Team |
| Suspend IAM user | SOC Lead + Cloud Security Engineer |
| Block source IP at network level | SOC Lead |
| Delete IAM user or role | Cloud Security Engineer + Engineering Manager |

Record the approver name, timestamp, and approval method (chat, phone, ticket) in the incident ticket before executing any step.

---

## Containment Actions — Priority Order

### Priority 1: Stop Active Session (execute within minutes of TP confirmation)

**1a. Identify all active sessions for the compromised principal**
```bash
# List access keys for the user
aws iam list-access-keys --user-name <username>

# For an assumed role — find active sessions via CloudTrail (no API to list live STS sessions)
# Cross-reference accessKeyId from CloudTrail events
```

**1b. Disable the compromised access key immediately**
```bash
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <AccessKeyId> \
  --status Inactive
```
Note: This is reversible. Prefer `Inactive` over deletion at this stage to preserve evidence (creation date, last used metadata).

**1c. If the session was from an assumed role, attach an explicit deny policy to invalidate in-flight tokens**
```bash
# Create a deny-all inline policy on the role
aws iam put-role-policy \
  --role-name <role-name> \
  --policy-name INCIDENT-CDET-010-DENY-ALL \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "<current_UTC_timestamp_ISO8601>"
        }
      }
    }]
  }'
```
Replace `<current_UTC_timestamp_ISO8601>` with the current time in format `2026-06-18T14:30:00Z`. This denies all tokens issued before now, effectively revoking the compromised session.

---

### Priority 2: Prevent Further Deletions on the Affected Bucket

**2a. Apply a deny-delete bucket policy (requires approval — see table above)**
```bash
# Save current policy first (evidence preservation)
aws s3api get-bucket-policy \
  --bucket <bucket-name> \
  --query Policy \
  --output text > /tmp/CDET-010-original-bucket-policy-<bucket-name>.json

# Apply deny-delete policy (replace <ACCOUNT-ID> and <bucket-name>)
aws s3api put-bucket-policy \
  --bucket <bucket-name> \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "INCIDENT-CDET-010-DenyDelete",
        "Effect": "Deny",
        "Principal": "*",
        "Action": [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:DeleteBucket"
        ],
        "Resource": [
          "arn:aws:s3:::<bucket-name>",
          "arn:aws:s3:::<bucket-name>/*"
        ]
      }
    ]
  }'
```

**2b. Enable S3 Object Lock on the bucket if not already set (forward protection)**
```bash
# Check current Object Lock configuration
aws s3api get-object-lock-configuration --bucket <bucket-name> 2>/dev/null || echo "Object Lock not enabled"
# Note: Enabling Object Lock on an existing bucket requires AWS Support — document for recovery phase
```

**2c. Re-enable versioning if it was disabled by the attacker**
```bash
aws s3api put-bucket-versioning \
  --bucket <bucket-name> \
  --versioning-configuration Status=Enabled
```

---

### Priority 3: Network and Cross-Account Isolation

**3a. If source IP is external and known malicious, block at the bucket policy level**
```bash
# Add a deny-by-IP condition to the bucket policy (merge with step 2a policy)
# Condition block to add:
# "Condition": {"NotIpAddress": {"aws:SourceIp": ["<your-approved-CIDR-list>"]}}
```

**3b. If replication to an external account was configured, remove it immediately**
```bash
# Verify the replication destination account (check approved_aws_accounts.csv)
aws s3api get-bucket-replication --bucket <bucket-name>

# Remove replication configuration
aws s3api delete-bucket-replication --bucket <bucket-name>
```

---

### Priority 4: Broader Principal Isolation (if compromise is confirmed)

**4a. Remove all inline and managed policies from the user (with approval)**
```bash
# List and detach managed policies
aws iam list-attached-user-policies --user-name <username>
aws iam detach-user-policy \
  --user-name <username> \
  --policy-arn <PolicyArn>

# List and delete inline policies
aws iam list-user-policies --user-name <username>
aws iam delete-user-policy \
  --user-name <username> \
  --policy-name <PolicyName>
```

**4b. Remove user from all IAM groups**
```bash
aws iam list-groups-for-user --user-name <username>
aws iam remove-user-from-group \
  --user-name <username> \
  --group-name <GroupName>
```

**4c. Invalidate console password if the user has console access**
```bash
aws iam delete-login-profile --user-name <username>
# Note: This is irreversible for the profile itself but the password can be reset
```

---

## What NOT to Do

These actions would destroy evidence, cause outages, or complicate recovery — do not perform without explicit senior approval and documented justification:

- **Do NOT delete the IAM user or role** during active investigation — you need the policy snapshot and activity history.
- **Do NOT delete the access key** (only disable/make Inactive) — deletion removes creation date and last-used metadata needed for timeline.
- **Do NOT empty the bucket or run additional deletions** to "clean up" — you may overwrite delete markers that are the only record of what was destroyed.
- **Do NOT delete CloudTrail events** or modify the logging configuration during investigation.
- **Do NOT apply MFA delete on the bucket** during incident response — this requires root credentials and can create operational issues.
- **Do NOT force-delete the bucket** if objects still exist — confirm with the application team that the bucket is truly expendable.
- **Do NOT revoke all active STS sessions account-wide** unless the scope of compromise extends beyond this principal — this causes a widespread outage.

---

## Rollback Steps (if containment action was triggered on a FP)

If triage or investigation later determines the activity was benign, reverse containment in this order:

1. **Restore original bucket policy:**
   ```bash
   aws s3api put-bucket-policy \
     --bucket <bucket-name> \
     --policy file:///tmp/CDET-010-original-bucket-policy-<bucket-name>.json
   ```

2. **Re-enable the access key:**
   ```bash
   aws iam update-access-key \
     --user-name <username> \
     --access-key-id <AccessKeyId> \
     --status Active
   ```

3. **Remove the role deny-all inline policy (if applied):**
   ```bash
   aws iam delete-role-policy \
     --role-name <role-name> \
     --policy-name INCIDENT-CDET-010-DENY-ALL
   ```

4. **Re-attach any detached managed policies** (use the list preserved in the incident ticket).

5. **Notify the bucket owner and application team** that access has been restored; confirm their operations are normal.

6. Document the FP determination, root cause of the false positive, and all rollback actions in the incident ticket.

---

## Containment Completion Checklist

- [ ] Compromised access key disabled or revoked session via role policy
- [ ] Bucket deny-delete policy applied
- [ ] Versioning re-enabled (if it was disabled)
- [ ] Any unauthorized replication removed
- [ ] All containment actions logged in incident ticket with approver names and timestamps
- [ ] Application team notified of bucket policy change and potential service impact
- [ ] Evidence collection confirmed complete before proceeding to recovery

**Next step:** Proceed to `recovery.md`.
