---
detection_id: CDET-009
detection_name: S3 Replication to External Account
tactic: Exfiltration
technique: T1537
last_updated: 2026-06-18
---

# CDET-009 — Containment Playbook
## S3 Replication to External Account

**Prerequisite:** Investigation playbook completed. Evidence collected and preserved.  
**Goal:** Stop the ongoing exfiltration, revoke attacker access, and prevent reactivation — without destroying forensic evidence or causing unnecessary service disruption.

---

## Approval Requirements

| Action | Approval Required |
|--------|------------------|
| Remove replication configuration | Cloud Security Lead (or on-call) |
| Disable/delete IAM credentials | Cloud Security Lead + bucket owner |
| Detach or delete IAM policies | Cloud Security Lead + IAM team |
| Delete IAM role | Cloud Security Lead + IAM team + manager approval |
| Block S3 bucket public access / apply deny policy | Cloud Security Lead |
| Suspend AWS account | VP Engineering + CISO |

All containment actions must be logged with: timestamp (UTC), actor performing the action, AWS account ID, resource ARN, and incident ticket number.

---

## Priority Order

Execute in this sequence. Do not skip steps.

```
1. Stop exfiltration (remove replication rule)
2. Revoke attacker credentials
3. Lock down the IAM role(s) used
4. Harden the bucket
5. Notify stakeholders
```

---

## Step 1 — Remove the Replication Configuration

This stops new objects from being replicated. **Data already replicated cannot be recalled from the external account.**

```bash
# Confirm the current replication config before removal (evidence snapshot)
aws s3api get-bucket-replication \
  --bucket <bucket_name> \
  --output json > /tmp/CDET-009_replication_config_<incident_id>.json

# Remove the replication configuration
aws s3api delete-bucket-replication \
  --bucket <bucket_name>

# Verify removal
aws s3api get-bucket-replication --bucket <bucket_name>
# Expected: An error occurred (ReplicationConfigurationNotFoundError)
```

**If multiple buckets are affected** (identified during investigation), repeat for each:
```bash
for bucket in <bucket1> <bucket2> <bucket3>; do
  aws s3api delete-bucket-replication --bucket "$bucket"
  echo "Removed replication from $bucket"
done
```

---

## Step 2 — Revoke Attacker Credentials

### If the attacker used an IAM user access key:

```bash
# List active access keys
aws iam list-access-keys --user-name <username>

# Deactivate the compromised key (preserves forensic history; safer than deletion)
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <access_key_id> \
  --status Inactive

# If console access was used, invalidate the password and MFA
aws iam delete-login-profile --user-name <username>
```

### If the attacker used an assumed IAM role:

Active sessions cannot be revoked directly, but the trust policy can be modified to block new assumptions and existing tokens will expire (default 1 hour, max 12 hours).

```bash
# Immediately revoke all active sessions by adding an explicit deny on sts:AssumeRole
# using a condition that matches all current sessions (via aws:TokenIssueTime)
aws iam put-role-policy \
  --role-name <compromised_role_name> \
  --policy-name INCIDENT_REVOCATION_CDET009 \
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

Replace `<current_utc_timestamp_iso8601>` with the current UTC time (e.g., `2026-06-18T14:30:00Z`). This denies all actions for tokens issued before now.

---

## Step 3 — Lock Down the IAM Role(s)

### Lock the calling identity role:

```bash
# Detach all managed policies
aws iam list-attached-role-policies --role-name <role_name> \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -I {} aws iam detach-role-policy --role-name <role_name> --policy-arn {}

# Remove inline policies
aws iam list-role-policies --role-name <role_name> \
  --query 'PolicyNames' --output text | \
  xargs -I {} aws iam delete-role-policy --role-name <role_name> --policy-name {}

# Replace trust policy with a deny-all (do NOT delete role yet — preserve forensic evidence)
aws iam update-assume-role-policy \
  --role-name <role_name> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
```

### Lock the replication execution role:

```bash
# Apply the same revocation inline policy to the replication role
aws iam put-role-policy \
  --role-name <replication_role_name> \
  --policy-name INCIDENT_REVOCATION_CDET009 \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }'
```

---

## Step 4 — Harden the Bucket

```bash
# Apply a resource-based deny policy blocking the attacker identity and
# any cross-account replication from unrecognized accounts
aws s3api put-bucket-policy \
  --bucket <bucket_name> \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "INCIDENT_DENY_ATTACKER_CDET009",
        "Effect": "Deny",
        "Principal": {"AWS": "<attacker_arn>"},
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::<bucket_name>",
          "arn:aws:s3:::<bucket_name>/*"
        ]
      },
      {
        "Sid": "INCIDENT_DENY_REPLICATION_CONFIG_CDET009",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutReplicationConfiguration",
        "Resource": "arn:aws:s3:::<bucket_name>",
        "Condition": {
          "StringNotEquals": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<own_account_id>:role/<approved_admin_role>"
            ]
          }
        }
      }
    ]
  }'
```

Enable S3 versioning if not already enabled (supports recovery and audit):
```bash
aws s3api put-bucket-versioning \
  --bucket <bucket_name> \
  --versioning-configuration Status=Enabled
```

---

## Step 5 — Notify Stakeholders

Within 30 minutes of beginning containment:
- Notify bucket owner / data owner team
- Notify legal/compliance if the bucket contains regulated data (PII, PCI, HIPAA)
- Notify the AWS account owner
- Update incident ticket with all actions taken, timestamps, and ARNs

If data classification is `sensitive` or higher, begin the breach notification assessment process per the organization's data breach response policy.

---

## What NOT to Do

- **Do NOT delete the attacker's IAM role** before forensics are complete — deletion is irreversible and loses creation metadata and policy history.
- **Do NOT delete the CloudTrail log bucket or disable CloudTrail** — this destroys the evidence trail.
- **Do NOT delete objects from the source bucket** — they may be needed to determine exactly what was exfiltrated.
- **Do NOT suspend the entire AWS account** without VP + CISO approval — this causes service outages.
- **Do NOT attempt to access or take ownership of the external (attacker) bucket** — this may constitute unauthorized access.
- **Do NOT rotate all IAM keys org-wide** without a coordinated plan — this causes widespread outage.

---

## Rollback — If Containment Actions Were Applied to a False Positive

If investigation subsequently determines this was an authorized replication (e.g., a missed change ticket), reverse containment in this order:

1. **Restore the replication configuration** from the evidence snapshot:
   ```bash
   aws s3api put-bucket-replication \
     --bucket <bucket_name> \
     --replication-configuration file:///tmp/CDET-009_replication_config_<incident_id>.json
   ```

2. **Remove the revocation inline policy** from the IAM role:
   ```bash
   aws iam delete-role-policy \
     --role-name <role_name> \
     --policy-name INCIDENT_REVOCATION_CDET009
   ```

3. **Restore the role's original trust policy and attached policies** from the evidence snapshot taken during investigation.

4. **Remove the deny statement** added to the bucket policy, or restore the previous policy from the evidence snapshot:
   ```bash
   aws s3api put-bucket-policy \
     --bucket <bucket_name> \
     --policy file:///tmp/CDET-009_bucket_policy_before_<incident_id>.json
   ```

5. **Re-enable the IAM access key** if it was deactivated:
   ```bash
   aws iam update-access-key \
     --user-name <username> \
     --access-key-id <access_key_id> \
     --status Active
   ```

6. Document the FP in the incident ticket. Update `splunk/lookups/trusted_aws_accounts.csv` and `known_pipeline_actors.csv` to prevent future false positives (coordinate with detection engineer).
