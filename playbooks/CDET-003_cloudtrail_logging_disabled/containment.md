---
detection_id: CDET-003
detection_name: CloudTrail Logging Disabled
tactic: Defense Evasion
technique: T1562.008
last_updated: 2026-06-18
---

# CDET-003 — CloudTrail Logging Disabled: Containment

**Prerequisite:** Investigation complete. Incident ticket open. Escalation path confirmed. AWS CLI configured via `aws configure` (no hardcoded credentials).

**Approval gate:** Steps marked **[APPROVAL REQUIRED]** must receive explicit sign-off from an IR lead or security manager before execution. Document the approver's name and time in the incident ticket.

---

## Containment Priority Order

1. Re-enable CloudTrail logging immediately (highest priority — restores visibility).
2. Isolate the compromised principal (prevent further attacker actions).
3. Revoke active sessions for the principal.
4. Scope blast radius and preserve evidence before any destructive remediation.

---

## Step 1 — Re-Enable CloudTrail Logging

This is your first action. Restoring logging visibility takes precedence over principal isolation so that all subsequent activity is captured.

### 1a. If `StopLogging` was used (trail still exists)
```bash
aws cloudtrail start-logging \
  --name "<trail_name_or_arn>" \
  --region "<trail_home_region>"
```

Verify logging is active:
```bash
aws cloudtrail get-trail-status \
  --name "<trail_name_or_arn>" \
  --region "<trail_home_region>" \
  --query "{IsLogging:IsLogging, LatestDeliveryTime:LatestDeliveryTime}"
```

Expected: `"IsLogging": true`

### 1b. If `DeleteTrail` was used (trail no longer exists)

**[APPROVAL REQUIRED]** — Re-creating a trail modifies account configuration.

Collect the original trail configuration from the investigation evidence, then re-create:

```bash
aws cloudtrail create-trail \
  --name "<original_trail_name>" \
  --s3-bucket-name "<original_log_bucket>" \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --region "<original_home_region>"

aws cloudtrail start-logging \
  --name "<original_trail_name>" \
  --region "<original_home_region>"
```

If multi-region trail covered additional regions, verify shadow trail status in each:
```bash
aws cloudtrail describe-trails --include-shadow-trails \
  --query "trailList[?Name=='<trail_name>']"
```

### 1c. Add CloudWatch Logs integration if not already present
```bash
aws cloudtrail update-trail \
  --name "<trail_name_or_arn>" \
  --cloud-watch-logs-log-group-arn "<log_group_arn>" \
  --cloud-watch-logs-role-arn "<iam_role_arn_for_delivery>"
```

---

## Step 2 — Isolate the Compromised Principal

Choose the appropriate sub-step based on the principal type.

### 2a. Attach an explicit deny policy to the IAM user or role

**[APPROVAL REQUIRED]** — Attaching a deny policy will break any legitimate workloads using this principal.

Create a deny-all policy file:
```bash
cat > /tmp/deny-all.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CDET003DenyAll",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
```

Apply to an IAM user:
```bash
aws iam put-user-policy \
  --user-name "<username>" \
  --policy-name "CDET003-Incident-DenyAll" \
  --policy-document file:///tmp/deny-all.json
```

Apply to an IAM role:
```bash
aws iam put-role-policy \
  --role-name "<role_name>" \
  --policy-name "CDET003-Incident-DenyAll" \
  --policy-document file:///tmp/deny-all.json
```

### 2b. Disable long-term access keys (IAM user only)

```bash
# Identify active keys
aws iam list-access-keys --user-name "<username>"

# Disable each active key (deactivate rather than delete — preserves forensic record)
aws iam update-access-key \
  --user-name "<username>" \
  --access-key-id "<key_id>" \
  --status Inactive
```

**Do NOT delete the access key at this stage** — see "What NOT to Do" below.

### 2c. Disable console access (IAM user only)

```bash
aws iam delete-login-profile --user-name "<username>"
```

If you need to preserve the login profile for forensic metadata, note the password last-used date first:
```bash
aws iam get-login-profile --user-name "<username>"
```

---

## Step 3 — Revoke Active Sessions

### 3a. Revoke all active assumed-role sessions for a role

This sets a policy condition that invalidates any token issued before the current time.

**[APPROVAL REQUIRED]** — This will terminate all active sessions for the role, including legitimate ones.

```bash
aws iam put-role-policy \
  --role-name "<role_name>" \
  --policy-name "AWSRevokeOlderSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"
        }
      }
    }]
  }'
```

### 3b. If Root account was the actor

**[APPROVAL REQUIRED — IR Lead + CISO]**

- Immediately notify the CISO and IR lead.
- Log into the AWS console using a secondary break-glass account and rotate the root password.
- Disable root user MFA device if it may be compromised, then re-enroll immediately.
- Do not perform root account remediation via CLI — use the console.

---

## Step 4 — Scope the Blast Radius

Before any further remediation, confirm the scope using the investigation timeline:

- Were any other trails disabled in the same window? (Use investigation query 3a.)
- Were any IAM users, access keys, or roles created during the blind window? (Use investigation query 3e / AWS CLI 4e.)
- Were any S3 log objects deleted? (Use investigation query 3e.)
- Were any other CDET detections fired from the same principal or IP in the past 48 hours?

Document all affected resources in the incident ticket before proceeding to any destructive remediation.

---

## What NOT to Do

These actions would destroy forensic evidence or cause unnecessary outage:

| Action | Why Forbidden |
|---|---|
| `aws iam delete-access-key` on the compromised key | Destroys audit evidence of key usage; deactivation is sufficient |
| `aws iam delete-user` on the compromised user | Destroys IAM audit metadata before forensics are complete |
| `aws iam delete-role` on the compromised role | Destroys role trust policy and permission evidence |
| Deleting CloudWatch Logs log groups or S3 log objects | Destroys log evidence; preserve these for the post-incident review |
| Terminating EC2 instances launched during the blind window without first creating a snapshot | Destroys volatile forensic data on running instances |
| Revoking sessions without approval | May break legitimate production workloads using the same role |

---

## Rollback / Undo Steps (If Containment Was Applied to an FP)

If investigation subsequently confirms the alert was a benign FP, reverse containment in this order:

### Undo the deny-all inline policy (user)
```bash
aws iam delete-user-policy \
  --user-name "<username>" \
  --policy-name "CDET003-Incident-DenyAll"
```

### Undo the deny-all inline policy (role)
```bash
aws iam delete-role-policy \
  --role-name "<role_name>" \
  --policy-name "CDET003-Incident-DenyAll"
```

### Undo the session revocation policy (role)
```bash
aws iam delete-role-policy \
  --role-name "<role_name>" \
  --policy-name "AWSRevokeOlderSessions"
```

### Re-activate an access key
```bash
aws iam update-access-key \
  --user-name "<username>" \
  --access-key-id "<key_id>" \
  --status Active
```

### Re-enable console access
```bash
# Coordinate with the account owner to reset their password via the IAM console
# or have them use the forgot-password flow — do not set a password on their behalf.
```

After rolling back, document the FP justification in the incident ticket, reference the change ticket, and update suppression as described in `recovery.md`.
