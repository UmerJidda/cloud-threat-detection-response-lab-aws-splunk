---
detection_id: CDET-004
detection_name: Admin Policy Attached Outside Pipeline
tactic: Privilege Escalation
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-004 — Recovery Playbook

## Purpose
Restore normal, secure operations after containment of an unauthorized admin policy attachment. Verify the threat is fully removed, harden the environment, and improve detection to prevent recurrence.

---

## Step 1 — Verify the Threat Is Fully Removed

### 1a. Confirm the unauthorized admin policy is no longer attached

```bash
aws iam list-attached-user-policies --user-name "<target_username>"
```

The admin policy (`AdministratorAccess` or equivalent) must not appear. If it does, return to containment.md Action 1.

### 1b. Confirm no residual admin inline policies exist

```bash
aws iam list-user-policies --user-name "<target_username>"
# For each returned policy name:
aws iam get-user-policy \
  --user-name "<target_username>" \
  --policy-name "<inline_policy_name>"
```

Review the policy document for wildcard `Action: *` or `Resource: *` statements. Remove any unauthorized inline policies:

```bash
aws iam delete-user-policy \
  --user-name "<target_username>" \
  --policy-name "<inline_policy_name>"
```

### 1c. Confirm no attacker-created IAM users, roles, or OIDC/SAML providers remain

```bash
# Check for users created during the attack window
aws iam list-users --query 'Users[?CreateDate>=`<attack_start_time>`]'

# Check for roles created during the attack window
aws iam list-roles --query 'Roles[?CreateDate>=`<attack_start_time>`]'

# Check for OIDC providers (attacker persistence mechanism)
aws iam list-open-id-connect-providers

# Check for SAML providers
aws iam list-saml-providers
```

Investigate any entries created during the attack window. Remove if unauthorized (with manager approval for user/role deletion).

### 1d. Confirm all attacker access keys are disabled or deleted

```bash
aws iam list-access-keys --user-name "<target_username>"
aws iam list-access-keys --user-name "<caller_username>"
```

Status must be `Inactive` or the keys must be absent for any key created or used during the incident.

---

## Step 2 — Credential Rotation

Treat any credentials that may have been exposed during the incident as compromised:

1. **Target user** — generate new access keys only after threat removal is confirmed, immediately deactivate and delete the old (now inactive) keys.

   ```bash
   aws iam create-access-key --user-name "<target_username>"
   # Securely distribute new key to the legitimate owner
   aws iam delete-access-key \
     --user-name "<target_username>" \
     --access-key-id "<old_key_id>"
   ```

2. **Calling actor** — if the actor's credentials were compromised (not a pipeline service account), rotate them and force a password reset.

3. **Any secrets stored alongside the compromised credentials** — rotate API tokens, database passwords, or third-party keys that may have been accessible to the attacker using the elevated IAM permissions.

---

## Step 3 — Restore Authorized State

### 3a. Remove the emergency deny policy from the calling role (if applied)

```bash
aws iam delete-role-policy \
  --role-name "<role_name>" \
  --policy-name "INCIDENT-CDET-004-EmergencyDeny"
```

### 3b. Re-attach correct, scoped policies to the target user

Coordinate with the resource owner to confirm what permissions the target user legitimately requires. Apply least-privilege policies only:

```bash
aws iam attach-user-policy \
  --user-name "<target_username>" \
  --policy-arn "<least_privilege_policy_arn>"
```

### 3c. Restore target user console access if applicable

```bash
aws iam create-login-profile \
  --user-name "<target_username>" \
  --password "<temporary_password>" \
  --password-reset-required
```

Notify the user directly via out-of-band channel (not email that may be compromised).

---

## Step 4 — Hardening Steps to Prevent Recurrence

### 4a. Enforce SCP to block direct `AttachUserPolicy` outside pipeline roles

Add or verify a Service Control Policy (SCP) in AWS Organizations that denies `iam:AttachUserPolicy` except for explicitly authorized pipeline role ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAttachAdminPolicyOutsidePipeline",
      "Effect": "Deny",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::<account_id>:role/<authorized_pipeline_role>"
          ]
        },
        "StringEquals": {
          "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      }
    }
  ]
}
```

### 4b. Enforce MFA for all human IAM users

```bash
# Verify MFA is enforced via IAM policy or SCP
aws iam list-virtual-mfa-devices
```

Ensure all human users have an MFA device assigned. Add an SCP or IAM policy that denies all actions when `aws:MultiFactorAuthPresent` is false.

### 4c. Enable IAM Access Analyzer

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name "CDET-004-PostIncident" \
  --type ACCOUNT
```

Review findings for any external access granted during the attack window.

### 4d. Review and tighten the `authorized_pipeline_principals.csv` lookup

- Remove any stale pipeline role ARNs.
- Add `last_reviewed` and `owner` columns if not present.
- Schedule a quarterly review of the lookup.

**Lookup CSV path:** `splunk/lookups/authorized_pipeline_principals.csv`

### 4e. Enable CloudTrail for all regions and ensure log integrity validation

```bash
aws cloudtrail describe-trails
# Confirm IsMultiRegionTrail=true and LogFileValidationEnabled=true
```

---

## Step 5 — Detection Tuning Recommendations

### Suppression (reduce FP noise)
- If the pipeline legitimately attaches admin policies during specific deployment windows, enrich the alert with a scheduled window field rather than suppressing entirely.
- Add pipeline role ARNs to `authorized_pipeline_principals.csv` with accurate `role` and `owner` metadata. CDET-004 should filter on this lookup — do not add broad wildcards.
- Do not suppress on `userAgent` alone — agents like `aws-cli` and `Boto3` are used by both attackers and pipelines.

### Enrichment (increase signal quality)
- Add a lookup join on `requestParameters.policyArn` to flag only genuinely privileged policies (avoid firing on read-only policy attachments).
- Enrich alerts with the target user's account age and last activity to quickly surface newly created or dormant accounts.
- Correlate with `CreateAccessKey` and `CreateLoginProfile` in the same detection window to auto-elevate severity when persistence is created alongside the attachment.
- Add `recipientAccountId` to the alert output and join against an account classification lookup (prod vs. dev vs. sandbox) to auto-adjust priority.

---

## Post-Incident Review Checklist

Schedule the review within 5 business days of incident closure.

**Timeline and Scope**
- [ ] Confirmed exact time of initial unauthorized policy attachment
- [ ] Confirmed whether attacker achieved any downstream access with elevated permissions
- [ ] Confirmed full scope of data or resources the attacker could have accessed
- [ ] Confirmed all attacker-created artifacts (users, keys, providers) are removed

**Root Cause**
- [ ] Identified how the calling actor's credentials were compromised
- [ ] Identified whether this was an insider threat or external actor
- [ ] Identified the gap that allowed the attachment to succeed (missing SCP, over-permissioned role, etc.)

**Detection and Response**
- [ ] CDET-004 alert fired within expected time window
- [ ] Triage time (alert to escalation decision) documented
- [ ] Containment time (escalation to policy detached) documented
- [ ] Any detection gaps identified (e.g., attacker actions that did not generate an alert)

**Corrective Actions**
- [ ] All hardening steps from Step 4 applied or tickets created with owners and due dates
- [ ] Detection tuning changes implemented or scheduled
- [ ] `authorized_pipeline_principals.csv` reviewed and updated
- [ ] Affected teams notified and briefed on outcome
- [ ] Incident report distributed to security leadership

**Metrics to Record**
- Mean time to detect (MTTD): alert timestamp minus estimated attack timestamp
- Mean time to contain (MTTC): alert timestamp minus policy-detached timestamp
- False positive rate for CDET-004 over the past 30 days
