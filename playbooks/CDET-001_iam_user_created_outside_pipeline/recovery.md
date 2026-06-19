---
detection_id: CDET-001
detection_name: IAM User Created Outside Pipeline
tactic: Persistence
technique: T1136.003
last_updated: 2026-06-18
---

# CDET-001 — Recovery Playbook
**IAM User Created Outside Pipeline**

> **Audience:** Tier-2 SOC Analyst with AWS IAM experience
> **Prerequisites:** Containment complete and confirmed; attacker access blocked
> **Goal:** Restore normal operations, harden the environment, and improve detection

---

## 1. Verify the Threat Has Been Fully Removed

Complete all checks before declaring the environment clean.

### 1a. Confirm the backdoor user is fully locked down

```bash
# Verify all access keys are inactive
aws iam list-access-keys --user-name "<NEW_USERNAME>" --output json

# Verify no policies remain attached
aws iam list-attached-user-policies --user-name "<NEW_USERNAME>" --output json
aws iam list-user-policies --user-name "<NEW_USERNAME>" --output json

# Verify not a member of any groups
aws iam list-groups-for-user --user-name "<NEW_USERNAME>" --output json

# Confirm deny permission boundary is in place
aws iam get-user --user-name "<NEW_USERNAME>" --output json | grep -i boundary
```

### 1b. Confirm no further API activity from the backdoor user

```spl
index=aws_cloudtrail userIdentity.arn="<NEW_USER_ARN>"
  earliest=<CONTAINMENT_TIME> latest=now
| stats count BY eventName, sourceIPAddress
```

If any events appear after containment time, the attacker may have additional credential paths. Re-examine the investigation.

### 1c. Scan for additional backdoor users created in the same window

```spl
index=aws_cloudtrail eventName=CreateUser
  earliest=<48H_BEFORE_ALERT> latest=now
| table _time, userIdentity.arn, requestParameters.userName, sourceIPAddress
| sort + _time
```

Cross-reference every `userName` against `splunk/lookups/iam_naming_conventions.csv`. Flag any that do not match approved patterns.

### 1d. Check for additional persistence mechanisms set up by the same caller

```bash
# List all roles with trust policies that reference unknown external principals
aws iam list-roles --output json | python3 -c "
import json, sys
roles = json.load(sys.stdin)['Roles']
for r in roles:
    doc = r.get('AssumeRolePolicyDocument', {})
    for stmt in doc.get('Statement', []):
        principal = stmt.get('Principal', {})
        print(r['RoleName'], json.dumps(principal))
" 2>/dev/null
```

Look for roles with trust relationships pointing to unexpected accounts, services, or SAML providers.

---

## 2. Delete the Backdoor User (After Evidence Preservation Confirmed)

Only proceed after IR lead approval and confirmation that all evidence JSON files are archived.

```bash
# Delete access keys first (required before user deletion)
aws iam delete-access-key \
  --user-name "<NEW_USERNAME>" \
  --access-key-id "<KEY_ID>"

# Delete login profile if it exists
aws iam delete-login-profile --user-name "<NEW_USERNAME>" 2>/dev/null || true

# Remove permission boundary
aws iam delete-user-permissions-boundary --user-name "<NEW_USERNAME>"

# Finally delete the user
aws iam delete-user --user-name "<NEW_USERNAME>"
```

Confirm deletion:

```bash
aws iam get-user --user-name "<NEW_USERNAME>" --output json 2>&1
# Expected: "NoSuchEntityException"
```

---

## 3. Restore the Compromised Calling Identity

### 3a. Rotate credentials for the compromised identity

If the caller was an IAM user with long-lived access keys:

```bash
# Create new access key for the legitimate owner
aws iam create-access-key --user-name "<CALLER_USERNAME>" --output json

# Deactivate (or delete) the old compromised key after the new one is confirmed working
aws iam delete-access-key \
  --user-name "<CALLER_USERNAME>" \
  --access-key-id "<COMPROMISED_KEY_ID>"
```

Work with the legitimate key owner to update their local `~/.aws/credentials` or secrets manager entries.

### 3b. Remove the containment deny policy from the calling role (if applicable)

```bash
aws iam delete-role-policy \
  --role-name "<ROLE_NAME>" \
  --policy-name "INCIDENT-CDET-001-ContainmentDeny"
```

### 3c. Verify the legitimate workload / user is operational

Confirm with the account owner that their pipeline or application is running normally after credential rotation.

---

## 4. Hardening Steps to Prevent Recurrence

### 4a. Enforce a permission boundary on all IAM users at creation time

Create an SCP that requires a permission boundary whenever `iam:CreateUser` is called:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequirePermBoundaryOnCreateUser",
      "Effect": "Deny",
      "Action": "iam:CreateUser",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::<ACCOUNT_ID>:policy/StandardUserBoundary"
        }
      }
    }
  ]
}
```

### 4b. Restrict CreateUser to known pipeline roles via SCP

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCreateUserOutsidePipeline",
      "Effect": "Deny",
      "Action": "iam:CreateUser",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::<ACCOUNT_ID>:role/PipelineIAMAdminRole",
            "arn:aws:iam::<ACCOUNT_ID>:role/TerraformExecutionRole"
          ]
        }
      }
    }
  ]
}
```

### 4c. Enable MFA requirement for all human IAM identities

```bash
# Attach MFA enforcement policy to all human user groups
aws iam attach-group-policy \
  --group-name "HumanUsers" \
  --policy-arn "arn:aws:iam::aws:policy/IAMUserMFARequired"
```

### 4d. Enable IAM Access Analyzer

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name "AccountAnalyzer" \
  --type ACCOUNT \
  --output json
```

Access Analyzer will alert on IAM users and roles with external trust relationships.

### 4e. Enforce CloudTrail multi-region logging and log file validation

```bash
aws cloudtrail update-trail \
  --name "<TRAIL_NAME>" \
  --is-multi-region-trail \
  --enable-log-file-validation
```

### 4f. Update authorized_automation_roles.csv

Add any newly created legitimate pipeline roles to `splunk/lookups/authorized_automation_roles.csv` so future alerts from those roles can be correctly triaged as FP.

---

## 5. Detection Tuning Recommendations

### 5a. Suppression (use sparingly)

Only suppress if the false positive rate is consistently high and the calling identity is fully trusted:

- Add confirmed pipeline ARNs to `splunk/lookups/authorized_automation_roles.csv`
- Add `userAgent` strings specific to your CI/CD platform (e.g., `Terraform/1.5.0`) as a secondary suppression filter — **never** as a primary filter alone
- Do **not** suppress based on IP range alone; IPs can be spoofed or rotated

### 5b. Enrichment to reduce analyst burden

Enrich the CDET-001 alert with the following context automatically before it reaches the analyst:

1. Lookup result from `authorized_automation_roles.csv` — attach as `is_known_pipeline_actor` field
2. Lookup result from `trusted_cidr_ranges.csv` — attach as `is_trusted_ip` field
3. Count of sensitive IAM events by the same caller in the past 24 hours — attach as `caller_recent_iam_event_count`
4. Whether the new user received an access key or policy within 5 minutes — attach as `immediate_permissions_granted`

### 5c. New detection candidates identified during this incident

| Detection opportunity | Suggested ID | Priority |
|---|---|---|
| `CreateAccessKey` for a user created in the last 10 minutes | CDET-002 (proposed) | High |
| `AttachUserPolicy` with AdministratorAccess ARN | CDET-003 (proposed) | High |
| `CreateLoginProfile` on a newly created user | CDET-004 (proposed) | Medium |
| Caller with `mfaAuthenticated: false` performing IAM write actions | CDET-005 (proposed) | Medium |

---

## 6. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Root cause identified and documented (how was the calling identity compromised?)
- [ ] Timeline of attacker activity fully reconstructed and attached to ticket
- [ ] All evidence files archived in the designated incident S3 bucket or case management system
- [ ] Affected account owner notified and credential rotation confirmed
- [ ] SCP / permission boundary hardening changes deployed to affected accounts
- [ ] `authorized_automation_roles.csv` updated with any newly discovered legitimate actors
- [ ] Detection tuning changes (suppression / enrichment) implemented and peer-reviewed
- [ ] New detection candidates (section 5c) submitted to detection backlog
- [ ] CDET-001 alert volume, MTTD, and MTTR metrics recorded for the security metrics dashboard
- [ ] Lessons learned shared with the broader SOC team (blameless post-mortem format)
- [ ] Incident ticket status set to CLOSED with final verdict, timeline summary, and CDET-001 reference

---

## Recovery Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| IR Lead | | | |
| Account Owner | | | |
| SOC Manager | | | |
