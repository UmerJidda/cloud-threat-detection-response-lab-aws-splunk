---
detection_id: CDET-005
detection_name: Cross-Account Trust Modified
tactic: Privilege Escalation
technique: T1484.002
last_updated: 2026-06-18
---

# CDET-005 — Cross-Account Trust Modified: Recovery Playbook

**Audience:** Tier-2 SOC Analyst  
**Prerequisite:** Containment actions from `containment.md` are complete and verified.  
**Goal:** Restore normal operations, verify the threat is fully removed, harden to prevent recurrence.

---

## 1 — Verify the Threat is Fully Removed

Complete all checks before removing containment controls.

### 1a — Confirm the trust policy contains only approved principals

```bash
aws iam get-role \
    --role-name "<ROLE_NAME>" \
    --query "Role.AssumeRolePolicyDocument" \
    --output json
```

Verify output against `splunk/lookups/approved_external_accounts.csv`. No unknown account IDs should appear in any `Principal` statement.

### 1b — Confirm no active sessions remain from the malicious external account

Run the following Splunk query for the 13 hours after the initial `UpdateAssumeRolePolicy` event (maximum role session lifetime):

```spl
index=aws_cloudtrail eventName=AssumeRole
    requestParameters.roleArn="arn:aws:iam::<VICTIM_ACCOUNT>:role/<ROLE_NAME>"
    userIdentity.accountId="<MALICIOUS_ACCOUNT_ID>"
    earliest=<MODIFY_EVENT_TIME> latest=+13h
| table _time, userIdentity.arn, requestParameters.roleSessionName, sourceIPAddress
```

If results appear after the containment timestamp, those sessions may still be active. Confirm the `RevokeOldSessions` inline policy was applied and covers those session issue times.

### 1c — Confirm the actor's access key is disabled

```bash
aws iam list-access-keys \
    --user-name "<ACTOR_USERNAME>" \
    --query "AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}" \
    --output json
```

Status must show `Inactive` for the key used in the incident.

### 1d — Verify no new IAM changes were made under the compromised session

```spl
index=aws_cloudtrail eventSource=iam.amazonaws.com
    userIdentity.sessionContext.sessionIssuer.arn="arn:aws:iam::<VICTIM_ACCOUNT>:role/<ROLE_NAME>"
    earliest=<MODIFY_EVENT_TIME>
| table _time, eventName, requestParameters, sourceIPAddress
| sort -_time
```

Any `CreateRole`, `AttachRolePolicy`, `CreateUser`, `CreateAccessKey`, or `PutUserPolicy` events here represent persistence artifacts that must be individually remediated.

---

## 2 — Restore Normal Operations

### 2a — Remove IR containment controls after verification

Once checks 1a–1d pass:

```bash
# Remove the explicit-deny permission boundary from the role
aws iam delete-role-permissions-boundary \
    --role-name "<ROLE_NAME>"

# Remove the session-revocation inline policy
aws iam delete-role-policy \
    --role-name "<ROLE_NAME>" \
    --policy-name "RevokeOldSessions"
```

### 2b — Handle the compromised IAM principal

Options in order of preference:

1. **Rotate the access key** (preferred if the actor account is legitimate but key was stolen):
   ```bash
   # Create a new key first, update applications, then delete the old key
   aws iam create-access-key --user-name "<ACTOR_USERNAME>"
   # After applications are updated:
   aws iam delete-access-key \
       --user-name "<ACTOR_USERNAME>" \
       --access-key-id "<OLD_ACCESS_KEY_ID>"
   ```

2. **Delete the user and re-provision** (if the account itself is considered compromised and no legitimate owner is identified).

### 2c — Verify dependent services are healthy

Notify the service owner and confirm that applications using the modified role are operating normally after the permission boundary is removed. Check application logs and any CloudWatch alarms tied to the role.

---

## 3 — Hardening Steps to Prevent Recurrence

### 3a — Apply least-privilege to `iam:UpdateAssumeRolePolicy`

Audit which principals have `iam:UpdateAssumeRolePolicy`. This permission should be restricted to a small group of named IAM admins or a dedicated break-glass role.

```bash
# Find all policies that grant iam:UpdateAssumeRolePolicy
aws iam list-policies --scope Local --output json | \
    jq -r '.Policies[].Arn' | while read arn; do
    aws iam get-policy-version \
        --policy-arn "$arn" \
        --version-id "$(aws iam get-policy --policy-arn "$arn" \
            --query 'Policy.DefaultVersionId' --output text)" \
        --output json | \
    grep -q "UpdateAssumeRolePolicy" && echo "$arn"
done
```

### 3b — Implement an SCP to restrict cross-account trust additions

Add an Organizations SCP that requires trust policy changes to reference only approved account IDs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnknownCrossAccountTrust",
      "Effect": "Deny",
      "Action": "iam:UpdateAssumeRolePolicy",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    }
  ]
}
```

Note: A complete implementation requires a custom Lambda-backed Config rule or IAM Access Analyzer policy check to validate the `policyDocument` content, as SCPs cannot inspect request body parameters directly.

### 3c — Enable IAM Access Analyzer for cross-account findings

```bash
aws accessanalyzer create-analyzer \
    --analyzer-name "cross-account-trust-analyzer" \
    --type ACCOUNT \
    --output json
```

Access Analyzer will flag any role accessible from outside the account, creating a baseline inventory.

### 3d — Tag high-privilege roles and alert on their modification

Apply a tag to sensitive roles, then create a CloudWatch Events rule for `UpdateAssumeRolePolicy` scoped to those roles:

```bash
aws iam tag-role \
    --role-name "<HIGH_PRIVILEGE_ROLE>" \
    --tags Key=sensitivity,Value=high Key=ir-monitor,Value=true
```

### 3e — Enable multi-factor authentication enforcement for IAM admin actions

Require MFA for any principal with `iam:UpdateAssumeRolePolicy` by adding the following condition to IAM policies:

```json
{
  "Effect": "Deny",
  "Action": "iam:UpdateAssumeRolePolicy",
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

---

## 4 — Detection Tuning Recommendations

### 4a — Suppression (reduce FP noise)

Update `splunk/lookups/approved_iam_admins.csv` and `splunk/lookups/approved_cross_account_roles.csv` to include:
- The confirmed legitimate actor from this incident (if it was a FP)
- Any CI/CD pipeline service accounts that routinely update trust policies during deployments
- Scheduled IaC drift-correction jobs

Add a suppression filter to the CDET-005 Splunk alert:

```spl
| lookup approved_iam_admins.csv userIdentity.arn OUTPUT is_approved_admin
| lookup approved_cross_account_roles.csv requestParameters.roleName OUTPUT is_approved_role
| where NOT (is_approved_admin="true" AND is_approved_role="true")
```

### 4b — Enrichment (improve signal quality)

Add the following enrichments to the alert to reduce triage time:
- Join `requestParameters.policyDocument` with `approved_external_accounts.csv` to immediately flag unknown principals
- Add a `role_attached_policies` lookup that maps role names to their attached policy names, so analysts see `AdministratorAccess` in the alert body without running a separate query
- Include IP geolocation and ASN in the alert via a `maxmind_geo` lookup

### 4c — New detection opportunities from this incident

Consider creating additional detections for:
- `AssumeRole` calls from accounts not in `approved_external_accounts.csv` (catches Step 3 of the attack chain even if Step 2 was missed)
- High-volume read-only IAM enumeration (`GetRole`, `ListRoles`, `ListAttachedRolePolicies`) by a single principal in a short window (pre-attack reconnaissance)

---

## 5 — Post-Incident Review Checklist

Complete within 5 business days of incident closure:

- [ ] Timeline documented from initial access through containment in case management system
- [ ] Root cause identified: how did the actor obtain `iam:UpdateAssumeRolePolicy`?
- [ ] All evidence artifacts linked to the case ticket (CloudTrail event JSON, Splunk exports, AWS CLI outputs)
- [ ] Blast radius confirmed: list all actions taken under the compromised session
- [ ] Any persistence mechanisms found and remediated (new IAM users, access keys, policies created)
- [ ] Hardening steps from Section 3 assigned to owners with due dates
- [ ] Detection tuning changes from Section 4 implemented and tested
- [ ] Lookup CSVs in `splunk/lookups/` updated to reflect new approved actors or suppression entries
- [ ] IR playbooks updated if any steps in CDET-005 playbooks were unclear or missing
- [ ] Lessons learned shared with the broader security team
- [ ] Incident classified: insider threat / compromised credential / misconfiguration / authorized change
- [ ] Metrics recorded: MTTD, MTTR, alert volume, FP rate for CDET-005

---

*End of CDET-005 response playbooks. For questions or playbook improvements, open a pull request against the detection engineering repository.*
