---
detection_id: CDET-012
detection_name: Cross-Account Role Assumption
tactic: Lateral Movement
technique: T1550.001
last_updated: 2026-06-18
---

# CDET-012 — Recovery Playbook
**Cross-Account Role Assumption**

> **Audience:** Tier-2 SOC Analyst coordinating with the cloud platform and IAM teams
> **Prerequisites:** Containment complete; attacker's active session confirmed terminated; incident ticket in "Contained" state.

---

## 1. Verify the Threat Has Been Fully Removed

Complete all checks below before moving to restoration steps.

### 1a. Confirm no active sessions exist for the compromised role

```bash
# Check for recent successful AssumeRole events after your containment timestamp
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "<CONTAINMENT_TIMESTAMP>" \
  --profile <ACCOUNT_B_PROFILE> \
  --output json | python -m json.tool
```

Also run the Splunk query:

```spl
index=aws_cloudtrail eventName=AssumeRole
  requestParameters.roleArn="<TARGET_ROLE_ARN>"
  earliest="<CONTAINMENT_TIMESTAMP>"
  latest=now
  errorCode!=AccessDenied
| table eventTime, userIdentity.arn, sourceIPAddress, requestParameters.roleSessionName
```

Expected result: zero rows after your containment timestamp.

### 1b. Verify the session-revocation deny policy is in place and correctly formed

```bash
aws iam get-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --policy-name "INCIDENT-CDET-012-RevokeSessions" \
  --profile <ACCOUNT_B_PROFILE> \
  --output json
```

Confirm the `DateLessThan` condition timestamp matches your containment action timestamp.

### 1c. Confirm the source principal can no longer assume cross-account roles

```bash
# Attempt a dry-run simulation using IAM policy simulator
aws iam simulate-principal-policy \
  --policy-source-arn <COMPROMISED_PRINCIPAL_ARN> \
  --action-names sts:AssumeRole \
  --resource-arns <TARGET_ROLE_ARN> \
  --profile <ACCOUNT_A_PROFILE> \
  --output json
```

Expected result: `implicitDeny` or `explicitDeny` — not `allowed`.

### 1d. Audit Account B for any persistence mechanisms left by the attacker

```bash
# List all IAM users created after the AssumeRole event time
aws iam list-users \
  --profile <ACCOUNT_B_PROFILE> \
  --query "Users[?CreateDate>='<ASSUMEROLE_EVENT_TIME>']" \
  --output table

# List all IAM roles created after the AssumeRole event time
aws iam list-roles \
  --profile <ACCOUNT_B_PROFILE> \
  --query "Roles[?CreateDate>='<ASSUMEROLE_EVENT_TIME>']" \
  --output table

# List all access keys in Account B and check creation dates
aws iam list-users --profile <ACCOUNT_B_PROFILE> --output json | \
  python3 -c "import sys,json; [print(u['UserName']) for u in json.load(sys.stdin)['Users']]" | \
  xargs -I{} aws iam list-access-keys --user-name {} \
    --profile <ACCOUNT_B_PROFILE> --output json
```

Any resource with a `CreateDate` after the CDET-012 trigger event and before containment is suspect. Delete only after IR lead approval.

### 1e. Check for S3 data exfiltration from Account B

```spl
index=aws_cloudtrail recipientAccountId="<DEST_ACCOUNT>"
  userIdentity.arn="<SESSION_ARN>"
  eventName IN (GetObject, ListObjects, ListObjectsV2, CopyObject,
                GetBucketAcl, PutBucketPolicy, CreateBucket)
  earliest="-48h" latest=now
| stats count BY eventName, requestParameters.bucketName
| sort - count
```

If `GetObject` or `CopyObject` events appear against sensitive buckets, scope a data breach assessment and notify your Data Protection Officer per your organisation's breach notification policy.

---

## 2. Restore Normal Operations

Execute restoration in the reverse order of containment.

### 2a. Remove temporary deny policies

After confirming no attacker activity and that all attacker-created resources have been removed or disabled:

```bash
# Remove session-revocation policy from target role in Account B
aws iam delete-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_B> \
  --policy-name "INCIDENT-CDET-012-RevokeSessions" \
  --profile <ACCOUNT_B_PROFILE>

# Remove cross-account block from source principal in Account A (if FP confirmed or after remediation)
aws iam delete-role-policy \
  --role-name <ROLE_NAME_IN_ACCOUNT_A> \
  --policy-name "INCIDENT-CDET-012-BlockCrossAccountAssumeRole" \
  --profile <ACCOUNT_A_PROFILE>
```

### 2b. Rotate the compromised credential

Do not simply re-enable a disabled access key — issue a new one and retire the old one.

```bash
# Create a new access key for the affected user/service
aws iam create-access-key \
  --user-name <USERNAME> \
  --profile <ACCOUNT_A_PROFILE> \
  --output json

# Delete the old (compromised) access key
aws iam delete-access-key \
  --user-name <USERNAME> \
  --access-key-id <OLD_ACCESS_KEY_ID> \
  --profile <ACCOUNT_A_PROFILE>
```

Update secrets in Secrets Manager, Parameter Store, or the relevant CI/CD pipeline with the new key. Confirm rotation with the owning team before closing.

### 2c. Delete attacker-created IAM resources in Account B

Only after IR lead approval and evidence preservation is confirmed:

```bash
# Delete attacker-created access key
aws iam delete-access-key \
  --user-name <ATTACKER_CREATED_USER> \
  --access-key-id <KEY_ID> \
  --profile <ACCOUNT_B_PROFILE>

# Detach all policies then delete attacker-created user
aws iam detach-user-policy \
  --user-name <ATTACKER_CREATED_USER> \
  --policy-arn <POLICY_ARN> \
  --profile <ACCOUNT_B_PROFILE>

aws iam delete-user \
  --user-name <ATTACKER_CREATED_USER> \
  --profile <ACCOUNT_B_PROFILE>

# Delete attacker-created role (detach policies first)
aws iam delete-role \
  --role-name <ATTACKER_CREATED_ROLE> \
  --profile <ACCOUNT_B_PROFILE>
```

### 2d. Validate service functionality

Work with the owning team to confirm all legitimate workloads depending on the target role and source principal are operating normally. Review application logs and CloudWatch alarms for any errors caused by the containment period.

---

## 3. Hardening Steps to Prevent Recurrence

### 3a. Apply least-privilege and scoped trust policies to all cross-account roles

Every cross-account trust policy should include at minimum:

- **Explicit principal ARN** — never use `"Principal": {"AWS": "*"}`.
- **`aws:PrincipalOrgID` condition** — restrict assumption to principals within your AWS Organisation.
- **`sts:ExternalId` condition** — required for any role trusted by a third-party or external principal.
- **`aws:SourceAccount` or `aws:SourceArn` condition** — where applicable for service-linked roles.

Example corrected trust policy snippet:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::<TRUSTED_ACCOUNT_ID>:role/<SPECIFIC_ROLE>"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "<YOUR_ORG_ID>",
        "sts:ExternalId": "<SHARED_SECRET>"
      }
    }
  }]
}
```

### 3b. Enable SCP guardrails in AWS Organizations

Deploy a Service Control Policy that denies `sts:AssumeRole` to principals outside your Organisation for sensitive accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyExternalRoleAssumption",
    "Effect": "Deny",
    "Action": "sts:AssumeRole",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalOrgID": "<YOUR_ORG_ID>"
      }
    }
  }]
}
```

### 3c. Enforce MFA for cross-account role assumption

For roles used by human operators, add an MFA condition to the trust policy:

```json
"Condition": {
  "Bool": {
    "aws:MultiFactorAuthPresent": "true"
  },
  "NumericLessThan": {
    "aws:MultiFactorAuthAge": "3600"
  }
}
```

### 3d. Audit all cross-account role trust policies

```bash
# List all roles and export their trust policies for review
aws iam list-roles \
  --profile <ACCOUNT_B_PROFILE> \
  --output json \
  --query 'Roles[*].{RoleName:RoleName,TrustPolicy:AssumeRolePolicyDocument}' \
  > /tmp/CDET-012-all-trust-policies-audit.json
```

Review the output for any wildcard principals, missing condition keys, or principals from unexpected accounts.

### 3e. Enable AWS IAM Access Analyzer

If not already enabled, activate IAM Access Analyzer in every account. It will automatically flag roles with trust policies that permit access from outside your organisation.

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name "cross-account-access-analyzer" \
  --type ORGANIZATION \
  --profile <MANAGEMENT_ACCOUNT_PROFILE>
```

---

## 4. Detection Tuning Recommendations

### 4a. Suppression — reducing false positives without weakening the rule

Add known-good cross-account role ARNs to `splunk/lookups/automation_role_arns.csv` with the following columns populated:

```
role_arn, trusted_source_account, trusted_source_principal_pattern, justification, owner, approved_date
```

Update the CDET-012 Splunk alert to join against this lookup and exclude matched rows from alerting. Do not suppress based on source IP alone — IP-based suppression is bypassable.

### 4b. Enrichment — improving signal quality

Add the following enrichment lookups to the CDET-012 alert search to provide analysts with immediate context:

- Join `userIdentity.accountId` against `splunk/lookups/approved_aws_accounts.csv` to add `account_env` (prod/staging/lab) and `account_owner`.
- Join `requestParameters.roleArn` against `splunk/lookups/approved_iam_principals.csv` to add `role_purpose` and `sanctioned` flag.
- Join `sourceIPAddress` against `splunk/lookups/approved_cidr_ranges.csv` to add `ip_classification` (corporate/ci-cd/unknown).

### 4c. Additional detections to consider deploying

| Scenario | Recommended detection |
|---|---|
| Role enumeration preceding assumption | Alert on burst of `AccessDenied` on `AssumeRole` from same source within 10 minutes |
| Multi-hop role chaining | Alert when `userIdentity.sessionContext.sessionIssuer.arn` itself references an assumed-role session |
| AssumeRole to accounts outside the Organisation | Alert when `recipientAccountId` is not in `approved_aws_accounts.csv` — zero-FP if lookup is maintained |
| Unusual roleSessionName patterns | Alert on `roleSessionName` matching regex for random strings (e.g., 8+ hex characters, no word characters) |

---

## 5. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Timeline of attacker activity documented from first credential use to last observed event.
- [ ] Root cause identified: Was the trust policy misconfigured? Were credentials phished, leaked in code, or exposed via IMDS?
- [ ] Blast radius confirmed: Full list of services and data touched in Account B (and any further accounts).
- [ ] Data breach determination made and documented; DPO notified if personal data was accessed.
- [ ] All attacker-created IAM resources deleted from Account B (and any further accounts).
- [ ] Compromised credential rotated; old credential deleted.
- [ ] Trust policy on target role corrected and reviewed by role owner.
- [ ] SCP or IAM Access Analyzer findings addressed.
- [ ] CDET-012 lookup CSVs updated (new entries in `approved_aws_accounts.csv`, `automation_role_arns.csv`).
- [ ] Detection tuning changes (suppression / enrichment) applied and tested.
- [ ] Incident ticket updated with all evidence links, timeline, and lessons learned.
- [ ] Lessons-learned session scheduled with cloud platform and security teams.
- [ ] CDET-012 playbook updated if any steps were unclear, missing, or incorrect during this incident.
