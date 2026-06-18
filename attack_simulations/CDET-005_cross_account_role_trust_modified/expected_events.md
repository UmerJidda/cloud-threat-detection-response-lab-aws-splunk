# CDET-005 — Expected CloudTrail Events

## Overview

This simulation generates one or two CloudTrail events: optionally `CreateRole` (if a new role is created for the test), and always `UpdateAssumeRolePolicy` (the primary detection trigger).

---

## Event 1 (Optional): CreateRole

Generated only when creating a new simulation role rather than modifying an existing one.

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `CreateRole` |
| `requestParameters.roleName` | `cdet005-simulation-target-role` |
| `requestParameters.assumeRolePolicyDocument` | JSON trust policy (URL-encoded in CloudTrail) |
| `responseElements.role.arn` | `arn:aws:iam::ACCOUNT_ID:role/cdet005-simulation-target-role` |
| `userIdentity.arn` | ARN of the creating principal |

**SPL Detection:**  
When `CreateRole` contains an external account in `requestParameters.assumeRolePolicyDocument`, it fires CDET-005. This is the "new role with external trust" variant.

---

## Primary Event: UpdateAssumeRolePolicy

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `UpdateAssumeRolePolicy` |
| `requestParameters.roleName` | Target role being modified |
| `requestParameters.policyDocument` | Full JSON trust policy (URL-encoded) |
| `userIdentity.arn` | Attacker's ARN |
| `sourceIPAddress` | Attacker's IP |
| `userAgent` | `aws-cli/2.x` or SDK user agent |

### The policyDocument field (decoded):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::VICTIM_ACCOUNT:root"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "ExternalAccessBackdoor",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::999999999999:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**What to look for**: The `Principal.AWS` field containing an account ID that is NOT in your organization's approved account list.

---

## SPL Detection Query (CDET-005 Logic)

```spl
index=aws_cloudtrail eventSource="iam.amazonaws.com"
  eventName IN ("UpdateAssumeRolePolicy", "CreateRole")
| eval trust_doc=urldecode(requestParameters.policyDocument)
| rex field=trust_doc max_match=10 "arn:aws:iam::(?P<account_id>\d{12}):[^\"]+" 
| mvexpand account_id
| lookup approved_aws_accounts.csv account_id OUTPUT is_approved
| where isnull(is_approved) OR is_approved!="true"
| stats
    values(account_id) as external_accounts,
    values(requestParameters.roleName) as modified_roles,
    dc(account_id) as num_external_accounts
    by _time, userIdentity.arn, eventName
| where num_external_accounts > 0
| eval alert_reason="External account added to role trust policy: " + mvjoin(external_accounts, ", ")
```

---

## Post-Exploitation Events

After trust policy modification, the attacker calls `sts:AssumeRole` from their source account. This generates:

| Field | Value |
|-------|-------|
| `eventSource` | `sts.amazonaws.com` |
| `eventName` | `AssumeRole` |
| `requestParameters.roleArn` | ARN of the backdoored role |
| `userIdentity.type` | `IAMUser` (attacker's source account user) |
| `userIdentity.accountId` | **Attacker's account ID** (different from victim account) |
| `recipientAccountId` | Victim account ID |
| `sourceIPAddress` | Attacker's IP (may be external to corporate network) |

**This follow-on `AssumeRole` event is the ultimate confirmation of exploitation** and is covered by CDET-012 (Cross-Account AssumeRole Chain).

---

## Cleanup Events

| `eventName` | Description |
|-------------|-------------|
| `UpdateAssumeRolePolicy` | Trust policy restored to original |
| `DeleteRole` | Simulation role deleted (if created in Option B) |

---

## Detection Notes

| Scenario | Signal Strength | Notes |
|----------|----------------|-------|
| External account added to existing high-privilege role | Very High | `UpdateAssumeRolePolicy` with unknown account ID |
| New role created with external trust | High | `CreateRole` with external account in trust doc |
| Existing cross-account role trust modified (approved accounts) | Low | May be legitimate — requires allowlist |
| Trust policy with `sts:ExternalId` condition added | Medium | Attacker may use ExternalId to evade simple regex detection |
