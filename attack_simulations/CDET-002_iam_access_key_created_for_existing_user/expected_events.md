# CDET-002 — Expected CloudTrail Events

## Overview

This simulation generates a single primary CloudTrail event: `CreateAccessKey`. The detection value comes from analyzing *who* created the key and *for whom*, not just that a key was created.

---

## Primary Event: CreateAccessKey

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `CreateAccessKey` |
| `requestParameters.userName` | `alice` (the target user receiving the new key) |
| `userIdentity.type` | `IAMUser` or `AssumedRole` (the attacker's identity) |
| `userIdentity.userName` | Attacker's username — differs from `requestParameters.userName` |
| `userIdentity.arn` | Full ARN of the creating principal |
| `responseElements.accessKey.accessKeyId` | `AKIA...` (new key ID — NOT the secret) |
| `responseElements.accessKey.status` | `Active` |
| `responseElements.accessKey.userName` | Same as `requestParameters.userName` |
| `sourceIPAddress` | IP of the attacker at time of API call |
| `userAgent` | `aws-cli/2.x` or SDK user agent |

**Key detection fields:**
- `requestParameters.userName` — identifies *whose account* received the new key
- `userIdentity.userName` (or `userIdentity.sessionContext.sessionIssuer.userName`) — identifies *who created* the key
- When these two differ, it is a strong indicator of unauthorized key creation

### What Is NOT Logged

| Data | Logged? |
|------|---------|
| `SecretAccessKey` | **Never** — not in CloudTrail or any AWS API response after creation |
| Original access key values | No |
| Purpose or label for the key | No (IAM access keys have no description field) |

---

## Secondary Enrichment: ListAccessKeys (Pre-Attack Reconnaissance)

An attacker checking key counts before creating a new one generates:

| Field | Value |
|-------|-------|
| `eventName` | `ListAccessKeys` |
| `requestParameters.userName` | Target username |
| `userIdentity.arn` | Attacker's ARN |

This event alone is low-fidelity, but when combined with a subsequent `CreateAccessKey` for the same target within a short window, it indicates deliberate targeting.

---

## Cleanup Event: DeleteAccessKey

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `DeleteAccessKey` |
| `requestParameters.userName` | Target username |
| `requestParameters.accessKeyId` | Key ID being deleted |

---

## SPL Detection Query (CDET-002 Logic)

```spl
index=aws_cloudtrail eventSource="iam.amazonaws.com" eventName="CreateAccessKey"
| eval creator=coalesce(userIdentity.userName, userIdentity.sessionContext.sessionIssuer.userName)
| eval target_user=requestParameters.userName
| where creator != target_user
| stats count by creator, target_user, sourceIPAddress, _time
| eval alert_reason="Access key created for another user: " + creator + " created key for " + target_user
```

**Additional enrichment query — detect keys created for privileged users:**
```spl
index=aws_cloudtrail eventSource="iam.amazonaws.com" eventName="CreateAccessKey"
| eval target_user=requestParameters.userName
| lookup iam_privileged_users.csv username AS target_user OUTPUT privilege_level
| where isnotnull(privilege_level)
| table _time, target_user, privilege_level, userIdentity.arn, sourceIPAddress
```

---

## Detection Variants

| Scenario | CloudTrail Signal | Detection Difficulty |
|----------|------------------|---------------------|
| Admin creates key for other user | `userIdentity` ≠ `requestParameters.userName` | Easy |
| Attacker creates key via assumed role | `userIdentity.sessionContext.sessionIssuer` differs | Medium |
| Attacker uses compromised key to self-rotate | `userIdentity` = `requestParameters.userName` | Hard (behavioral baseline needed) |
| Service role creates key for service account | Both are service accounts | Medium (requires allowlist) |
