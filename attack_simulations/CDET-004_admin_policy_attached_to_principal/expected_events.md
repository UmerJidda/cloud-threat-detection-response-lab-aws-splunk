# CDET-004 — Expected CloudTrail Events

## Overview

This simulation generates one of four CloudTrail events depending on the variant executed. The events differ in how the privilege escalation is performed and how detectable it is.

---

## Variant A: AttachUserPolicy (Managed Policy)

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `AttachUserPolicy` |
| `requestParameters.userName` | Target user receiving admin access |
| `requestParameters.policyArn` | `arn:aws:iam::aws:policy/AdministratorAccess` |
| `userIdentity.arn` | ARN of the principal performing escalation |
| `sourceIPAddress` | Attacker IP |

**SPL Detection:**
- Primary field: `requestParameters.policyArn` — match against admin policy ARN patterns
- `requestParameters.policyArn IN ("arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/PowerUserAccess")`
- Can also match on `*FullAccess*` or `*Admin*` in policy name

---

## Variant B: AttachRolePolicy (Managed Policy to Role)

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `AttachRolePolicy` |
| `requestParameters.roleName` | Target role name |
| `requestParameters.policyArn` | `arn:aws:iam::aws:policy/AdministratorAccess` |
| `userIdentity.arn` | Attacker's ARN |

**SPL Detection:**
- Same logic as Variant A, but `eventName = "AttachRolePolicy"` and `requestParameters.roleName`
- Combined query: `eventName IN ("AttachUserPolicy", "AttachRolePolicy")`

---

## Variant C: PutUserPolicy (Inline Wildcard Policy)

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `PutUserPolicy` |
| `requestParameters.userName` | Target user |
| `requestParameters.policyName` | Inline policy name (arbitrary — attacker controlled) |
| `requestParameters.policyDocument` | Full JSON policy document (URL-encoded in CloudTrail) |
| `userIdentity.arn` | Attacker's ARN |

**The `policyDocument` field value (URL-decoded):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FullAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

**SPL Detection:**
```spl
index=aws_cloudtrail eventName IN ("PutUserPolicy","PutRolePolicy")
| eval doc=urldecode(requestParameters.policyDocument)
| where match(doc, "\"Action\":\s*\"\*\"") OR match(doc, "\"Resource\":\s*\"\*\"")
| table _time, eventName, userIdentity.arn, requestParameters.userName, requestParameters.roleName, doc
```

**Detection difficulty**: Requires JSON parsing within the CloudTrail event. The inline policy name is attacker-controlled and can be anything — detection cannot rely on the policy name.

---

## Variant D: PutRolePolicy (Inline Wildcard Policy to Role)

| Field | Value |
|-------|-------|
| `eventSource` | `iam.amazonaws.com` |
| `eventName` | `PutRolePolicy` |
| `requestParameters.roleName` | Target role |
| `requestParameters.policyName` | Inline policy name |
| `requestParameters.policyDocument` | Full JSON policy document |
| `userIdentity.arn` | Attacker's ARN |

---

## Cleanup Events

| `eventName` | Variant |
|-------------|---------|
| `DetachUserPolicy` | Variant A cleanup |
| `DetachRolePolicy` | Variant B cleanup |
| `DeleteUserPolicy` | Variant C cleanup |
| `DeleteRolePolicy` | Variant D cleanup |

---

## Combined SPL Detection Query (All Variants)

```spl
index=aws_cloudtrail eventSource="iam.amazonaws.com"
  eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy")
| eval principal=coalesce(requestParameters.userName, requestParameters.roleName, "unknown")
| eval
    is_admin_managed_policy=if(
      like(requestParameters.policyArn, "%AdministratorAccess%") OR
      like(requestParameters.policyArn, "%PowerUserAccess%"),
      1, 0
    ),
    is_wildcard_inline=if(
      eventName IN ("PutUserPolicy","PutRolePolicy") AND
      like(urldecode(requestParameters.policyDocument), "%\"Action\":\"*\"%"),
      1, 0
    )
| where is_admin_managed_policy=1 OR is_wildcard_inline=1
| table _time, eventName, principal, userIdentity.arn, requestParameters.policyArn, sourceIPAddress
| eval severity="HIGH"
```

---

## Attack Chain Correlation

When CDET-004 fires within 60 minutes of a CDET-001 `CreateUser` event for the same username, it indicates a complete persistence + escalation chain:

```spl
index=aws_cloudtrail
| eval username=coalesce(requestParameters.userName, responseElements.user.userName)
| stats
    values(eventName) as events,
    min(_time) as first_event,
    max(_time) as last_event
    by username
| where mvfind(events, "CreateUser") >= 0 AND (
    mvfind(events, "AttachUserPolicy") >= 0 OR
    mvfind(events, "PutUserPolicy") >= 0
  )
| eval chain_duration_min=round((last_event-first_event)/60, 1)
| table username, events, chain_duration_min, first_event
```
