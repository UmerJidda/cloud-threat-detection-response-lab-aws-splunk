---
detection_id: CDET-004
detection_name: Admin Policy Attached Outside Pipeline
tactic: Privilege Escalation
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-004 — Investigation Playbook

## Purpose
Perform a full technical investigation of a confirmed or suspected admin policy attachment outside the authorized pipeline. Goal: determine scope, actor intent, entry point, and whether further compromise has occurred.

---

## T1078.004 Attack Chain — What You Are Looking For

In a typical cloud valid accounts (T1078.004) privilege escalation sequence:

1. Attacker gains initial access via stolen IAM credentials, phishing, or compromised CI/CD secrets.
2. Actor calls `AttachUserPolicy` (or `PutUserPolicy`) to grant admin-level permissions to a user or role they control.
3. Actor uses elevated permissions to enumerate resources, exfiltrate data, create persistence (new users, access keys, OIDC providers), or launch infrastructure.
4. Actor may detach the policy after use to cover tracks.

The CDET-004 detection fires on step 2. Investigation must determine whether steps 3–4 have also occurred.

---

## Step 1 — Preserve the Triggering Event Record

Collect and record the following fields from the triggering CloudTrail event. These form the core of your evidence record.

| Field | Notes |
|---|---|
| `eventID` | Unique identifier — preserve this |
| `eventTime` | UTC timestamp |
| `eventName` | `AttachUserPolicy` |
| `eventSource` | `iam.amazonaws.com` |
| `awsRegion` | Region where API was called |
| `sourceIPAddress` | Caller IP |
| `userAgent` | Caller user agent string |
| `userIdentity.type` | IAMUser / AssumedRole / Root |
| `userIdentity.arn` | Full ARN of the calling principal |
| `userIdentity.accountId` | Account ID |
| `userIdentity.sessionContext.sessionIssuer.arn` | If AssumedRole — the role ARN |
| `requestParameters.userName` | Target user that received the policy |
| `requestParameters.policyArn` | The policy that was attached |
| `responseElements` | Should be null on success |
| `errorCode` | Must be absent for a successful attachment |
| `requestID` | AWS request ID for cross-referencing |

---

## Step 2 — Retrieve the Full Event from Splunk

```spl
index=aws_cloudtrail eventName=AttachUserPolicy
| where eventTime >= "<alert_window_start>" AND eventTime <= "<alert_window_end>"
| search userIdentity.arn="<actor_arn>"
| table _time, eventID, userIdentity.arn, userIdentity.type, sourceIPAddress,
         userAgent, requestParameters.userName, requestParameters.policyArn,
         awsRegion, requestID
```

If multiple events are returned, check for repeated attachment attempts or multiple target users.

---

## Step 3 — Profile the Calling Identity

### 3a. Determine what the calling identity is authorized to do

```bash
# Identify the IAM entity
aws iam get-user --user-name "<caller_username>"
# or for a role:
aws iam get-role --role-name "<role_name>"

# List all attached policies on the caller
aws iam list-attached-user-policies --user-name "<caller_username>"
aws iam list-user-policies --user-name "<caller_username>"

# List group memberships and group policies
aws iam list-groups-for-user --user-name "<caller_username>"
```

Note: use `boto3.Session()` (default credential chain via `aws configure`) — never hardcode credentials.

### 3b. Check when the calling identity's credentials were created

```bash
aws iam list-access-keys --user-name "<caller_username>"
# Note CreateDate and Status. A recently created key is a strong indicator of attacker-created persistence.
```

---

## Step 4 — Examine the Target User

```bash
# Who received the admin policy?
aws iam get-user --user-name "<target_username>"

# What policies does the target now have?
aws iam list-attached-user-policies --user-name "<target_username>"
aws iam list-user-policies --user-name "<target_username>"

# Does the target have console access?
aws iam get-login-profile --user-name "<target_username>"

# Does the target have active access keys?
aws iam list-access-keys --user-name "<target_username>"
```

---

## Step 5 — Timeline Reconstruction in Splunk

Build a 24-hour activity timeline for the calling actor ARN:

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
| eval _time_fmt=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table _time_fmt, eventName, eventSource, sourceIPAddress, awsRegion,
         requestParameters, responseElements, errorCode
| sort _time_fmt
```

Also build a timeline for the target user from the point the policy was attached:

```spl
index=aws_cloudtrail userIdentity.arn="<target_user_arn>"
| where _time >= relative_time(strptime("<attachment_time>","%Y-%m-%dT%H:%M:%SZ"), "-5m")
| table _time, eventName, eventSource, sourceIPAddress, awsRegion, requestParameters
| sort _time
```

---

## Step 6 — Check for Downstream Abuse of Elevated Permissions

Look for high-impact API calls made by the target user after the policy attachment:

```spl
index=aws_cloudtrail userIdentity.arn="<target_user_arn>"
| where _time > relative_time(strptime("<attachment_time>","%Y-%m-%dT%H:%M:%SZ"), "0")
| search eventName IN (
    "CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "PutUserPolicy", "AttachUserPolicy", "CreateRole", "AttachRolePolicy",
    "PutRolePolicy", "CreateSAMLProvider", "UpdateSAMLProvider",
    "CreateOpenIDConnectProvider", "UpdateAssumeRolePolicy",
    "GetObject", "PutObject", "DeleteObject",
    "DescribeInstances", "RunInstances", "TerminateInstances",
    "CreateBucket", "DeleteBucket", "PutBucketPolicy",
    "AssumeRole", "AssumeRoleWithWebIdentity"
  )
| table _time, eventName, eventSource, sourceIPAddress, requestParameters
| sort _time
```

---

## Step 7 — Check for Persistence Mechanisms Created

```spl
index=aws_cloudtrail
  (eventName=CreateAccessKey OR eventName=CreateLoginProfile OR
   eventName=CreateOpenIDConnectProvider OR eventName=CreateSAMLProvider OR
   eventName=UpdateAssumeRolePolicy)
| where _time >= relative_time(strptime("<attachment_time>","%Y-%m-%dT%H:%M:%SZ"), "-1h")
| table _time, eventName, userIdentity.arn, requestParameters, sourceIPAddress
| sort _time
```

---

## Step 8 — Check if Policy Was Subsequently Detached (Evidence of Cleanup)

```spl
index=aws_cloudtrail eventName=DetachUserPolicy
| search requestParameters.userName="<target_username>"
  requestParameters.policyArn="<policy_arn>"
| table _time, eventID, userIdentity.arn, requestParameters, sourceIPAddress
```

A detach event shortly after attachment is a strong indicator of a deliberate attacker covering tracks.

---

## Step 9 — Gather IP and Session Context

```bash
# Check CloudTrail for all events from the source IP in the last 48 hours
# (use Splunk for this — CLI example below is pseudocode for boto3 API)
```

```spl
index=aws_cloudtrail sourceIPAddress="<source_ip>"
| where _time >= relative_time(now(), "-48h")
| stats count by userIdentity.arn, eventName, awsRegion
| sort - count
```

---

## Evidence Collection Checklist

Before proceeding to containment, confirm you have recorded:

- [ ] `eventID` of the triggering `AttachUserPolicy` event
- [ ] Full `userIdentity` block of the calling actor
- [ ] Full `requestParameters` of the triggering event
- [ ] `requestID` for AWS Support cross-reference if needed
- [ ] Timeline export (CSV or JSON) from Splunk for the actor and target
- [ ] List of all IAM policies currently attached to the target user
- [ ] List of all access keys on the target user (key IDs and creation dates)
- [ ] Any downstream high-impact API calls with timestamps
- [ ] Source IP geolocation and threat intel lookup result
- [ ] Screenshot or export of Splunk search results (for ticket attachment)
