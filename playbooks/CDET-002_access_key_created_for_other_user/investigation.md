---
detection_id: CDET-002
detection_name: Access Key Created for Another User
tactic: Persistence
technique: T1098.001
last_updated: 2026-06-18
---

# CDET-002 — Investigation Playbook
# Access Key Created for Another User

**Prerequisites:** Triage complete and alert marked as FAIL (real alert).  
**Goal:** Build a complete picture of the attack chain, scope lateral movement, and collect evidence for containment and post-incident review.

---

## 1. Understand the Technique (T1098.001)

In T1098.001 (Account Manipulation — Additional Cloud Credentials), an adversary who has already obtained valid IAM credentials calls `CreateAccessKey` on a **different** IAM user to establish a persistent, independent access path. Key characteristics:

- The actor's own credentials may be short-lived (e.g., assumed-role session tokens), so they backdoor a long-lived IAM user to maintain access even after their original session expires.
- Target accounts are often service accounts or dormant users with broad permissions but low monitoring coverage.
- The attacker may immediately begin reconnaissance using the new key before the alert fires, so speed matters.

---

## 2. Anchor the Investigation on the Triggering Event

Retrieve the full event from CloudTrail via Splunk:

```spl
index=aws_cloudtrail eventName=CreateAccessKey
| search userIdentity.arn="<actor_arn>" AND requestParameters.userName="<target_username>"
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table event_time, eventID, userIdentity.arn, userIdentity.accessKeyId,
         requestParameters.userName, responseElements.accessKey.accessKeyId,
         sourceIPAddress, userAgent, awsRegion, recipientAccountId
```

**Record and preserve:**
- `eventID` — unique CloudTrail event identifier
- `responseElements.accessKey.accessKeyId` — the new key (`AKIA...`)
- `userIdentity.accessKeyId` — the key the actor used to call CreateAccessKey
- `eventTime` — anchor timestamp for the timeline
- `sourceIPAddress` and `userAgent`

---

## 3. CloudTrail Fields to Examine in Detail

| Field | What to look for |
|---|---|
| `userIdentity.type` | `AssumedRole` → trace back to the originating role and source; `IAMUser` → static key compromise likely |
| `userIdentity.sessionContext.sessionIssuer.arn` | For AssumedRole: the parent role ARN — determine if it should have IAM write permissions |
| `userIdentity.sessionContext.attributes.mfaAuthenticated` | `false` on a sensitive IAM action is a risk indicator |
| `userIdentity.sessionContext.attributes.creationDate` | How old is the session? Very recent session + immediate IAM action = suspicious |
| `requestParameters.userName` | Target user — check their permission policies immediately |
| `responseElements.accessKey.status` | Should be `Active`; if `Inactive` the actor may have already disabled it to cover tracks (unusual) |
| `tlsDetails.tlsVersion` | Anomalous TLS versions can indicate non-standard tooling |
| `requestParameters.serialNumber` | Absence of MFA device serial on sensitive action |

---

## 4. Splunk SPL Pivot Queries

### 4.1 Actor Pre-Attack Activity (What did the actor do before this event?)

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
    earliest=-2h latest=<event_time>
| sort _time asc
| table _time, eventName, eventSource, requestParameters, sourceIPAddress, userAgent, errorCode
```

Look for reconnaissance events: `ListUsers`, `GetUser`, `ListRoles`, `ListAttachedUserPolicies`, `ListAccessKeys`.

### 4.2 Actor Post-Event Activity (Did the actor continue operating?)

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
    earliest=<event_time> latest=now
| sort _time asc
| table _time, eventName, eventSource, requestParameters, sourceIPAddress
```

### 4.3 New Key Usage (Is the backdoor key already in use?)

```spl
index=aws_cloudtrail userIdentity.accessKeyId="<new_key_id>"
| sort _time asc
| table _time, eventName, eventSource, userIdentity.arn, sourceIPAddress, userAgent,
         requestParameters, responseElements, errorCode
```

This is the most critical query. Any hits confirm active exploitation.

### 4.4 Target User Activity (Has the target account been abused?)

```spl
index=aws_cloudtrail userIdentity.userName="<target_username>"
    earliest=-24h
| sort _time asc
| table _time, eventName, eventSource, userIdentity.accessKeyId,
         sourceIPAddress, userAgent, requestParameters, errorCode
```

Distinguish events made with the **old** key vs. the **new** key by comparing `userIdentity.accessKeyId`.

### 4.5 Source IP Correlation (Any other accounts / users from same IP?)

```spl
index=aws_cloudtrail sourceIPAddress="<source_ip>" earliest=-24h
| stats dc(userIdentity.arn) as unique_actors, values(userIdentity.arn) as actors,
         values(eventName) as actions count by sourceIPAddress
```

Multiple accounts from the same IP suggests a broader compromise campaign.

### 4.6 Actor Key History (Has this actor created other keys recently?)

```spl
index=aws_cloudtrail eventName=CreateAccessKey userIdentity.arn="<actor_arn>" earliest=-7d
| table _time, requestParameters.userName, responseElements.accessKey.accessKeyId, sourceIPAddress
```

### 4.7 Privilege Escalation Check (Did the actor modify IAM policies before or after?)

```spl
index=aws_cloudtrail (eventName=AttachUserPolicy OR eventName=PutUserPolicy
    OR eventName=AttachRolePolicy OR eventName=CreatePolicyVersion
    OR eventName=SetDefaultPolicyVersion OR eventName=AddUserToGroup)
    userIdentity.arn="<actor_arn>" earliest=-4h
| table _time, eventName, requestParameters
```

---

## 5. Gather IAM / Resource Context via AWS CLI

All commands use the boto3 default credential chain (`aws configure` / instance profile / environment). Do not hardcode credentials.

### 5.1 Enumerate existing access keys for the target user

```bash
aws iam list-access-keys \
  --user-name "<target_username>" \
  --output json
```

Note all key IDs and their `Status` and `CreateDate`. The new key from the alert should appear here.

### 5.2 Get target user details and attached policies

```bash
aws iam get-user --user-name "<target_username>" --output json

aws iam list-attached-user-policies \
  --user-name "<target_username>" --output json

aws iam list-user-policies \
  --user-name "<target_username>" --output json

aws iam list-groups-for-user \
  --user-name "<target_username>" --output json
```

Understand what the backdoor key can access before containment.

### 5.3 Get actor identity details

```bash
# If actor is an IAM user
aws iam get-user --user-name "<actor_username>" --output json

# If actor is an assumed role, describe the role
aws iam get-role --role-name "<role_name>" --output json
aws iam list-attached-role-policies --role-name "<role_name>" --output json
```

### 5.4 Check for any existing active sessions using the new key

```bash
# Use CloudTrail lookup (last 90 days, API-side)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="<new_key_id>" \
  --output json
```

### 5.5 Check CloudTrail data event logging coverage

```bash
aws cloudtrail get-trail-status --name "<trail_name>" --output json
aws cloudtrail describe-trails --output json
```

Confirm S3 data events and Lambda data events are captured if relevant to the target user's permissions.

---

## 6. Genuine Attack Chain for T1098.001

A typical attack sequence that should inform your timeline reconstruction:

```
T-60m to T-30m  Actor gains initial access (phished key, exposed credential,
                 SSRF against EC2 instance metadata, etc.)

T-30m to T-10m  Reconnaissance phase:
                 GetCallerIdentity → ListUsers → GetUser (target) →
                 ListAttachedUserPolicies (target) → select high-value target

T=0             CreateAccessKey for target_user  ← CDET-002 fires here

T+0 to T+5m     Actor tests new key:
                 GetCallerIdentity (with new key) → confirms key works

T+5m onward     Lateral movement / data access using target's permissions:
                 ListBuckets, GetObject, AssumeRole, etc.
```

Deviations from this pattern (e.g., no recon, or key created but never used) may indicate a misconfigured automation or an insider threat using console access.

---

## 7. Evidence to Collect and Preserve

Document the following in your incident ticket before taking any containment action:

| Evidence item | Where to find it | Preservation method |
|---|---|---|
| Triggering CloudTrail event JSON | Splunk / S3 CloudTrail bucket | Export full JSON; record `eventID` |
| New key ID (`AKIA...`) | `responseElements.accessKey.accessKeyId` | Record in ticket |
| Actor ARN and session details | `userIdentity` block | Copy full block to ticket |
| Source IP and user agent | CloudTrail event | Record in ticket; run threat-intel lookup |
| Actor activity timeline (pre/post) | Splunk queries 4.1 and 4.2 | Export as CSV and attach to ticket |
| New key usage events | Splunk query 4.3 | Export as CSV; note first-use timestamp |
| Target user policies | AWS CLI step 5.2 | Paste JSON output into ticket |
| All access keys for target user | AWS CLI step 5.1 | Paste JSON output into ticket |

---

## 8. Timeline Reconstruction

1. Set the anchor: `T=0` is the `eventTime` of the `CreateAccessKey` event.
2. Working backward from T=0, identify the actor's first CloudTrail event in the account — this is the **initial access timestamp**.
3. Identify the first recon event (ListUsers, GetCallerIdentity, etc.) — this is **discovery start**.
4. Working forward from T=0, map every event made with the new key — this defines the **exploitation window**.
5. Determine if other users, roles, or keys were created/modified in the same window (`eventName` in `CreateUser`, `CreateRole`, `AttachUserPolicy`, `CreateAccessKey`).
6. Build a table: `timestamp | actor | event | resource | source_ip` sorted ascending.
7. Identify any gaps in CloudTrail coverage (check for `eventType=AwsApiCall` vs. `AwsConsoleSignIn`; console activity may appear in a separate trail or CloudWatch).

Once the timeline is complete, proceed to `containment.md`.
