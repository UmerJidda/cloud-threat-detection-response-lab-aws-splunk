---
detection_id: CDET-001
detection_name: IAM User Created Outside Pipeline
tactic: Persistence
technique: T1136.003
last_updated: 2026-06-18
---

# CDET-001 — Investigation Playbook
**IAM User Created Outside Pipeline**

> **Audience:** Tier-2 SOC Analyst with AWS IAM experience
> **Prerequisites:** Triage complete, verdict is REAL ALERT
> **Goal:** Reconstruct the full attack chain, gather evidence, determine blast radius

---

## 1. Key CloudTrail Fields for T1136.003

For each `CreateUser` event, examine and record these fields:

| Field | Significance |
|---|---|
| `eventSource` | Must be `iam.amazonaws.com` |
| `eventName` | `CreateUser` |
| `eventTime` | UTC — correlate against change windows |
| `userIdentity.type` | `IAMUser` or `AssumedRole` — Root is critical |
| `userIdentity.arn` | Full ARN of the caller |
| `userIdentity.sessionContext.sessionIssuer` | For AssumedRole: the underlying role |
| `userIdentity.sessionContext.attributes.mfaAuthenticated` | `false` = no MFA — higher risk |
| `requestParameters.userName` | Name given to the new user |
| `requestParameters.path` | IAM path — `/` is default; custom paths can indicate staging |
| `requestParameters.tags` | Tags on the new user — adversaries often leave none |
| `sourceIPAddress` | Calling IP; `AWS Internal` = called from within AWS |
| `userAgent` | SDK / tool string |
| `responseElements.user.userId` | Unique user ID (AIDA…) — preserve for all subsequent queries |
| `responseElements.user.arn` | Full ARN of the newly created user |
| `responseElements.user.createDate` | Confirm matches eventTime |

---

## 2. Splunk SPL Pivot Queries

Replace `<NEW_USER_ARN>`, `<CALLER_ARN>`, and `<SOURCE_IP>` with values from the alert.

### 2a. Full context around the CreateUser event

```spl
index=aws_cloudtrail eventName=CreateUser
  earliest=-7d latest=now
| eval new_user_name=requestParameters.userName
| eval caller=userIdentity.arn
| eval src_ip=sourceIPAddress
| table _time, eventTime, awsRegion, caller, new_user_name, src_ip, userAgent, errorCode
| sort - _time
```

### 2b. All actions by the caller in the 4 hours surrounding the alert

```spl
index=aws_cloudtrail userIdentity.arn="<CALLER_ARN>"
  earliest=-4h@h latest=+4h@h
| table _time, eventName, eventSource, sourceIPAddress, userAgent, errorCode, requestParameters
| sort + _time
```

### 2c. All actions taken ON the new user after creation

```spl
index=aws_cloudtrail
  (requestParameters.userName="<NEW_USERNAME>" OR requestParameters.targetUserName="<NEW_USERNAME>"
   OR resources{}.ARN="<NEW_USER_ARN>")
  earliest=-7d latest=now
| table _time, eventName, eventSource, userIdentity.arn, sourceIPAddress, errorCode
| sort + _time
```

### 2d. Access key creation for the new user (persistence mechanism)

```spl
index=aws_cloudtrail eventName=CreateAccessKey
  requestParameters.userName="<NEW_USERNAME>"
  earliest=-7d latest=now
| table _time, userIdentity.arn, responseElements.accessKey.accessKeyId, sourceIPAddress
```

### 2e. Policy and group attachments to the new user

```spl
index=aws_cloudtrail
  eventName IN (AttachUserPolicy, PutUserPolicy, AddUserToGroup)
  requestParameters.userName="<NEW_USERNAME>"
  earliest=-7d latest=now
| table _time, eventName, requestParameters.policyArn, requestParameters.policyDocument, requestParameters.groupName, userIdentity.arn
| sort + _time
```

### 2f. Console or API activity by the new user (did they use the account?)

```spl
index=aws_cloudtrail userIdentity.arn="<NEW_USER_ARN>"
  earliest=-7d latest=now
| stats count BY eventName, eventSource, sourceIPAddress, userAgent
| sort - count
```

### 2g. Lateral source IP — what else came from this IP?

```spl
index=aws_cloudtrail sourceIPAddress="<SOURCE_IP>"
  earliest=-48h latest=now
| stats count BY userIdentity.arn, eventName
| sort - count
```

---

## 3. What a Genuine T1136.003 Attack Chain Looks Like

A typical attacker sequence after gaining initial access to a privileged IAM identity:

```
1. AssumeRole / credential theft         → attacker gains a privileged identity
2. CreateUser                            → creates a backdoor user (CDET-001 fires here)
3. CreateAccessKey (new user)            → generates long-lived programmatic credentials
4. AttachUserPolicy / AddUserToGroup     → grants permissions (AdministratorAccess is common)
5. [Optional] CreateLoginProfile         → enables console access with a password
6. Attacker uses new credentials         → independent of compromised identity
7. Original compromised session ends     → attacker retains access via backdoor user
```

Look for all seven steps in your Splunk queries. If you find steps 3–6 complete, treat this as a confirmed, active backdoor.

---

## 4. AWS CLI Context Collection

Use your configured AWS CLI profile (`aws configure` / boto3 default credential chain — **no hardcoded credentials**).

### 4a. Describe the new IAM user

```bash
aws iam get-user --user-name "<NEW_USERNAME>" --output json
```

### 4b. List attached managed policies

```bash
aws iam list-attached-user-policies --user-name "<NEW_USERNAME>" --output json
```

### 4c. List inline policies

```bash
aws iam list-user-policies --user-name "<NEW_USERNAME>" --output json
# For each policy name returned:
aws iam get-user-policy --user-name "<NEW_USERNAME>" --policy-name "<POLICY_NAME>" --output json
```

### 4d. List group memberships

```bash
aws iam list-groups-for-user --user-name "<NEW_USERNAME>" --output json
```

### 4e. List access keys and their status

```bash
aws iam list-access-keys --user-name "<NEW_USERNAME>" --output json
```

### 4f. Check for console login profile (password-based access)

```bash
aws iam get-login-profile --user-name "<NEW_USERNAME>" --output json 2>&1
# A "NoSuchEntity" error means no console password was set — lower risk
```

### 4g. Check last-used for each access key

```bash
aws iam get-access-key-last-used --access-key-id "<KEY_ID>" --output json
```

### 4h. Review caller identity's permissions (understand what the attacker could do)

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "<CALLER_ARN>" \
  --action-names "iam:CreateUser" "iam:AttachUserPolicy" "iam:CreateAccessKey" \
  --output json
```

---

## 5. Evidence to Collect and Preserve

For each item, record the value and the timestamp retrieved:

- [ ] Full raw CloudTrail JSON for the `CreateUser` event (download from S3 bucket or Splunk export)
- [ ] `responseElements.user.userId` (AIDA… identifier — survives username changes)
- [ ] `responseElements.user.arn`
- [ ] `responseElements.user.createDate`
- [ ] Source IP and full `userAgent` string
- [ ] All access key IDs created for the new user (from `CreateAccessKey` events and `list-access-keys`)
- [ ] All policy ARNs and inline policy documents attached to the new user
- [ ] All CloudTrail events by the new user (if any) — export to file
- [ ] All CloudTrail events by the calling identity in the ±4 hour window — export to file
- [ ] Output of all AWS CLI commands in section 4 — save as JSON

**Preserve raw event JSON.** Do not rely on Splunk field extraction alone — save the `_raw` field.

---

## 6. Timeline Reconstruction

Build a chronological table of all events with these columns:

| Timestamp (UTC) | Event | Actor (ARN) | Source IP | Notes |
|---|---|---|---|---|
| T+0 | Initial compromise / credential theft | | | |
| T+N | `CreateUser` — CDET-001 fires | | | |
| T+N | `CreateAccessKey` | | | |
| T+N | `AttachUserPolicy` / `PutUserPolicy` | | | |
| T+N | `AddUserToGroup` | | | |
| T+N | First use of new user credentials | | | |

Use Splunk's timeline visualization or export all events to CSV and sort by `_time`.

Note any **gaps in CloudTrail** (missing minutes) which could indicate log tampering — check for `DeleteTrail`, `StopLogging`, or `UpdateTrail` events by the caller around the same time:

```spl
index=aws_cloudtrail userIdentity.arn="<CALLER_ARN>"
  eventName IN (DeleteTrail, StopLogging, UpdateTrail, PutEventSelectors, DeleteLogGroup)
  earliest=-24h latest=now
| table _time, eventName, sourceIPAddress
```
