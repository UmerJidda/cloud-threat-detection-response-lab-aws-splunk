---
detection_id: CDET-003
detection_name: CloudTrail Logging Disabled
tactic: Defense Evasion
technique: T1562.008
last_updated: 2026-06-18
---

# CDET-003 — CloudTrail Logging Disabled: Investigation

**Prerequisite:** Triage checklist passed. An incident ticket is open. AWS CLI is configured using `aws configure` (boto3 default credential chain — no hardcoded credentials).

---

## 1. Understand the Attack Technique

**MITRE ATT&CK T1562.008 — Impair Defenses: Disable Cloud Logs**

An adversary who has obtained sufficient IAM privileges will disable CloudTrail logging before or during further attack phases to suppress evidence. Common patterns:

1. **Credential compromise** — attacker obtains long-term access key or assumes a privileged role.
2. **Reconnaissance** — `DescribeTrails`, `GetTrailStatus`, `ListTrails` to enumerate logging config.
3. **Disable logging** — `StopLogging` (reversible, quieter) or `DeleteTrail` (irreversible without re-creation).
4. **Subsequent actions** — data exfiltration, lateral movement, persistence — now unlogged in CloudTrail for that trail's scope.
5. **Optional cleanup** — delete S3 log objects (`DeleteObject` / `DeleteBucket`) to remove already-delivered logs (see CDET-014).

The gap between step 3 and when logging is restored is the **blind window** — your most critical investigative challenge.

---

## 2. Preserve the Triggering Event

Before any investigation queries, preserve the raw triggering event. Copy the full JSON from Splunk or the CloudTrail console and attach it to the incident ticket.

Key fields to record:

```
eventVersion
eventTime                         ← exact timestamp of the disablement
eventSource                       ← cloudtrail.amazonaws.com
eventName                         ← StopLogging | DeleteTrail
awsRegion
sourceIPAddress
userAgent
userIdentity.type
userIdentity.principalId
userIdentity.arn
userIdentity.accountId
userIdentity.sessionContext.sessionIssuer.arn   ← if AssumedRole
userIdentity.sessionContext.attributes.creationDate
requestParameters.name            ← trail ARN or name
responseElements                  ← should be null on success
errorCode                         ← present only if the call failed
```

---

## 3. Splunk SPL Investigation Queries

All queries use `index=aws_cloudtrail`. Substitute `<principal_arn>`, `<trail_name>`, and `<event_time>` from the triggering event.

### 3a. Confirm the event and get full context
```spl
index=aws_cloudtrail eventSource="cloudtrail.amazonaws.com"
  eventName IN ("StopLogging","DeleteTrail")
| table _time, eventName, userIdentity.arn, userIdentity.type,
        requestParameters.name, sourceIPAddress, userAgent, awsRegion,
        recipientAccountId, errorCode
| sort -_time
```

### 3b. Reconnaissance before the disablement (look back 2 hours)
```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
  eventSource="cloudtrail.amazonaws.com"
  eventName IN ("DescribeTrails","GetTrailStatus","ListTrails","GetEventSelectors","GetInsightSelectors")
| table _time, eventName, sourceIPAddress, userAgent
| sort _time
```

### 3c. Full activity from this principal in the 24 hours surrounding the event
```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
| eval event_time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| where event_time >= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "-24h")
  AND event_time <= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "+6h")
| table _time, eventName, eventSource, sourceIPAddress, userAgent,
        requestParameters, responseElements, errorCode
| sort _time
```

### 3d. Identify the blind window (events that occurred while logging was stopped)
```spl
index=aws_cloudtrail eventSource="cloudtrail.amazonaws.com"
  eventName IN ("StopLogging","StartLogging")
  requestParameters.name="<trail_name>"
| table _time, eventName, userIdentity.arn
| sort _time
```
The gap between the last `StopLogging` and the next `StartLogging` (or `CreateTrail`) is the blind window. Events during this window for the affected region(s) may be absent from CloudTrail.

### 3e. Check for S3 log deletion (evidence destruction, see CDET-014)
```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("DeleteObject","DeleteObjects","DeleteBucket")
| search requestParameters.bucketName IN (<values from cloudtrail_log_buckets.csv>)
| table _time, eventName, userIdentity.arn, requestParameters.bucketName,
        requestParameters.key, sourceIPAddress
| sort _time
```

### 3f. Look for privilege escalation preceding the disablement (48-hour lookback)
```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
  eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy",
                "CreateAccessKey","AssumeRole","CreateRole","UpdateAssumeRolePolicy")
| table _time, eventName, requestParameters, sourceIPAddress
| sort _time
```

### 3g. Identify if the session token was newly obtained (short-lived credential abuse)
```spl
index=aws_cloudtrail
  userIdentity.sessionContext.sessionIssuer.arn="<role_arn>"
| stats min(_time) as first_use, max(_time) as last_use, count by userIdentity.arn, sourceIPAddress
| sort first_use
```

### 3h. Check for concurrent suspicious activity across the account in the blind window
```spl
index=aws_cloudtrail
  recipientAccountId="<account_id>"
  eventName IN ("RunInstances","CreateUser","CreateAccessKey","PutBucketPolicy",
                "GetSecretValue","GetParameter","AssociateRouteTable","ModifyInstanceAttribute")
| where _time >= "<StopLogging_time>" AND _time <= "<StartLogging_or_now_time>"
| table _time, eventName, userIdentity.arn, sourceIPAddress, requestParameters
| sort _time
```

---

## 4. AWS CLI Context Gathering

All commands use the boto3 default credential chain (`aws configure`). Do not hardcode credentials.

### 4a. Verify current trail status
```bash
aws cloudtrail get-trail-status \
  --name "<trail_name_or_arn>" \
  --region "<awsRegion>"
```
Key output fields: `IsLogging`, `LatestDeliveryTime`, `LatestDeliveryError`, `StopLoggingTime`.

### 4b. Describe all trails in the account
```bash
aws cloudtrail describe-trails \
  --include-shadow-trails \
  --query "trailList[*].{Name:Name,S3Bucket:S3BucketName,MultiRegion:IsMultiRegionTrail,HomeRegion:HomeRegion,LogFileValidation:LogFileValidationEnabled}"
```

### 4c. Check IAM policy for the triggering principal
```bash
# For an IAM user
aws iam list-attached-user-policies --user-name "<username>"
aws iam list-user-policies --user-name "<username>"

# For a role
aws iam list-attached-role-policies --role-name "<role_name>"
aws iam list-role-policies --role-name "<role_name>"
aws iam get-role --role-name "<role_name>" \
  --query "Role.AssumeRolePolicyDocument"
```

### 4d. Determine when the principal's credentials were created
```bash
# Long-term access keys
aws iam list-access-keys --user-name "<username>" \
  --query "AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}"
```

### 4e. Check for recently created IAM entities (lateral movement / persistence)
```bash
aws iam list-users \
  --query "Users[?CreateDate>='<48h_before_event>'].{User:UserName,Created:CreateDate,Arn:Arn}"

aws iam list-roles \
  --query "Roles[?CreateDate>='<48h_before_event>'].{Role:RoleName,Created:CreateDate,Arn:Arn}"
```

### 4f. Validate log file integrity (if log file validation was enabled)
```bash
aws cloudtrail validate-logs \
  --trail-arn "<trail_arn>" \
  --start-time "<StopLogging_time>" \
  --s3-bucket "<log_bucket>" \
  --verbose
```

### 4g. List S3 bucket contents for the log bucket around the blind window
```bash
aws s3 ls s3://<log_bucket>/AWSLogs/<account_id>/CloudTrail/<region>/<year>/<month>/<day>/ \
  --recursive
```

---

## 5. Evidence to Collect and Preserve

For each item, attach to the incident ticket with a timestamp and the analyst's name.

| Evidence Item | How to Collect | Notes |
|---|---|---|
| Raw JSON of the triggering CloudTrail event | Splunk export or CloudTrail console | Include `eventID` as unique reference |
| Full principal activity log (±24 h) | SPL query 3c above, export as CSV | Covers pre/post disablement |
| Trail status output | AWS CLI 4a above, save as JSON | Confirms whether logging is still off |
| IAM policy documents for the principal | AWS CLI 4c above, save as JSON | Establishes how the actor got the permission |
| Access key creation date | AWS CLI 4d above | Helps determine if credential was recently created |
| S3 log bucket object listing | AWS CLI 4g above | Identifies if logs were deleted |
| List of all other active CloudTrail trails | AWS CLI 4b above | Confirms blast radius |
| Timeline of `StopLogging`/`StartLogging` events | SPL query 3d above | Defines blind window precisely |

Record the `eventID` for the triggering event — this is the immutable unique identifier for the CloudTrail record.

---

## 6. Timeline Reconstruction

1. **T-48h to T-2h:** Look for reconnaissance (`DescribeTrails`, `ListTrails`) and privilege escalation events from the same or related principal (queries 3b, 3f).
2. **T-2h to T:** Look for credential issuance (`AssumeRole`, `GetSessionToken`, console login) that produced the session used at time T (query 3g).
3. **T (StopLogging/DeleteTrail):** The triggering event. Record exact `eventTime`.
4. **T to T+X (blind window):** Use query 3h to identify any events that were still captured (CloudTrail may have latency — events just before T may appear after T). Check VPC Flow Logs, GuardDuty findings, and Config snapshots as supplementary sources for the blind period.
5. **T+X (StartLogging or trail re-creation, if any):** When and by whom was logging restored? Was it the same actor or a different principal (IR response)?
6. Compile the full timeline in chronological order and attach to the incident ticket before proceeding to containment.
