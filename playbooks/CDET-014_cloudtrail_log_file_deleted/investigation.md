---
detection_id: CDET-014
detection_name: CloudTrail Log File Deleted
tactic: Defense Evasion
technique: T1070.004
last_updated: 2026-06-18
---

# CDET-014 — CloudTrail Log File Deleted: Investigation

**Prerequisite:** CDET-014 triage checklist completed with a FAIL result. An incident ticket is open. AWS CLI is configured using `aws configure` (boto3 default credential chain — no hardcoded credentials). You have read access to the target S3 bucket and CloudTrail.

---

## 1. Understand the Attack Technique

**MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion**

An adversary who has already compromised credentials with `s3:DeleteObject` permissions on the CloudTrail delivery bucket will delete log files to destroy forensic evidence of earlier activity. This is almost always a **secondary action** in a broader attack chain — the deletion itself is the last step to cover tracks.

### Typical attack chain leading to CDET-014

```
1. Credential compromise
   └─ Phishing / access key leak / SSRF / instance metadata abuse (CDET-007)

2. Reconnaissance
   └─ ListBuckets, GetBucketLocation, ListObjectsV2 on the CloudTrail bucket
      DescribeTrails, GetTrailStatus to identify log delivery configuration

3. Privilege escalation or lateral movement (optional)
   └─ IAM privilege escalation to get s3:DeleteObject on the log bucket

4. Pre-deletion activity coverage
   └─ CDET-003: StopLogging / DeleteTrail  ← may precede or follow deletion
      CDET-005: Modify role trust to maintain access

5. Log deletion  ← CDET-014 triggers here
   └─ DeleteObject / DeleteObjects on AWSLogs/ prefix
      Targeted: specific date ranges covering the initial compromise
      OR bulk: mass deletion to remove all recent evidence

6. Continued attack (now operating with reduced visibility)
   └─ Data exfiltration, persistence, lateral movement
```

The critical question is: **what activity was the attacker trying to hide?** The deleted log files represent a gap in your visibility. Reconstruct the timeline before and after the deleted log window using any surviving sources.

---

## 2. Preserve the Triggering Event

Before running any queries, preserve the raw triggering event. Copy the full JSON from Splunk or the CloudTrail console and attach it to the incident ticket.

Key fields to record and carry through all investigation steps:

```
eventVersion
eventTime                              ← exact deletion timestamp
eventSource                            ← s3.amazonaws.com
eventName                              ← DeleteObject | DeleteObjects
awsRegion
sourceIPAddress
userAgent
userIdentity.type
userIdentity.principalId
userIdentity.arn
userIdentity.accountId
userIdentity.accessKeyId              ← the key used — check if it was recently created
userIdentity.sessionContext.sessionIssuer.arn          ← if AssumedRole
userIdentity.sessionContext.attributes.creationDate    ← when the session was created
requestParameters.bucketName          ← target CloudTrail log bucket
requestParameters.key                 ← deleted object key (AWSLogs/...)
requestParameters.versionId           ← present if a specific version was permanently deleted
responseElements                      ← should be null on success
errorCode                             ← present only if the call failed
```

For `DeleteObjects` (batch), extract every `requestParameters.delete.objects[*].key` entry — each is a log file that was destroyed.

---

## 3. Decode the Deleted Log File Key

A CloudTrail S3 object key follows a predictable format:

```
AWSLogs/<account_id>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/
  <account_id>_CloudTrail_<region>_<YYYYMMDDTHHmmZ>_<random>.json.gz
```

From the deleted key, extract:
- **Account ID** and **region** the logs cover
- **Date range** of the logs destroyed

This tells you the exact time window you are blind for — document it in the ticket as the **evidence gap window**.

---

## 4. CloudTrail Event Fields to Examine for T1070.004

Beyond the standard fields, pay particular attention to:

| Field | What to Look For |
|---|---|
| `requestParameters.key` | Date range in the path — are the deleted files concentrated around the attacker's initial access? |
| `requestParameters.versionId` | If present, the object is permanently gone even with versioning enabled |
| `userIdentity.accessKeyId` | Is this key recent? Was it created by a different principal? |
| `userIdentity.sessionContext.attributes.creationDate` | Short-lived sessions that were created specifically for this action are suspicious |
| `sourceIPAddress` | Does the IP match prior suspicious activity for this principal? |
| `userAgent` | `aws-cli/` or `Boto3/` strings suggest scripted automation; a browser-based `console.amazonaws.com` agent suggests manual action |
| `tlsDetails.cipherSuite` | Anomalous TLS configurations can indicate non-standard tooling |

---

## 5. Splunk SPL Investigation Queries

All queries use `index=aws_cloudtrail`. Substitute values from the triggering event where indicated.

### 5a. Confirm the deletion event and get all deleted keys

```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("DeleteObject","DeleteObjects")
  requestParameters.bucketName="<bucket_name>"
| spath requestParameters.delete.objects{}.key output=batch_keys
| eval all_keys=coalesce(requestParameters.key, batch_keys)
| table _time, eventName, userIdentity.arn, userIdentity.accessKeyId,
        all_keys, requestParameters.versionId, sourceIPAddress, userAgent,
        awsRegion, recipientAccountId, errorCode
| sort _time
```

### 5b. Reconnaissance activity before the deletion (look back 6 hours)

```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
  eventSource="s3.amazonaws.com"
  eventName IN ("ListBuckets","ListObjectsV2","ListObjects","GetBucketLogging",
                "GetBucketLocation","GetBucketVersioning","HeadObject")
| where _time <= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "+0s")
  AND _time >= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "-6h")
| table _time, eventName, requestParameters.bucketName, requestParameters.prefix,
        sourceIPAddress, userAgent
| sort _time
```

### 5c. CloudTrail-service reconnaissance (look back 6 hours, same principal)

```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
  eventSource="cloudtrail.amazonaws.com"
  eventName IN ("DescribeTrails","GetTrailStatus","ListTrails",
                "GetEventSelectors","GetInsightSelectors","LookupEvents")
| where _time >= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "-6h")
| table _time, eventName, sourceIPAddress, userAgent, requestParameters
| sort _time
```

### 5d. Did the same actor also disable CloudTrail logging? (CDET-003 correlation)

```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
  eventSource="cloudtrail.amazonaws.com"
  eventName IN ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors")
| table _time, eventName, requestParameters.name, sourceIPAddress, userAgent
| sort _time
```

### 5e. Full 48-hour activity timeline for this principal

```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
| where _time >= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "-24h")
  AND _time <= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "+24h")
| table _time, eventSource, eventName, awsRegion, sourceIPAddress, userAgent,
        requestParameters, responseElements, errorCode
| sort _time
```

### 5f. IAM activity associated with the access key (was the key newly created?)

```spl
index=aws_cloudtrail eventSource="iam.amazonaws.com"
  eventName="CreateAccessKey"
| where responseElements.accessKey.accessKeyId="<accessKeyId from alert>"
| table _time, userIdentity.arn, requestParameters.userName, sourceIPAddress
```

### 5g. Did any other principal delete log files from the same bucket in the past 7 days?

```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("DeleteObject","DeleteObjects")
  requestParameters.bucketName="<bucket_name>"
  requestParameters.key="AWSLogs/*"
| stats count AS delete_count BY userIdentity.arn, date_mday
| sort -delete_count
```

### 5h. Are there correlated events from the same source IP across other services?

```spl
index=aws_cloudtrail sourceIPAddress="<source_ip>"
| where _time >= relative_time(strptime("<event_time>","%Y-%m-%dT%H:%M:%SZ"), "-12h")
| stats count AS event_count BY eventSource, eventName, userIdentity.arn
| sort -event_count
```

---

## 6. IAM and Resource Context — AWS CLI Commands

Run these commands using `aws configure` credentials (boto3 default chain — no hardcoded keys).

### 6a. Who is the acting principal?

```bash
# Get the current caller identity for reference
aws sts get-caller-identity

# Describe the IAM user or role that performed the deletion
# For IAM users:
aws iam get-user \
  --user-name <username_from_arn>

# For assumed roles — get the role details
aws iam get-role \
  --role-name <role_name_from_arn>
```

### 6b. What S3 permissions does the actor have on the log bucket?

```bash
# Get the bucket policy
aws s3api get-bucket-policy \
  --bucket <bucket_name> \
  --output json

# Get the bucket ACL
aws s3api get-bucket-acl \
  --bucket <bucket_name>

# Check bucket versioning and MFA delete status
aws s3api get-bucket-versioning \
  --bucket <bucket_name>
```

### 6c. What inline and attached policies does the actor have?

```bash
# List attached policies for the role
aws iam list-attached-role-policies \
  --role-name <role_name>

# List inline policies for the role
aws iam list-role-policies \
  --role-name <role_name>

# Get a specific inline policy
aws iam get-role-policy \
  --role-name <role_name> \
  --policy-name <policy_name>
```

### 6d. Are the deleted log objects still recoverable?

```bash
# List all versions of objects under AWSLogs/ — delete markers will appear
aws s3api list-object-versions \
  --bucket <bucket_name> \
  --prefix "AWSLogs/" \
  --query "Versions[?IsLatest==\`false\`].[Key,VersionId,LastModified]" \
  --output table

# List delete markers specifically
aws s3api list-object-versions \
  --bucket <bucket_name> \
  --prefix "AWSLogs/" \
  --query "DeleteMarkers[*].[Key,VersionId,LastModified,IsLatest]" \
  --output table
```

### 6e. What is the current CloudTrail configuration?

```bash
# List all trails in this account/region
aws cloudtrail describe-trails \
  --include-shadow-trails false

# Check the delivery status for the affected trail
aws cloudtrail get-trail-status \
  --name <trail_name_or_arn>
```

### 6f. Is there a secondary/backup CloudTrail trail that captured the blind window?

```bash
# List all trails (including shadow trails from other regions)
aws cloudtrail describe-trails \
  --include-shadow-trails true \
  --query "trailList[*].[Name,S3BucketName,IsMultiRegionTrail,HomeRegion]" \
  --output table
```

---

## 7. Evidence to Collect and Preserve

Attach all of the following to the incident ticket before containment:

| Evidence Item | How to Collect |
|---|---|
| Raw CloudTrail JSON for the triggering `DeleteObject` event | Export from Splunk or CloudTrail console |
| Full list of deleted object keys (especially for batch `DeleteObjects`) | Splunk query 5a above |
| The exact evidence gap window (account, region, date/time range) | Decoded from the deleted key path |
| Full 48-hour activity timeline for the actor | Splunk query 5e above |
| IAM user/role details and attached policy documents | AWS CLI commands 6b–6c above |
| Bucket versioning status and list of delete markers | AWS CLI command 6d above |
| Current CloudTrail trail configuration and delivery status | AWS CLI command 6e above |
| Source IP WHOIS / ASN information | External lookup |
| Access key creation event (if key was newly created) | Splunk query 5f above |

---

## 8. Timeline Reconstruction Approach

Because log objects may be destroyed, reconstruct the full picture using **every available log source**:

1. **Surviving CloudTrail events** — events delivered to S3 before the deletion window, plus events from any secondary trails.
2. **CloudTrail Insights** — check for unusual API activity patterns in the weeks before the incident.
3. **AWS Config** — resource configuration changes (IAM policy attachments, S3 bucket policy changes) are recorded independently.
4. **VPC Flow Logs** — network-level evidence of data movement, even if CloudTrail API logs are missing.
5. **S3 Access Logs** — if server access logging was enabled on the CloudTrail bucket, these logs are stored separately and may survive the deletion.
6. **GuardDuty findings** — check for any findings generated against the acting principal in the 7 days before the alert.
7. **Delete marker timestamps in S3 versioning** — even if objects are deleted, the delete markers record the exact deletion time, which you can use to anchor the gap window precisely.

Document the gap window and all surviving log sources in a timeline table in the incident ticket. Flag any time ranges where no log sources are available.
