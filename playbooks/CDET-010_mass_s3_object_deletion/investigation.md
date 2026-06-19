---
detection_id: CDET-010
detection_name: Mass S3 Object Deletion
tactic: Impact
technique: T1485
last_updated: 2026-06-18
---

# CDET-010 — Mass S3 Object Deletion: Investigation Playbook

**Audience:** Tier-2 SOC Analyst  
**Prerequisites:** Triage complete, alert assessed as TP or needs deeper investigation.  
**Goal:** Reconstruct the full attack chain, determine blast radius, and collect court-quality evidence before containment.

---

## 1. Understand the T1485 Attack Chain

T1485 (Data Destruction) in AWS S3 typically follows this sequence:

```
1. Initial Access / Credential Compromise
   └─ StealApplicationAccessToken, PhishingForCredentials, EC2 IMDS abuse (CDET-007)

2. Reconnaissance
   └─ ListBuckets, GetBucketPolicy, ListObjectsV2, GetBucketVersioning, GetBucketReplication

3. Defense Evasion (optional — may overlap with CDET-003/CDET-014)
   └─ DeleteTrail, StopLogging, PutBucketLogging (disable access logs)
   └─ PutBucketLifecycleConfiguration (set aggressive expiry)
   └─ PutBucketVersioning (disable versioning) ← destroys recovery path

4. Impact
   └─ DeleteObjects (bulk) ← CDET-010 trigger
   └─ DeleteBucket (if bucket becomes empty after deletions)

5. Persistence / Ransom (in some variants)
   └─ PutBucketPolicy (deny all) or external account replication before deletion
```

**Key differentiator from accidental deletion:** Attackers almost always disable versioning or delete all versions + delete markers in the same session. A legitimate misconfiguration rarely touches versioning controls.

---

## 2. Critical CloudTrail Event Fields for CDET-010

| Field | Significance |
|---|---|
| `requestParameters.delete.objects[*].key` | Exact keys deleted — look for patterns (all keys? specific prefix?) |
| `requestParameters.delete.objects[*].versionId` | If populated: attacker specifically targeted versioned objects (bypasses restore) |
| `requestParameters.delete.quiet` | `true` = errors not returned — common in scripted attacks |
| `userIdentity.sessionContext.creationDate` | Session age — new sessions minutes old = compromised credential |
| `userIdentity.sessionContext.mfa` | Was MFA present? Absence for a human identity is suspicious |
| `tlsDetails.clientProvidedHostHeader` | Client hostname — can identify tooling (e.g., boto3, awscli, custom script) |
| `userAgent` | `aws-cli/`, `Boto3/`, `python-requests/`, `curl/` — note anomalous agents |
| `requestID` | Preserve — unique event identifier for legal hold |
| `eventID` | Preserve — Splunk/SIEM correlation anchor |
| `recipientAccountId` | Confirm this is your account, not a cross-account confusion |

---

## 3. Splunk SPL Investigation Queries

All queries target the `aws_cloudtrail` index. Adjust `earliest`/`latest` to your incident window.

**3a. Full activity timeline for the implicated principal (±2 hours around deletion)**
```spl
index=aws_cloudtrail userIdentity.arn="<ARN>"
  earliest=-2h@h latest=+30m
| eval eventTime=strftime(strptime(eventTime,"%Y-%m-%dT%H:%M:%SZ"),"%Y-%m-%d %H:%M:%S")
| table eventTime, eventName, awsRegion, sourceIPAddress, requestParameters, errorCode, errorMessage
| sort eventTime
```

**3b. Reconstruction: all S3 actions on the affected bucket in the last 24 hours**
```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  requestParameters.bucketName="<bucket>"
  earliest=-24h
| stats count BY eventName, userIdentity.arn, sourceIPAddress
| sort -count
```

**3c. Check if versioning was disabled before deletion (defense evasion)**
```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName="PutBucketVersioning"
  requestParameters.bucketName="<bucket>"
  earliest=-6h
| table eventTime, userIdentity.arn, requestParameters, sourceIPAddress
```

**3d. Check if lifecycle rules were tampered with**
```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("PutBucketLifecycleConfiguration","DeleteBucketLifecycle")
  requestParameters.bucketName="<bucket>"
  earliest=-6h
| table eventTime, userIdentity.arn, requestParameters
```

**3e. Check if CloudTrail logging was disabled around the same time (CDET-003 correlation)**
```spl
index=aws_cloudtrail eventName IN ("StopLogging","DeleteTrail","UpdateTrail")
  earliest=-6h latest=+1h
| table eventTime, userIdentity.arn, requestParameters, sourceIPAddress
```

**3f. Determine total object count and key prefixes deleted**
```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName="DeleteObjects"
  requestParameters.bucketName="<bucket>"
  earliest=-24h
| spath input=requestParameters path="delete.objects{}" output=deleted_objects
| mvexpand deleted_objects
| spath input=deleted_objects path="key" output=key
| stats count AS total_deleted, dc(key) AS unique_keys, values(key) AS sample_keys BY userIdentity.arn
```

**3g. Pivot: same source IP used against other buckets or services**
```spl
index=aws_cloudtrail sourceIPAddress="<IP>"
  earliest=-24h
| stats count BY eventName, eventSource, requestParameters.bucketName, userIdentity.arn
| sort -count
```

**3h. Check for cross-account replication setup before deletion (data exfil + destroy)**
```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName="PutBucketReplication"
  requestParameters.bucketName="<bucket>"
  earliest=-12h
| table eventTime, userIdentity.arn, requestParameters
```

---

## 4. IAM and Resource Context (AWS CLI)

All commands use the default boto3 credential chain — configure via `aws configure` or environment variables. Do not hardcode credentials.

**4a. Who is the compromised principal and what policies are attached?**
```bash
# For an IAM user
aws iam get-user --user-name <username>
aws iam list-attached-user-policies --user-name <username>
aws iam list-user-policies --user-name <username>
aws iam list-groups-for-user --user-name <username>

# For an assumed role
aws iam get-role --role-name <role-name>
aws iam list-attached-role-policies --role-name <role-name>
aws iam list-role-policies --role-name <role-name>
```

**4b. Check when the principal's access key was created (recency = higher suspicion)**
```bash
aws iam list-access-keys --user-name <username>
# Note: CreateDate and Status fields
```

**4c. Get current bucket state**
```bash
# Versioning status
aws s3api get-bucket-versioning --bucket <bucket-name>

# Lifecycle configuration
aws s3api get-bucket-lifecycle-configuration --bucket <bucket-name> 2>/dev/null || echo "No lifecycle rules"

# Replication configuration
aws s3api get-bucket-replication --bucket <bucket-name> 2>/dev/null || echo "No replication"

# Bucket policy
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text | python -m json.tool

# ACL
aws s3api get-bucket-acl --bucket <bucket-name>
```

**4d. Enumerate surviving objects and delete markers**
```bash
# Count delete markers (confirms objects were "deleted" rather than permanently destroyed if versioning was on)
aws s3api list-object-versions --bucket <bucket-name> \
  --query "length(DeleteMarkers)" \
  --output text

# List all delete markers with timestamps
aws s3api list-object-versions --bucket <bucket-name> \
  --query "DeleteMarkers[*].{Key:Key,VersionId:VersionId,LastModified:LastModified,Owner:Owner.DisplayName}" \
  --output table
```

**4e. Check S3 server access logs (if enabled)**
```bash
aws s3api get-bucket-logging --bucket <bucket-name>
# If logging is enabled, retrieve logs from the target logging bucket for the incident window
```

---

## 5. Evidence to Collect and Preserve

Before any containment action, collect and store the following in the incident ticket or evidence S3 bucket (write-once policy preferred):

| Evidence Item | How to Collect |
|---|---|
| CloudTrail event JSON for all `DeleteObjects` events | Splunk export or `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObjects` |
| Full `requestParameters.delete.objects` list (all deleted keys + versionIds) | From CloudTrail event JSON; also from `list-object-versions` delete markers |
| `eventID` and `requestID` for each deletion event | From CloudTrail JSON |
| Actor's IAM policies (snapshot) | `aws iam get-user-policy` / `aws iam get-role-policy` output |
| Bucket versioning/lifecycle/replication config at time of discovery | `aws s3api get-bucket-versioning` etc. (document current state) |
| Source IP geolocation and ASN | `whois <IP>`, `dig -x <IP>`, threat intel lookup |
| User-Agent string from CloudTrail | From `tlsDetails` or `userAgent` field |
| Timestamps of all related events (session start to last action) | Timeline table from SPL query 3a above |

---

## 6. Timeline Reconstruction Approach

1. **Anchor the session start:** Find the earliest `AssumeRole`, `GetSessionToken`, or API call using the same `accessKeyId` from the CloudTrail `userIdentity.accessKeyId` field. This is T0.
2. **Map enumeration phase:** List all `List*`, `Get*`, `Describe*` calls by the same principal in the window T0 to T(deletion).
3. **Identify defense evasion:** Note any `PutBucketVersioning`, `DeleteTrail`, `StopLogging`, `PutBucketLifecycleConfiguration` between T0 and T(deletion).
4. **Mark deletion events:** Timestamp of first `DeleteObjects` call = T(impact start). Timestamp of last = T(impact end).
5. **Check for exfiltration before destruction:** `GetObject`, `CopyObject`, `PutBucketReplication` in T0 to T(impact start).
6. **Look for cleanup:** `DeleteBucket`, `DeleteAccessKey`, `DeactivateMFADevice` after T(impact end).

Build the timeline as a table in the incident ticket with columns: `eventTime | eventName | resource | sourceIPAddress | notes`.

---

## Next Step

Once the blast radius is understood and evidence is preserved, proceed to `containment.md`.
