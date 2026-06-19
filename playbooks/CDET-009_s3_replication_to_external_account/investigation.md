---
detection_id: CDET-009
detection_name: S3 Replication to External Account
tactic: Exfiltration
technique: T1537
last_updated: 2026-06-18
---

# CDET-009 — Investigation Playbook
## S3 Replication to External Account

**Prerequisite:** Triage playbook completed and alert confirmed as requiring investigation.  
**Goal:** Reconstruct the full attack chain, determine the blast radius, and collect evidence for containment and post-incident review.

---

## 1. ATT&CK Context — T1537: Transfer Data to Cloud Account

In this technique an adversary creates or modifies S3 Cross-Region Replication (CRR) or Same-Region Replication (SRR) rules to silently copy all objects written to a victim bucket into an attacker-controlled S3 bucket in a different AWS account. Key characteristics:

- **Stealthy:** Replication happens asynchronously; no direct `GetObject` calls appear in logs for replicated data
- **Persistent:** The rule survives until explicitly removed — data exfiltration continues as long as new objects are written
- **Scalable:** A single `PutBucketReplication` call can exfiltrate an entire bucket's future writes
- **Pre-conditions:** The attacker must have obtained IAM credentials with `s3:PutReplicationConfiguration` permission and usually `iam:PassRole` to attach a replication IAM role

Typical attack chain:
```
Credential compromise / privilege escalation
  → IAM enumeration (GetAccountSummary, ListRoles, ListPolicies)
  → S3 enumeration (ListBuckets, GetBucketPolicy, GetBucketTagging)
  → (Optional) Create IAM role with replication trust policy
  → PutBucketReplication pointing to external account bucket
  → Ongoing silent exfiltration as objects are written
```

---

## 2. Preserve the Triggering Event

Before any further investigation, capture and preserve the raw event:

```spl
index=aws_cloudtrail eventName=PutBucketReplication
    requestParameters.bucketName="<bucket_name>"
| where _time >= relative_time(now(), "-2h")
| table _time, eventID, eventSource, eventName, awsRegion,
         userIdentity.type, userIdentity.arn, userIdentity.accountId,
         userIdentity.sessionContext.sessionIssuer.arn,
         requestParameters, responseElements,
         sourceIPAddress, userAgent, errorCode, errorMessage,
         requestID, eventID
```

**Record the following for your incident ticket:**
- `eventID` — unique identifier for this CloudTrail event
- `requestID` — correlates to S3 access logs if enabled
- `_time` (UTC) — authoritative timestamp
- Full `requestParameters` JSON — contains the complete replication configuration
- `userIdentity.sessionContext.sessionIssuer.arn` — the root identity if assumed role was used

Export and attach to incident ticket:
```spl
... | outputlookup CDET-009_evidence_<incident_id>.csv
```

---

## 3. Examine the Replication Configuration

The `requestParameters.replicationConfiguration` field contains the full rule set. Key sub-fields:

| Field | What to Look For |
|-------|-----------------|
| `rules[].destination.bucket` | Destination bucket ARN — extract account ID from this |
| `rules[].destination.accessControlTranslation` | If set, ACLs are being overridden — attacker may be granting themselves ownership |
| `rules[].destination.encryptionConfiguration.replicaKmsKeyID` | If attacker-controlled KMS key, data is encrypted under their key |
| `rules[].filter.prefix` | Empty prefix = all objects; narrow prefix = targeted exfiltration |
| `rules[].deleteMarkerReplication.status` | Enabled = delete markers also replicated (rare, more suspicious) |
| `role` | IAM role ARN used — must have `s3:ReplicateObject` on destination |

---

## 4. Reconstruct the Actor's Full Session

Identify all actions the actor took in the 4 hours before and 1 hour after the `PutBucketReplication` event:

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
| where _time >= relative_time("<event_time>", "-4h")
      AND _time <= relative_time("<event_time>", "+1h")
| stats count by eventName, eventSource, awsRegion, errorCode
| sort -count
```

Look specifically for these pre-attack reconnaissance events:

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
    (eventName IN (
        "GetAccountSummary", "ListRoles", "ListPolicies", "ListAttachedRolePolicies",
        "GetPolicy", "GetPolicyVersion", "SimulatePrincipalPolicy",
        "ListBuckets", "GetBucketPolicy", "GetBucketAcl", "GetBucketTagging",
        "GetBucketVersioning", "GetBucketReplication", "ListObjects", "HeadBucket"
    ))
| where _time >= relative_time("<event_time>", "-4h")
| table _time, eventName, requestParameters, sourceIPAddress
| sort _time
```

---

## 5. IAM Role Investigation

Investigate the IAM role used to call `PutBucketReplication` and the replication role referenced in the config:

**Calling identity:**
```bash
aws iam get-role --role-name <calling_role_name>
aws iam list-attached-role-policies --role-name <calling_role_name>
aws iam list-role-policies --role-name <calling_role_name>
# For inline policies:
aws iam get-role-policy --role-name <calling_role_name> --policy-name <policy_name>
```

**Replication execution role (from config):**
```bash
aws iam get-role --role-name <replication_role_name>
# Check trust policy — should only trust s3.amazonaws.com
# If it trusts an external account or wildcard principal, it was modified by the attacker

aws iam get-role-policy --role-name <replication_role_name> --policy-name <policy_name>
# Legitimate replication roles have s3:ReplicateObject, s3:ReplicateDelete, s3:GetObjectVersionForReplication
# Attacker-created roles may have broader permissions (s3:* or sts:AssumeRole)
```

**When was the replication role created?**
```bash
aws iam get-role --role-name <replication_role_name> \
  --query 'Role.{Created:CreateDate,Arn:Arn,TrustPolicy:AssumeRolePolicyDocument}'
```

---

## 6. S3 Bucket Context

```bash
# Current replication configuration (may have been modified since the event)
aws s3api get-bucket-replication --bucket <bucket_name>

# Bucket versioning (required for replication — was it recently enabled?)
aws s3api get-bucket-versioning --bucket <bucket_name>

# Bucket policy — has cross-account access been granted?
aws s3api get-bucket-policy --bucket <bucket_name>

# Bucket ACL
aws s3api get-bucket-acl --bucket <bucket_name>

# Bucket tags — data classification
aws s3api get-bucket-tagging --bucket <bucket_name>

# Recent object activity (if S3 server access logging is enabled)
aws s3api list-objects-v2 --bucket <access-log-bucket> \
  --prefix <log_prefix>/<bucket_name>/ \
  --query 'Contents[?LastModified>=`<event_time>`]'
```

---

## 7. Determine Blast Radius — What Data Was Exposed

**Estimate data written since the replication rule was created:**

```bash
# List objects modified after the PutBucketReplication timestamp
aws s3api list-objects-v2 \
  --bucket <bucket_name> \
  --query "Contents[?LastModified>=\`<event_time_iso8601>\`].{Key:Key,Size:Size,LastModified:LastModified}" \
  --output json
```

```spl
index=aws_cloudtrail eventName IN ("PutObject", "CopyObject", "CompleteMultipartUpload")
    requestParameters.bucketName="<bucket_name>"
| where _time >= "<event_time>"
| stats count AS object_count, sum(requestParameters.contentLength) AS total_bytes
        by requestParameters.bucketName
```

**If S3 server access logs are available:**
```spl
index=s3_access_logs bucket_name="<bucket_name>"
    operation IN ("REST.PUT.OBJECT", "REST.COPY.OBJECT", "REST.POST.UPLOAD")
| where _time >= "<event_time>"
| stats count, sum(bytes_sent) by bucket_name
```

---

## 8. Check for Lateral Movement or Persistence

Was the attacker's session used to create additional backdoors?

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
    (eventName IN (
        "CreateUser", "CreateRole", "AttachUserPolicy", "AttachRolePolicy",
        "PutUserPolicy", "PutRolePolicy", "CreateAccessKey", "CreateLoginProfile",
        "AddUserToGroup", "UpdateAssumeRolePolicy", "PutBucketPolicy",
        "PutBucketNotification", "CreateFunction20150331", "UpdateFunctionCode20150331v2"
    ))
| where _time >= relative_time("<event_time>", "-6h")
| table _time, eventName, requestParameters
| sort _time
```

---

## 9. Check for Other Affected Buckets

Did the same actor configure replication on any other bucket?

```spl
index=aws_cloudtrail eventName=PutBucketReplication
    userIdentity.arn="<actor_arn>"
| table _time, requestParameters.bucketName, requestParameters.replicationConfiguration
| sort _time
```

Also check for the same destination account across all `PutBucketReplication` events (not just this actor):

```spl
index=aws_cloudtrail eventName=PutBucketReplication
| rex field=requestParameters.replicationConfiguration "arn:aws:iam::(?P<dest_account_id>\d{12}):"
| where dest_account_id="<external_account_id>"
| table _time, userIdentity.arn, requestParameters.bucketName, dest_account_id
```

---

## 10. Evidence Checklist

Collect and preserve the following before moving to containment:

- [ ] Raw CloudTrail event JSON for the triggering `PutBucketReplication` event (`eventID`)
- [ ] Full replication configuration (destination bucket ARN, destination account, IAM role ARN, prefix filter)
- [ ] IAM role details for calling identity (creation date, attached policies)
- [ ] IAM role details for replication execution role (trust policy, creation date)
- [ ] List of objects written to the bucket after the replication rule was set (count + estimated size)
- [ ] Actor session timeline (all API calls ±4 hours)
- [ ] Current bucket replication config (snapshot via `get-bucket-replication`)
- [ ] Bucket policy and ACL snapshot
- [ ] Any additional buckets affected by the same actor or destination account
- [ ] Source IP geolocation and ASN
- [ ] CloudTrail event IDs for any IAM changes made by the same actor

All evidence files should be written to the incident ticket with timestamps and stored in the IR evidence S3 bucket following the chain-of-custody process.
