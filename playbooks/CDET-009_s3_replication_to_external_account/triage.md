---
detection_id: CDET-009
detection_name: S3 Replication to External Account
tactic: Exfiltration
technique: T1537
last_updated: 2026-06-18
---

# CDET-009 — Triage Playbook
## S3 Replication to External Account

**Target completion time:** 5–10 minutes  
**Goal:** Determine whether this is a genuine exfiltration attempt or a benign/authorized replication configuration. Escalate immediately if confirmed real.

---

## 1. Pull the Raw Alert

Locate the triggering CloudTrail event in Splunk:

```spl
index=aws_cloudtrail eventName=PutBucketReplication
| where _time >= relative_time(now(), "-15m")
| table _time, userIdentity.arn, userIdentity.accountId, requestParameters.bucketName,
         requestParameters.replicationConfiguration, sourceIPAddress, userAgent,
         errorCode, awsRegion
```

Note the following fields before proceeding:
- `userIdentity.arn` — who made the call
- `userIdentity.accountId` — source AWS account
- `requestParameters.bucketName` — bucket being configured
- `requestParameters.replicationConfiguration` — **contains the destination account ID**
- `sourceIPAddress` — origin of the API call
- `errorCode` — if present, the action may have failed (lower urgency but still investigate)

---

## 2. Extract the Destination Account ID

The destination account is embedded in the replication configuration. Look for the `Role` ARN and `Bucket` ARN in the replication config:

```
requestParameters.replicationConfiguration.rules{}.destination.bucket
```

The bucket ARN format is `arn:aws:s3:::bucket-name`. The owning account can be confirmed via:

```bash
aws s3api get-bucket-location --bucket <destination-bucket-name>
# If access denied, bucket is in a foreign account — expected for external replication
```

Extract the destination account from the IAM role ARN in the replication config:
```
arn:aws:iam::<ACCOUNT_ID>:role/<role-name>
```

---

## 3. Validate Against Known-Good Lookups

Check the destination account ID against the authorized accounts lookup CSV:

```spl
index=aws_cloudtrail eventName=PutBucketReplication
| eval dest_account = mvindex(split(mvindex(split('requestParameters.replicationConfiguration', "arn:aws:iam::"), 1), ":"), 0)
| lookup splunk/lookups/trusted_aws_accounts.csv account_id AS dest_account OUTPUT account_label, is_authorized
| table _time, userIdentity.arn, requestParameters.bucketName, dest_account, account_label, is_authorized
```

**Relevant lookup files (splunk/lookups/):**
| File | Purpose |
|------|---------|
| `trusted_aws_accounts.csv` | Authorized internal/partner AWS account IDs |
| `approved_service_accounts.csv` | IAM roles/users approved for S3 cross-account operations |
| `s3_sensitive_buckets.csv` | Buckets tagged as sensitive or containing regulated data |
| `known_pipeline_actors.csv` | CI/CD and automation roles expected to modify bucket configs |

---

## 4. Check the Actor Identity

**Is this a known pipeline actor?**

```spl
index=aws_cloudtrail eventName=PutBucketReplication
| lookup splunk/lookups/known_pipeline_actors.csv userArn AS userIdentity.arn OUTPUT pipeline_name, is_approved
| table userIdentity.arn, pipeline_name, is_approved
```

**Is the source IP expected?**
- Internal corporate IP ranges: check `trusted_ip_ranges.csv`
- If `sourceIPAddress` is an AWS service endpoint (e.g., `s3.amazonaws.com`), a service or Lambda triggered the call — trace the invoker
- Unexpected geographic origin is a strong escalation signal

**Is the IAM role/user newly created or recently modified?**

```bash
aws iam get-role --role-name <role-name>
# Check CreateDate — roles created within the last 24–48 hours are suspicious
```

---

## 5. Check the Target Bucket Sensitivity

```spl
index=aws_cloudtrail eventName=PutBucketReplication
| lookup splunk/lookups/s3_sensitive_buckets.csv bucket_name AS requestParameters.bucketName OUTPUT data_classification, owner_team
| table requestParameters.bucketName, data_classification, owner_team
```

If the bucket is classified as `sensitive`, `pii`, `regulated`, or `confidential`, **escalate immediately regardless of other indicators**.

---

## 6. Check for Prior Reconnaissance Activity

Look for S3 enumeration by the same actor in the preceding 60 minutes:

```spl
index=aws_cloudtrail userIdentity.arn="<actor_arn>"
    (eventName=ListBuckets OR eventName=GetBucketPolicy OR eventName=GetBucketAcl
     OR eventName=ListObjects OR eventName=GetBucketReplication)
| where _time >= relative_time(now(), "-60m")
| stats count by eventName, _time
| sort _time
```

A sequence of List → Get → PutBucketReplication is a strong indicator of intentional exfiltration setup.

---

## 7. PASS / FAIL Criteria

### PASS — Likely Benign (False Positive)

All of the following must be true to pass:
- [ ] Destination account ID matches an entry in `trusted_aws_accounts.csv` with `is_authorized=true`
- [ ] Actor identity matches an entry in `known_pipeline_actors.csv` or `approved_service_accounts.csv`
- [ ] Source IP is within known corporate or AWS-internal ranges
- [ ] No prior reconnaissance events from the same actor in the last 60 minutes
- [ ] Bucket is not flagged in `s3_sensitive_buckets.csv`
- [ ] A change ticket or CAB approval exists for this replication config (verify with asset owner)

**Action:** Document findings, close alert as FP, note ticket reference, and consider suppression tuning (see recovery playbook).

### FAIL — Escalate Immediately

Escalate if **any** of the following are true:
- [ ] Destination account ID is not in `trusted_aws_accounts.csv`
- [ ] Actor is not a recognized pipeline/service account
- [ ] Source IP is from an unexpected geography or anonymizing proxy
- [ ] Bucket contains sensitive, PII, or regulated data
- [ ] Reconnaissance activity preceded the `PutBucketReplication` call
- [ ] The IAM role used was created or modified within the last 48 hours
- [ ] `errorCode` is absent (the action succeeded)

**Action:** Immediately proceed to `investigation.md`. Page the on-call cloud security engineer. Do **not** delete evidence.

---

## 8. Escalation

| Condition | Action |
|-----------|--------|
| Destination account unknown + sensitive bucket | **P1 — Page immediately** |
| Destination account unknown + non-sensitive bucket | **P2 — Begin investigation now** |
| Destination account known partner + no change ticket | **P3 — Verify with asset owner within 1 hour** |
| All PASS criteria met | Close as FP, document |

Escalation contact: Cloud Security on-call via PagerDuty runbook `IR-CLOUD-001`.
