---
detection_id: CDET-010
detection_name: Mass S3 Object Deletion
tactic: Impact
technique: T1485
last_updated: 2026-06-18
---

# CDET-010 — Mass S3 Object Deletion: Triage Playbook

**Target completion time:** 5–10 minutes  
**Audience:** Tier-2 SOC Analyst  
**Escalate immediately if:** bucket contains production data, logging/backup artifacts, or financial records — do not wait to complete triage.

---

## 1. Confirm the Alert Fired Correctly

1. Open the CDET-010 alert in Splunk and verify the detection query matched on `eventName=DeleteObjects` (not a related but benign event such as `DeleteObject` on a single key).
2. Confirm the event came from the `aws_cloudtrail` index and is NOT a replayed/test event (check `_indextime` vs `eventTime` — a gap > 5 minutes with no other surrounding events suggests a test replay).
3. Verify the Splunk saved-search threshold was crossed (default: ≥ 50 objects deleted within a 10-minute window by a single principal). Note the exact count.

---

## 2. Fields to Check in the Alert and CloudTrail

| Field | What to Check |
|---|---|
| `userIdentity.arn` | Is this a known automation role or human user? |
| `userIdentity.type` | `AssumedRole`, `IAMUser`, `Root`? Root is an immediate escalation trigger. |
| `userIdentity.sessionContext.sessionIssuer.arn` | For assumed roles — what is the parent role? |
| `sourceIPAddress` | AWS service IP (e.g., `s3.amazonaws.com`) or external IP? |
| `requestParameters.bucketName` | Which bucket? Is it in `cloudtrail_log_buckets.csv`? |
| `requestParameters.delete.objects` | How many keys? What key prefixes? |
| `requestParameters.delete.quiet` | `true` means errors are suppressed — common in attack tooling. |
| `errorCode` | Errors present? `AccessDenied` errors mixed in suggest trial-and-error. |
| `resources[].ARN` | Full bucket ARN — cross-check against known critical asset inventory. |
| `awsRegion` | Is this an approved region? Check `approved_regions.csv`. |
| `versionId` | Were versioned objects deleted? Were delete markers applied instead of true deletes? |

---

## 3. Lookup CSV Checks

Run each check in Splunk before concluding triage:

**3a. Is the actor a known automation principal?**
```spl
| inputlookup approved_iam_principals.csv
| search arn="<userIdentity.arn from alert>"
```
If a match is found, record the `purpose` and `owner` fields and continue to step 4.

**3b. Is the source account approved?**
```spl
| inputlookup approved_aws_accounts.csv
| search account_id="<recipientAccountId from alert>"
```
An unapproved account is an immediate escalation trigger.

**3c. Is the source IP in an approved CIDR range?**
```spl
| inputlookup approved_cidr_ranges.csv
```
Compare `sourceIPAddress` manually or via `iplocation` + CIDR overlap. IP outside all approved ranges = escalate.

**3d. Is this bucket a CloudTrail log bucket?**
```spl
| inputlookup cloudtrail_log_buckets.csv
| search bucket_name="<requestParameters.bucketName>"
```
A match here elevates severity — deletion of CloudTrail logs is a secondary indicator of T1485/T1562 combo.

**3e. Is the actor a privileged user?**
```spl
| inputlookup privileged_iam_users.csv
| search username="<userIdentity.userName or sessionName>"
```

---

## 4. Determine Urgency

Answer each question and record your answer:

- [ ] Were more than 200 objects deleted? → **Escalate immediately**
- [ ] Is the bucket a CloudTrail log bucket, backup bucket, or DR bucket? → **Escalate immediately**
- [ ] Is the actor `Root` or a privileged IAM user not in `approved_iam_principals.csv`? → **Escalate immediately**
- [ ] Is `sourceIPAddress` outside all approved CIDR ranges and not an AWS service principal? → **Escalate immediately**
- [ ] Is `requestParameters.delete.quiet` = `true`? → **High confidence attack indicator — escalate**
- [ ] Did the same principal perform reconnaissance events (ListBuckets, GetBucketPolicy, ListObjectsV2) in the 30 minutes prior? → **Escalate immediately**

If none of the above are true, continue collecting context but do not yet escalate.

---

## 5. Quick Scope Check (< 2 minutes)

```bash
# Count total objects deleted in the triggering window
aws s3api list-object-versions \
  --bucket <bucket-name> \
  --query "DeleteMarkers[?LastModified>='<window-start>'].{Key:Key,DeletedAt:LastModified}" \
  --output table
```

Note: Use `--profile` or environment credentials configured via `aws configure`. Never hardcode credentials.

---

## 6. PASS / FAIL Criteria

### REAL ALERT (escalate and move to investigation.md)
- Principal is NOT in `approved_iam_principals.csv`, OR
- `sourceIPAddress` is outside approved CIDRs and is not an AWS service endpoint, OR
- Bucket is a log/backup bucket, OR
- `quiet=true` in delete request, OR
- Preceded by enumeration activity from the same principal, OR
- Object count deleted exceeds 200 in a single API call batch.

### BENIGN FALSE POSITIVE (close with documentation)
- Principal matches a known pipeline role in `approved_iam_principals.csv` with `purpose=lifecycle_cleanup` or similar.
- Activity matches a known scheduled job (confirm with bucket owner or ops team — do not assume).
- All deleted keys match a documented data-retention policy prefix (e.g., `tmp/`, `staging/`, `cache/`).
- Object count is low (< 50) and all keys share the same prefix consistent with a cleanup task.

**Even on a likely FP, document:** actor ARN, bucket name, object count, deletion timestamps, and your conclusion in the ticket before closing.

---

## 7. Escalation

- **Immediate escalation path:** SOC Lead → Cloud Security Engineer on-call
- **Ticket fields to populate before handing off:** `userIdentity.arn`, bucket name, object count, `sourceIPAddress`, preliminary FP/TP assessment, links to Splunk search results.
- **Next step if TP confirmed:** Proceed to `investigation.md`.
