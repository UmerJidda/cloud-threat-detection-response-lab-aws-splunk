---
detection_id: CDET-014
detection_name: CloudTrail Log File Deleted
tactic: Defense Evasion
technique: T1070.004
last_updated: 2026-06-18
---

# CDET-014 — CloudTrail Log File Deleted: Triage

**Time budget: 5–10 minutes**

This checklist determines whether the CDET-014 alert represents a genuine attempt to destroy CloudTrail evidence (defense evasion), or a benign/FP event from an approved pipeline, lifecycle policy, or test environment. Work through every step before escalating — but if step 3 confirms an unapproved principal deleted production log objects, escalate immediately without waiting to finish the checklist.

---

## 1. Locate and Open the Alert

1. Open the Splunk alert or SIEM ticket for CDET-014.
2. Confirm the raw event contains **all** of the following:
   - `eventName = "DeleteObject"` (or `DeleteObjects` for a batch delete)
   - `eventSource = "s3.amazonaws.com"`
   - `requestParameters.key` beginning with `AWSLogs/`
3. If the key prefix does not start with `AWSLogs/`, flag as **misfire** and close.
4. If `eventName` is something other than `DeleteObject` or `DeleteObjects`, flag as **misfire** and close.

---

## 2. Extract Key Fields from the Alert

Record these fields before proceeding — every subsequent step references them:

| Field | Where to Find It | Notes |
|---|---|---|
| `eventName` | CloudTrail event | `DeleteObject` or `DeleteObjects` |
| `eventTime` | CloudTrail event | ISO-8601 timestamp |
| `userIdentity.arn` | CloudTrail event | Full principal ARN performing the delete |
| `userIdentity.type` | CloudTrail event | `IAMUser`, `AssumedRole`, `Root`, `AWSService` |
| `userIdentity.sessionContext.sessionIssuer.arn` | CloudTrail event | Role ARN if `AssumedRole` |
| `requestParameters.bucketName` | CloudTrail event | The target S3 bucket |
| `requestParameters.key` | CloudTrail event | Full object key (should start with `AWSLogs/`) |
| `sourceIPAddress` | CloudTrail event | IP address or AWS service name |
| `userAgent` | CloudTrail event | CLI, console, SDK, or service identifier |
| `awsRegion` | CloudTrail event | Region of the S3 API call |
| `recipientAccountId` | CloudTrail event | AWS account where the bucket lives |

---

## 3. Check Lookup CSVs for Known-Good Actors

Run these Splunk lookups. A match is **not** automatic clearance — verify intent and confirm the specific object key and bucket are expected.

**Is the bucket a known CloudTrail log bucket?**
```spl
| inputlookup cloudtrail_log_buckets.csv
| where bucket_name="<requestParameters.bucketName from alert>"
```
File: `splunk/lookups/cloudtrail_log_buckets.csv`
- FAIL if the bucket is listed as a CloudTrail log bucket and the actor is not an approved service.

**Is the principal an approved IAM actor?**
```spl
| inputlookup approved_iam_principals.csv
| where principal_arn="<userIdentity.arn from alert>"
```
File: `splunk/lookups/approved_iam_principals.csv`

**Is the principal an approved automation/pipeline role?**
```spl
| inputlookup automation_role_arns.csv
| where role_arn="<sessionIssuer.arn from alert>"
```
File: `splunk/lookups/automation_role_arns.csv`

**Is this from an approved AWS account?**
```spl
| inputlookup approved_aws_accounts.csv
| where account_id="<recipientAccountId from alert>"
```
File: `splunk/lookups/approved_aws_accounts.csv`

---

## 4. Validate the Alert Is Real (Not Test Data or Pipeline)

Answer each question. A single **FAIL** answer moves you to escalation.

### 4a. Is the source IP or user agent expected?

- Check `sourceIPAddress`: is it an internal corporate range (see `splunk/lookups/approved_cidr_ranges.csv`), a known CI/CD NAT gateway, or an unexpected external IP?
- If `userAgent` matches `s3.amazonaws.com` or `elasticmapreduce.amazonaws.com`, investigate whether an AWS-managed service had a legitimate reason to delete log objects (rare but possible for lifecycle rules executed by the service itself — however, lifecycle rules show as `s3.amazonaws.com` with no `userIdentity` principal, so distinguish carefully).

```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("DeleteObject","DeleteObjects")
  requestParameters.bucketName="<bucket>"
  requestParameters.key="AWSLogs/*"
| table _time, userIdentity.arn, userIdentity.type, sourceIPAddress, userAgent,
        requestParameters.key, recipientAccountId
| sort -_time
| head 20
```

### 4b. Is this consistent with an S3 Lifecycle expiration policy?

S3 Object Lifecycle expirations are executed by the S3 service itself and will appear in CloudTrail with `userIdentity.type = "AWSService"` and `invokedBy = "s3.amazonaws.com"`. Confirm:

```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName="DeleteObject"
  requestParameters.bucketName="<bucket>"
| eval lifecycle=if(userIdentity.type="AWSService" AND userIdentity.invokedBy="s3.amazonaws.com","yes","no")
| table _time, lifecycle, requestParameters.key, userIdentity.type
```

- If `lifecycle = yes` and the key age is consistent with the bucket's configured lifecycle rule, this is **likely benign**. Verify the lifecycle rule exists in AWS console/CLI before closing.
- If `lifecycle = no` and the actor is an IAM principal — continue.

### 4c. Is this a known test environment?

- Check `recipientAccountId` against `splunk/lookups/approved_aws_accounts.csv` for accounts tagged as `env=dev` or `env=test`.
- If the bucket name contains `test`, `dev`, `sandbox`, or `staging`, document it and lower urgency — but still verify the actor is expected.

### 4d. Were multiple log files deleted?

- A single `DeleteObject` call against one stale log object is lower risk than `DeleteObjects` deleting dozens of objects in a short window.
- Run a count across the last 30 minutes:

```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("DeleteObject","DeleteObjects")
  requestParameters.bucketName="<bucket>"
  requestParameters.key="AWSLogs/*"
  userIdentity.arn="<principal_arn>"
| bucket _time span=30m
| stats count AS delete_count BY _time, userIdentity.arn
```

- More than 5 deletions in 30 minutes from a non-lifecycle actor: **FAIL — escalate immediately**.

### 4e. Did the S3 bucket have versioning or MFA Delete enabled?

```bash
aws s3api get-bucket-versioning \
  --bucket <bucket_name>
```

- If versioning is `Enabled` and the `DeleteObject` call did **not** include a `versionId`, S3 inserts a delete marker rather than permanently destroying the object. This is **recoverable** — lower the urgency but still investigate the actor.
- If the call included a specific `versionId`, the object is **permanently deleted** — treat as critical regardless of other factors.
- If versioning is `Suspended` or `Disabled`, all deletes are permanent — treat as critical.

---

## 5. PASS / FAIL Criteria

### PASS — Benign / FP (close or downgrade)

All of the following must be true:

- [ ] `userIdentity.type = "AWSService"` with `invokedBy = "s3.amazonaws.com"` (lifecycle expiration), **OR** the principal is in `automation_role_arns.csv` with a documented log-rotation responsibility.
- [ ] The bucket is not the sole/primary CloudTrail delivery bucket — or the bucket has versioning enabled and delete markers were inserted (not permanent deletion).
- [ ] The volume of deletions is consistent with normal lifecycle/rotation cadence (not a sudden spike).
- [ ] `sourceIPAddress` and `userAgent` are consistent with the expected actor.

Document the FP reason in the ticket and add a suppression note referencing the automation role ARN or lifecycle rule ID.

### FAIL — Real Alert (escalate)

Any of the following is sufficient to escalate:

- [ ] An IAM user or assumed role that is **not** in approved lookup CSVs performed the delete.
- [ ] `Root` account performed the delete.
- [ ] The delete includes a specific `versionId` (permanent removal of a versioned object).
- [ ] Bucket versioning is disabled and the bucket is the primary CloudTrail delivery bucket.
- [ ] More than 5 log objects deleted in 30 minutes by a non-lifecycle actor.
- [ ] Source IP is an unknown external address.
- [ ] The deletion closely follows other defense-evasion events (e.g., CDET-003 CloudTrail logging disabled, CDET-005 trust policy modified).

---

## 6. Escalation Decision

| Outcome | Action |
|---|---|
| PASS | Document findings, close or downgrade, tag `fp:lifecycle` or `fp:automation`. |
| FAIL — single deletion, versioned bucket, internal actor | Open P2 incident, move to investigation. |
| FAIL — mass deletion OR unversioned bucket OR external IP | Open P1 incident, page on-call IR lead immediately, move to investigation. |

Attach the raw CloudTrail JSON event and your triage notes to the incident ticket before handing off to investigation.
