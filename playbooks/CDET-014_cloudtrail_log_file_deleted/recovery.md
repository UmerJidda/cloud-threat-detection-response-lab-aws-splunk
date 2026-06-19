---
detection_id: CDET-014
detection_name: CloudTrail Log File Deleted
tactic: Defense Evasion
technique: T1070.004
last_updated: 2026-06-18
---

# CDET-014 — CloudTrail Log File Deleted: Recovery

**Prerequisite:** CDET-014 containment is complete. The compromised credential has been revoked. The log bucket has been secured. An incident ticket with the full investigation record is open.

---

## 1. Restore Deleted Log Objects (If Possible)

### 1a. Remove delete markers to restore versioned objects

If the bucket had versioning enabled and the `DeleteObject` call did not include a `versionId`, S3 inserted a delete marker rather than destroying the object. Removing the delete marker restores the original object.

```bash
# List all delete markers under AWSLogs/ that were created during the incident window
aws s3api list-object-versions \
  --bucket <bucket_name> \
  --prefix "AWSLogs/" \
  --query "DeleteMarkers[?LastModified>='<incident_start_time>'].[Key,VersionId]" \
  --output json

# For each Key + VersionId pair (delete marker), remove the marker to restore the object
aws s3api delete-object \
  --bucket <bucket_name> \
  --key "<object_key>" \
  --version-id "<delete_marker_version_id>"
```

Verify the object is restored:

```bash
aws s3api head-object \
  --bucket <bucket_name> \
  --key "<object_key>"
```

Repeat for each delete marker from the incident window. For large batches, script this loop over the JSON output from `list-object-versions`.

### 1b. Permanent deletion — explore alternative sources

If versioning was disabled or the attacker specified a `versionId` in the delete call, the objects are permanently gone from S3. Attempt recovery from alternative log sources:

1. **AWS CloudTrail Lake** — if the account has an event data store configured, query it for the gap window:

   ```bash
   aws cloudtrail start-query \
     --query-statement "SELECT * FROM <event_data_store_id>
       WHERE eventTime >= '<gap_start>' AND eventTime <= '<gap_end>'
       AND awsRegion = '<region>'"
   ```

2. **Secondary CloudTrail trail** — if a multi-region trail delivers to a different bucket, retrieve log files from that bucket for the gap window.

3. **SIEM historical index** — if Splunk or another SIEM was indexing CloudTrail events in real time before the deletion, the events may already be in the SIEM. The log gap in S3 does not necessarily mean the events were never ingested.

4. **AWS Config history** — resource configuration change events are independent of CloudTrail and may corroborate activity during the gap.

5. **VPC Flow Logs and DNS query logs** — network-layer evidence survives the log deletion and can help reconstruct attacker activity.

Document in the incident ticket which gap windows remain unrecoverable after exhausting all sources.

---

## 2. Verify CloudTrail is Healthy and Delivering Logs

2.1. Confirm the trail is logging:

```bash
aws cloudtrail get-trail-status \
  --name <trail_name_or_arn>
```

Check that:
- `IsLogging` is `true`
- `LatestDeliveryTime` is recent (within the last 15 minutes for active accounts)
- `LatestDeliveryError` is null or empty
- `LatestNotificationError` is null or empty

2.2. Verify log file delivery manually by listing recent objects:

```bash
aws s3api list-objects-v2 \
  --bucket <bucket_name> \
  --prefix "AWSLogs/<account_id>/CloudTrail/<region>/$(date +%Y/%m/%d)/" \
  --query "Contents[*].[Key,LastModified]" \
  --output table
```

New log files should appear within 15 minutes of the check.

2.3. Validate log file integrity using CloudTrail log file validation:

```bash
aws cloudtrail validate-logs \
  --trail-arn <trail_arn> \
  --start-time <gap_end_time> \
  --verbose
```

A successful validation confirms the hash chain is intact for all logs after the gap window.

---

## 3. Verify the Threat Has Been Fully Removed

3.1. Confirm no active sessions exist for the compromised credential:

```bash
# For an IAM role — verify the revocation policy is in effect
aws iam get-role-policy \
  --role-name <role_name> \
  --policy-name CDET014-EmergencyRevoke

# For an IAM user access key — confirm the key is inactive
aws iam list-access-keys \
  --user-name <username> \
  --query "AccessKeyMetadata[?AccessKeyId=='<keyId>'].Status"
```

3.2. Confirm no new suspicious DeleteObject events have occurred since containment:

```spl
index=aws_cloudtrail eventSource="s3.amazonaws.com"
  eventName IN ("DeleteObject","DeleteObjects")
  requestParameters.bucketName="<bucket_name>"
  requestParameters.key="AWSLogs/*"
| where _time >= relative_time(now(),"-2h")
| table _time, userIdentity.arn, requestParameters.key, sourceIPAddress
```

3.3. Confirm no new access keys have been created for the compromised user/role since the incident:

```bash
aws iam list-access-keys \
  --user-name <username>
```

3.4. Check GuardDuty for any new findings related to the compromised principal since containment:

```bash
aws guardduty list-findings \
  --detector-id <detector_id> \
  --finding-criteria "{
    \"Criterion\": {
      \"resource.accessKeyDetails.accessKeyId\": {
        \"Eq\": [\"<access_key_id>\"]
      }
    }
  }"
```

---

## 4. Hardening Steps to Prevent Recurrence

Implement the following controls after the incident is resolved. Assign each item to a responsible team member with a due date.

### 4a. Enable S3 Versioning and MFA Delete on the CloudTrail log bucket

Versioning ensures that even if an attacker executes `DeleteObject`, a recoverable delete marker is inserted rather than permanent deletion. MFA Delete requires a second factor to remove versions.

```bash
# Enable versioning (if not already enabled)
aws s3api put-bucket-versioning \
  --bucket <bucket_name> \
  --versioning-configuration Status=Enabled

# Enable MFA Delete (requires the root account MFA device serial and code)
aws s3api put-bucket-versioning \
  --bucket <bucket_name> \
  --versioning-configuration "Status=Enabled,MFADelete=Enabled" \
  --mfa "<mfa_device_serial> <mfa_code>"
```

### 4b. Apply an S3 Object Lock retention policy

For new CloudTrail log buckets, enable Object Lock in Compliance mode to prevent any deletion during the retention period:

```bash
# Object Lock must be enabled at bucket creation — create a new bucket if needed
aws s3api create-bucket \
  --bucket <new_bucket_name> \
  --object-lock-enabled-for-bucket \
  --region <region>

aws s3api put-object-lock-configuration \
  --bucket <new_bucket_name> \
  --object-lock-configuration "{
    \"ObjectLockEnabled\": \"Enabled\",
    \"Rule\": {
      \"DefaultRetention\": {
        \"Mode\": \"GOVERNANCE\",
        \"Days\": 365
      }
    }
  }"
```

### 4c. Add an explicit bucket policy deny for DeleteObject on AWSLogs/

Apply the deny statement documented in `containment.md` (Step 3.2) permanently:

```bash
aws s3api put-bucket-policy \
  --bucket <bucket_name> \
  --policy file:///path/to/hardened_bucket_policy.json
```

Ensure the policy denies `s3:DeleteObject`, `s3:DeleteObjectVersion`, and `s3:DeleteObjects` for all principals except an approved lifecycle automation role.

### 4d. Enable AWS Config rules to monitor the CloudTrail log bucket

```bash
# Ensure the bucket is not publicly accessible
aws configservice put-config-rule \
  --config-rule "{
    \"ConfigRuleName\": \"s3-bucket-public-access-prohibited\",
    \"Source\": {
      \"Owner\": \"AWS\",
      \"SourceIdentifier\": \"S3_BUCKET_PUBLIC_ACCESS_PROHIBITED\"
    }
  }"
```

### 4e. Enable CloudTrail log file integrity validation

```bash
aws cloudtrail update-trail \
  --name <trail_name> \
  --enable-log-file-validation
```

Digest files allow you to detect tampering with log files even if an attacker modifies rather than deletes them.

### 4f. Review and minimize IAM permissions for all principals with S3 access to the log bucket

Audit all IAM principals that have `s3:DeleteObject` or `s3:*` on the CloudTrail log bucket. Apply least-privilege: CloudTrail itself needs only `s3:PutObject`; no human principals should have delete permissions on log buckets.

```bash
# Use IAM Access Analyzer to identify overly permissive policies
aws accessanalyzer start-resource-scan \
  --analyzer-arn <analyzer_arn> \
  --resource-arn "arn:aws:s3:::<bucket_name>"
```

---

## 5. Detection Tuning Recommendations

### 5a. Suppress confirmed benign patterns without removing the detection

Do **not** suppress CDET-014 globally. Instead, add enrichment to reduce FP noise:

- Add S3 lifecycle execution events (`userIdentity.type = AWSService`, `invokedBy = s3.amazonaws.com`) to the `automation_role_arns.csv` lookup with a `delete_reason = lifecycle` annotation.
- Add a Splunk lookup-based filter in the CDET-014 search to exclude `lifecycle` tagged actors from alerting while still logging them for audit.

```spl
| inputlookup automation_role_arns.csv
| where delete_reason="lifecycle"
| rename role_arn AS "userIdentity.sessionContext.sessionIssuer.arn"
```

### 5b. Add enrichment to increase signal fidelity

Enhance the CDET-014 Splunk detection to include:

- **Bucket classification**: join against `cloudtrail_log_buckets.csv` to flag deletes on known CloudTrail buckets as higher severity.
- **Version ID presence**: if `requestParameters.versionId` is populated, auto-escalate to P1.
- **Volume threshold**: if more than 5 log objects are deleted within 30 minutes, escalate severity automatically.
- **Correlated CDET-003**: if the same principal triggered CDET-003 within the past 24 hours, add a correlation tag to the CDET-014 alert.

### 5c. Create a new detection for reconnaissance precursors

If this incident revealed a pattern of `ListObjectsV2` or `GetBucketLogging` calls on the CloudTrail bucket before the deletion, consider creating a detection for reconnaissance against log buckets as a lower-severity leading indicator.

---

## 6. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Full incident timeline documented from first evidence of compromise to containment.
- [ ] Evidence gap window identified and documented: which log files are unrecoverable, what time range they cover, and what activity may have been concealed.
- [ ] Root cause identified: how did the attacker obtain `s3:DeleteObject` permissions on the CloudTrail log bucket?
- [ ] IAM policy remediation complete: the permission path that allowed the deletion has been closed.
- [ ] Bucket hardening actions (Steps 4a–4f) assigned, tracked, and completed.
- [ ] Detection tuning changes (Step 5) implemented and tested in Splunk.
- [ ] Lessons learned documented in the incident ticket and shared with the security team.
- [ ] Confirm whether any regulatory or compliance notification obligations apply given the evidence destruction (e.g., if the account is in scope for SOC 2, PCI DSS, or HIPAA).
- [ ] Confirm whether a secondary trail or CloudTrail Lake has been configured to reduce the impact of future log bucket attacks.
- [ ] Schedule a tabletop exercise to test the CDET-014 response playbook based on findings from this incident.
