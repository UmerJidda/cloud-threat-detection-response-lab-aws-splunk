---
detection_id: CDET-003
detection_name: CloudTrail Logging Disabled
tactic: Defense Evasion
technique: T1562.008
last_updated: 2026-06-18
---

# CDET-003 — CloudTrail Logging Disabled: Recovery

**Prerequisite:** Containment actions are complete. Compromised principal is isolated. CloudTrail logging has been re-enabled (verified). Incident ticket is open with full evidence attached.

---

## 1. Restore Normal Operations

### 1a. Verify CloudTrail is delivering logs to S3

Logs typically appear in S3 within 15 minutes of re-enabling. Confirm delivery:

```bash
aws cloudtrail get-trail-status \
  --name "<trail_name_or_arn>" \
  --region "<home_region>" \
  --query "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}"
```

Expected: `"IsLogging": true` and `LatestDeliveryTime` within the last 20 minutes.

Check the S3 bucket directly for new log files:
```bash
aws s3 ls \
  "s3://<log_bucket>/AWSLogs/<account_id>/CloudTrail/<region>/$(date -u +%Y/%m/%d)/" \
  --recursive \
  | tail -20
```

### 1b. Verify log file integrity validation is active

```bash
aws cloudtrail get-trail \
  --name "<trail_name_or_arn>" \
  --query "Trail.LogFileValidationEnabled"
```

Expected: `true`. If false:
```bash
aws cloudtrail update-trail \
  --name "<trail_name_or_arn>" \
  --enable-log-file-validation
```

### 1c. Verify all intended regions are covered

If the trail is multi-region, confirm the home region and confirm shadow trails are active in all target regions:
```bash
aws cloudtrail describe-trails \
  --include-shadow-trails \
  --query "trailList[?Name=='<trail_name>'].{Region:HomeRegion,MultiRegion:IsMultiRegionTrail,Logging:HasCustomEventSelectors}"
```

### 1d. Confirm Splunk is receiving new CloudTrail events

```spl
index=aws_cloudtrail
| stats max(_time) as latest_event
| eval age_minutes=round((now()-latest_event)/60,1)
| table age_minutes
```

If `age_minutes` is above 30, investigate the Splunk HEC/S3 ingestion pipeline — the trail may be delivering to S3 but Splunk may not be reading the new objects.

### 1e. Restore the compromised principal (if FP or after full remediation)

Only perform this step after the IR lead has signed off that the threat is fully contained.

For a legitimate service principal that was isolated:
1. Remove the `CDET003-Incident-DenyAll` inline policy (see `containment.md` rollback steps).
2. Issue a new access key and deliver it securely to the workload owner.
3. Disable and delete the old compromised key.
4. Update secrets management (Secrets Manager, Parameter Store) with the new key.

```bash
# Issue new key
aws iam create-access-key --user-name "<username>"

# Delete old key (now safe — forensics are complete)
aws iam delete-access-key \
  --user-name "<username>" \
  --access-key-id "<old_key_id>"
```

---

## 2. Verify the Threat Has Been Fully Removed

### 2a. Confirm no active sessions remain for the compromised principal

```bash
# For a role — verify the revocation policy timestamp is still in place
aws iam get-role-policy \
  --role-name "<role_name>" \
  --policy-name "AWSRevokeOlderSessions"
```

Run a final Splunk query to check for any new activity from the compromised principal after containment time:

```spl
index=aws_cloudtrail
  userIdentity.arn="<principal_arn>"
| where _time > "<containment_timestamp>"
| table _time, eventName, sourceIPAddress, userAgent
| sort _time
```

Expected: zero results, or results only from your own IR actions.

### 2b. Check for persistence mechanisms planted during the blind window

Review findings from investigation query 3h for any of the following that require additional remediation:

- New IAM users or access keys: enumerate and remove if unauthorized.
- New IAM roles with external trust: identify and delete.
- Modified S3 bucket policies: revert to approved state.
- New EC2 instances or Lambda functions: review and terminate/delete if unauthorized.
- Modified security groups: revert to approved state using `splunk/lookups/approved_cidr_ranges.csv` as reference.
- New or modified SNS/SQS subscriptions: review for exfiltration channels.

For each unauthorized resource found, create a child ticket linked to this incident before removing it.

### 2c. Validate GuardDuty and Security Hub findings are cleared

```bash
aws guardduty list-findings \
  --detector-id "<detector_id>" \
  --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}' \
  --query "FindingIds"
```

Review any unarchived findings related to the incident timeframe and either archive (resolved) or investigate further.

---

## 3. Hardening — Prevent Recurrence

### 3a. Apply an SCP to prevent CloudTrail disablement

**[APPROVAL REQUIRED — Cloud Platform Team]**

Attach a Service Control Policy at the AWS Organizations level to prevent any principal (except a designated break-glass role) from calling `StopLogging` or `DeleteTrail`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudTrailDisablement",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/BreakGlassAdmin",
            "arn:aws:iam::*:role/SecurityIncidentResponse"
          ]
        }
      }
    }
  ]
}
```

Apply via AWS CLI (Organizations management account required):
```bash
aws organizations create-policy \
  --name "DenyCloudTrailDisablement" \
  --type SERVICE_CONTROL_POLICY \
  --description "Prevent disablement or deletion of CloudTrail trails (CDET-003)" \
  --content file:///tmp/scp-deny-cloudtrail-disable.json
```

### 3b. Enable CloudTrail log file validation (if not already enabled)

Validated log files allow detection of log tampering between delivery and analysis. Already covered in 1b above — confirm it is applied to all trails.

### 3c. Restrict the S3 log bucket

Ensure the CloudTrail S3 bucket has:
- **S3 Object Lock** (COMPLIANCE mode, minimum 90-day retention) to prevent deletion of existing logs.
- **Bucket policy** denying `s3:DeleteObject` and `s3:DeleteBucket` for all principals except the designated retention management role.
- **MFA delete** enabled.

```bash
aws s3api put-bucket-versioning \
  --bucket "<log_bucket>" \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "<mfa_serial> <mfa_code>"
```

### 3d. Enable CloudWatch Alarms on CloudTrail metric filters

If not already in place, create a metric filter and alarm that fires immediately on `StopLogging` or `DeleteTrail` — separate from the Splunk detection, as a defense-in-depth layer:

```bash
aws logs put-metric-filter \
  --log-group-name "<cloudtrail_log_group>" \
  --filter-name "CloudTrailDisablement" \
  --filter-pattern '{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) }' \
  --metric-transformations \
      metricName=CloudTrailDisablementCount,metricNamespace=CISBenchmark,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name "CDET003-CloudTrailDisablement" \
  --metric-name CloudTrailDisablementCount \
  --namespace CISBenchmark \
  --statistic Sum \
  --period 60 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "<sns_topic_arn>"
```

### 3e. Enforce least-privilege on CloudTrail management permissions

Audit all IAM policies granting `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail`. Remove these permissions from any role that does not require them. Roles that do require them should be tightly scoped and monitored.

```bash
aws iam get-account-authorization-details \
  --filter "LocalManagedPolicy" "AWSManagedPolicy" \
  --query "Policies[*].PolicyVersionList[*].Document.Statement[?contains(Action,'cloudtrail:StopLogging')]"
```

---

## 4. Detection Tuning Recommendations

### 4a. Suppression — reduce FP noise from known pipelines

If the investigation confirmed a specific automation role or CI/CD pipeline legitimately calls `StopLogging` (e.g., during Terraform `destroy` in non-production accounts), add a suppression rule rather than whitelisting globally:

- Add the role ARN to `splunk/lookups/automation_role_arns.csv`.
- Add a Splunk suppression scoped to that role ARN **AND** the specific non-production account ID from `splunk/lookups/approved_aws_accounts.csv`.
- Do not suppress `DeleteTrail` — this should always alert.

### 4b. Enrichment — improve triage speed

Add the following fields to the CDET-003 Splunk alert output to reduce triage time:

- `lookup automation_role_arns.csv role_arn AS userIdentity.sessionContext.sessionIssuer.arn OUTPUT is_automation`
- `lookup approved_iam_principals.csv principal_arn AS userIdentity.arn OUTPUT is_approved`
- `lookup approved_aws_accounts.csv account_id AS recipientAccountId OUTPUT account_name`

### 4c. Correlate with CDET-014

CDET-003 (logging disabled) frequently precedes CDET-014 (CloudTrail log deleted from S3). Ensure your SIEM correlates these two detections by principal and account within a 60-minute window, and escalates automatically to CRITICAL if both fire together.

---

## 5. Post-Incident Review Checklist

Complete this checklist within 5 business days of incident closure and attach the completed form to the incident ticket.

- [ ] Root cause identified and documented (how the attacker obtained the permission to disable CloudTrail).
- [ ] Full timeline reconstructed and reviewed with the IR team.
- [ ] Blind window assessed — were any unauthorized actions taken while logging was disabled? If yes, list them as sub-incidents.
- [ ] All containment actions documented with approver names and timestamps.
- [ ] All compromised credentials rotated and old credentials deleted.
- [ ] SCP / preventive controls implemented and tested (Step 3a).
- [ ] S3 Object Lock and MFA delete confirmed on log bucket (Step 3c).
- [ ] CloudWatch alarm for CloudTrail disablement deployed (Step 3d).
- [ ] Detection tuning changes applied (Step 4) and reviewed with detection engineering.
- [ ] Lessons learned shared with the broader security team.
- [ ] Incident ticket formally closed with final severity, duration, and impact recorded.
- [ ] If a third-party service was compromised, notify the vendor and assess contractual obligations.
- [ ] Consider regulatory notification requirements (e.g., GDPR 72-hour rule) if PII was potentially exposed during the blind window.
