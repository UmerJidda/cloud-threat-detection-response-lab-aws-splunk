---
detection_id: CDET-010
detection_name: Mass S3 Object Deletion
tactic: Impact
technique: T1485
last_updated: 2026-06-18
---

# CDET-010 — Mass S3 Object Deletion: Recovery Playbook

**Audience:** Tier-2 SOC Analyst (coordinate with Cloud Engineer for data restoration steps)  
**Prerequisites:** Containment complete. Actor access revoked. No further deletions occurring.  
**Goal:** Restore normal operations safely, verify the threat is gone, harden against recurrence, and tune the detection.

---

## 1. Verify the Threat Has Been Fully Removed

Before restoring data or re-opening access, confirm the attacker has no remaining foothold.

**1a. Check for other active access keys on the compromised user**
```bash
aws iam list-access-keys --user-name <username>
# Ensure all keys are Inactive or only the re-authorized key is Active
```

**1b. Check for new IAM users, roles, or keys created by the attacker during the incident window**
```bash
# New IAM users created in incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time <incident_start_ISO8601> \
  --end-time <now_ISO8601> \
  --query "Events[*].{Time:EventTime,User:Username,Event:CloudTrailEvent}" \
  --output table

# New access keys created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time <incident_start_ISO8601> \
  --end-time <now_ISO8601> \
  --output table

# New roles created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time <incident_start_ISO8601> \
  --end-time <now_ISO8601> \
  --output table
```

**1c. Check for unauthorized bucket policy or ACL changes that may have created a backdoor**
```bash
aws s3api get-bucket-policy --bucket <bucket-name> --query Policy --output text | python -m json.tool
aws s3api get-bucket-acl --bucket <bucket-name>
# Verify no unexpected external principal has been granted access
```

**1d. Check for unauthorized replication (attacker may have re-added it)**
```bash
aws s3api get-bucket-replication --bucket <bucket-name> 2>/dev/null || echo "No replication configured"
```

**1e. Run a final Splunk check for any post-containment activity by the actor**
```spl
index=aws_cloudtrail userIdentity.arn="<compromised_ARN>"
  earliest=<containment_timestamp>
| table eventTime, eventName, sourceIPAddress, requestParameters, errorCode
| sort eventTime
```
If any events appear after containment, the session revocation did not fully work — re-execute `containment.md` step Priority 1c with an updated timestamp.

---

## 2. Data Restoration

Restoration options depend on the bucket's versioning state at time of deletion.

**2a. If versioning was ENABLED at time of deletion (delete markers placed, versions intact)**

Objects are recoverable by removing delete markers:
```bash
# List all delete markers created during the incident window
aws s3api list-object-versions \
  --bucket <bucket-name> \
  --query "DeleteMarkers[?LastModified>='<incident_start>'].[Key,VersionId]" \
  --output text > /tmp/CDET-010-delete-markers.txt

# Remove delete markers to restore objects (run for each Key/VersionId pair)
# For large-scale recovery, use a script:
while IFS=$'\t' read -r key versionid; do
  aws s3api delete-object \
    --bucket "<bucket-name>" \
    --key "$key" \
    --version-id "$versionid"
done < /tmp/CDET-010-delete-markers.txt
```
Verify restoration:
```bash
aws s3api list-objects-v2 --bucket <bucket-name> --query "Contents[*].{Key:Key,Size:Size}" --output table
```

**2b. If versioning was DISABLED or the attacker also deleted all versions**

Data cannot be restored from S3 itself. Escalate to the application/data team immediately for:
- AWS Backup recovery (if S3 Backup plans were configured)
- Cross-region replication replica (if replication was set up before the attack and the replica was not destroyed)
- Application-level backups (database dumps, CI/CD artifacts, etc.)
- AWS Support — in some cases, AWS may be able to assist if the bucket itself still exists

```bash
# Check if AWS Backup has recovery points for this bucket
aws backup list-recovery-points-by-resource \
  --resource-arn arn:aws:s3:::<bucket-name> \
  --query "RecoveryPoints[*].{RecoveryPointArn:RecoveryPointArn,CreationDate:CreationDate,Status:Status}" \
  --output table
```

**2c. Restore bucket configuration to pre-incident state**
```bash
# Restore versioning (if it was active before the incident)
aws s3api put-bucket-versioning \
  --bucket <bucket-name> \
  --versioning-configuration Status=Enabled

# Restore lifecycle configuration from your backup/IaC source of truth (Terraform, CloudFormation)
# Do NOT re-apply any lifecycle configuration that was placed by the attacker

# Restore original bucket policy (from the evidence copy saved during containment)
aws s3api put-bucket-policy \
  --bucket <bucket-name> \
  --policy file:///tmp/CDET-010-original-bucket-policy-<bucket-name>.json
```

---

## 3. Re-enable Authorized Access

Only after steps 1 and 2 are confirmed complete:

1. Create a new IAM user or rotate the access key (do not re-activate the original compromised key for production use):
   ```bash
   aws iam create-access-key --user-name <username>
   # Distribute new credentials via your secrets management system (Secrets Manager, SSM Parameter Store)
   # Never send credentials via email or chat
   ```

2. Re-attach policies using your IaC pipeline — do not hand-craft policy documents from memory.

3. Remove the incident containment bucket policy (the deny-delete policy applied in `containment.md`):
   ```bash
   # If the original policy was empty before the incident:
   aws s3api delete-bucket-policy --bucket <bucket-name>

   # If the original policy had legitimate statements, restore from the saved copy:
   aws s3api put-bucket-policy \
     --bucket <bucket-name> \
     --policy file:///tmp/CDET-010-original-bucket-policy-<bucket-name>.json
   ```

4. Notify the application team to validate application functionality and confirm data integrity.

---

## 4. Hardening Steps to Prevent Recurrence

Implement these controls as tickets or IaC PRs — document them in the incident ticket as action items.

**4a. Enable S3 Versioning on all critical buckets**
- Priority: Any bucket containing logs, backups, customer data, or application artifacts.
- IaC: `aws_s3_bucket_versioning` resource in Terraform / `BucketVersioningConfiguration` in CloudFormation.

**4b. Enable S3 Object Lock (WORM) on immutable data buckets**
- Required for CloudTrail log buckets — also recommended for DR/backup buckets.
- Must be enabled at bucket creation; existing buckets require AWS Support ticket.

**4c. Enforce MFA Delete on versioned buckets containing critical data**
```bash
# Requires root credentials — escalate to Cloud Security Engineer
aws s3api put-bucket-versioning \
  --bucket <bucket-name> \
  --versioning-configuration '{"MFADelete":"Enabled","Status":"Enabled"}' \
  --mfa "arn:aws:iam::<account>:mfa/root-account-mfa-device <TOTP-code>"
```

**4d. Apply least-privilege IAM policies — remove `s3:DeleteObject` and `s3:DeleteObjectVersion` from all non-administrative roles**
```bash
# Audit which principals have delete permissions on the affected bucket
aws iam simulate-principal-policy \
  --policy-source-arn <role-or-user-arn> \
  --action-names s3:DeleteObject s3:DeleteObjectVersion \
  --resource-arns arn:aws:s3:::<bucket-name>/*
```

**4e. Enable S3 Server Access Logging on all buckets that do not already have it**
```bash
aws s3api put-bucket-logging \
  --bucket <bucket-name> \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "<log-destination-bucket>",
      "TargetPrefix": "s3-access-logs/<bucket-name>/"
    }
  }'
```

**4f. Implement AWS Config rules to detect and alert on versioning being disabled**
- Managed rule: `s3-bucket-versioning-enabled`
- Alert action: SNS → SOC notification

**4g. Review and restrict `s3:PutBucketVersioning` permission**
- Only infrastructure pipeline roles should be able to change versioning — not application roles.

**4h. Tag buckets with data classification and owner**
- Enables automated policy enforcement and faster blast radius assessment in future incidents.

---

## 5. Detection Tuning Recommendations

**5a. Suppression — add to `approved_iam_principals.csv` if appropriate**

If the alert triggered on a legitimate pipeline role that was not previously in the lookup:
- Validate the role's purpose with the owning team.
- Add it to `splunk/lookups/approved_iam_principals.csv` with `purpose`, `owner`, and `review_date` fields.
- Add a note in the incident ticket explaining why this was a FP and what was added to the lookup.

Do NOT suppress based on bucket name alone — future incidents could use the same bucket.

**5b. Enrichment improvements**

Consider enriching CDET-010 alerts with:
- A join against a bucket criticality/classification lookup (create `s3_bucket_inventory.csv` if it does not exist).
- The `requestParameters.delete.quiet` field as a high-severity modifier — add a `| eval severity=if(quiet="true","critical","high")` branch to the detection query.
- A lookup against `cloudtrail_log_buckets.csv` in the alert itself so the subject line includes `[LOG BUCKET TARGETED]` when relevant.

**5c. Lower the threshold for high-value buckets**

The default threshold of 50 objects in 10 minutes is appropriate for general buckets. For buckets tagged as `data_classification=critical` or in `cloudtrail_log_buckets.csv`, consider a threshold of 10 objects or even a single `DeleteObjects` call.

**5d. Add a companion detection for versioning disable events**

A `PutBucketVersioning` event setting `Status=Suspended` on a critical bucket should trigger its own alert. Pair with CDET-010 correlation logic to automatically elevate severity if both fire within 1 hour.

---

## 6. Post-Incident Review Checklist

Complete within 5 business days of incident closure:

- [ ] Incident timeline documented from initial access (T0) through containment completion
- [ ] Root cause identified: How was the credential compromised? (phishing, key exposure in code, IMDS abuse, etc.)
- [ ] Blast radius confirmed: Total objects deleted, recovery status (full/partial/none), data classification
- [ ] All evidence preserved in incident ticket or designated evidence bucket with immutable policy
- [ ] Legal / compliance notified if PII, PHI, or PCI data was destroyed
- [ ] Hardening action items created as tracked tickets with owners and due dates
- [ ] Detection tuning changes (suppression/enrichment) implemented and tested
- [ ] Incident response playbooks (this set) reviewed for gaps and updated if needed
- [ ] CDET-010 alert re-fired against historical data post-tuning to confirm no new FP rate increase
- [ ] Lessons learned shared with broader security team (blameless postmortem format)
- [ ] Confirmed that `approved_iam_principals.csv`, `cloudtrail_log_buckets.csv`, and other lookups are up to date

**Incident closed when:** All checklist items above are complete, the compromised credential is permanently decommissioned, and no residual attacker access has been detected for a minimum of 72 hours post-containment.
