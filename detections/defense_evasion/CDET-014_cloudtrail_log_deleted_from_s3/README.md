# CDET-014 — CloudTrail Log File Deleted from S3

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-014 |
| **Severity** | Critical |
| **Confidence** | High |
| **Tactic** | Defense Evasion |
| **Technique** | T1070.004 — Indicator Removal: File Deletion |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 5 minutes |

## Detection Logic

CloudTrail logs are the primary forensic evidence source in AWS. An attacker who successfully deletes CloudTrail logs from their S3 delivery bucket can prevent forensic reconstruction of their activity. This technique is the AWS equivalent of clearing Windows Event Log — a strong indicator that the attacker is attempting to cover their tracks.

This detection monitors all `DeleteObject`, `DeleteObjects`, and `DeleteBucket` events in S3 and cross-references the bucket name against the `cloudtrail_log_buckets.csv` lookup. It fires on any non-lifecycle deletion from a CloudTrail delivery bucket.

The detection intentionally avoids suppression — there are almost no legitimate operational reasons for a human principal to delete CloudTrail log files. All alerts should be treated as critical until proven otherwise.

### Deletion Type Classification

| Event | `deletion_type` | Urgency |
|-------|-----------------|---------|
| `DeleteBucket` | CRITICAL: Entire CloudTrail log bucket deleted | P0 |
| `DeleteObjects` | HIGH: Batch CloudTrail log deletion | P0 |
| `DeleteObject` | Single CloudTrail log file deleted | P0 |

## Required Lookup: `cloudtrail_log_buckets.csv`

This detection requires a lookup that maps all CloudTrail delivery bucket names. Populate it from the AWS Console (CloudTrail > Trails > S3 bucket column) or via AWS CLI:

```bash
aws cloudtrail describe-trails --query 'trailList[*].{bucket:S3BucketName,name:Name}'
```

```csv
bucket_name,is_cloudtrail_bucket,trail_name,date_added,added_by
my-org-cloudtrail-logs,true,management-events-trail,2024-01-15,security-team
my-org-cloudtrail-secondary,true,data-events-trail,2024-01-15,security-team
```

## Example Alert Output

```
detection_id          : CDET-014
severity              : critical
deletion_type         : CRITICAL: Entire CloudTrail log bucket deleted
eventName             : DeleteBucket
principal_arn         : arn:aws:iam::123456789012:user/attacker
bucket_name           : my-org-cloudtrail-logs
trail_name            : management-events-trail
object_key            : bucket-level-operation
estimated_logs_deleted: 1000
event_source_ip       : 198.51.100.88
region                : us-east-1
```

## Immediate Response

1. **Preserve what remains** — check if S3 Versioning was enabled on the CloudTrail bucket; if so, deleted objects can be recovered from delete markers
2. **Check CloudTrail integrity** — use `aws cloudtrail validate-logs` to identify the time window of missing logs
3. **Cross-reference other log sources** — VPC Flow Logs, ALB access logs, and GuardDuty findings may fill the gap
4. **Suspend the acting principal immediately**
5. **Notify legal/compliance** — evidence tampering has regulatory and legal implications
6. **Enable MFA Delete on CloudTrail S3 buckets** as a preventive control if not already enabled

## Preventive Controls

This detection is a last-resort signal. The following controls should prevent log deletion from succeeding:

- Enable **S3 Object Lock** (WORM mode) on CloudTrail delivery buckets
- Attach an **S3 bucket policy** denying `s3:DeleteObject` for all principals except the AWS Config/Security team role
- Enable **MFA Delete** on the bucket
- Route CloudTrail to **CloudWatch Logs** as a secondary, independent delivery target
