# CDET-010 — Mass S3 Object Deletion

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-010 |
| **Severity** | Critical |
| **Confidence** | High |
| **Tactic** | Impact |
| **Technique** | T1485 — Data Destruction |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 5 minutes |

## Detection Logic

Mass S3 deletion is a common ransomware and destruction technique in AWS environments. Attackers delete S3 objects either as the final stage of an exfiltrate-then-destroy attack, or as a standalone destructive action. S3 versioning can mitigate data loss only if `DeleteObject` does not also delete the version markers.

The detection aggregates `DeleteObject`, `DeleteObjects`, and `DeleteBucket` events by principal over a 10-minute window. It fires when:
- Estimated objects deleted ≥ 100, **OR**
- Delete API call count ≥ 20

The `DeleteObjects` API call is weighted higher because a single call can delete up to 1000 objects. `DeleteBucket` is treated as deleting 1000 objects (worst-case assumption).

AWS service-initiated deletions (`userIdentity.type=AWSService`) from S3 lifecycle policies are explicitly excluded.

## Example Alert Output

```
detection_id            : CDET-010
severity                : critical
destruction_scope       : severe — significant data volume affected
principal_arn           : arn:aws:iam::123456789012:user/ransomware-actor
total_delete_events     : 47
estimated_objects_deleted: 4700
buckets_targeted        : 3
bucket_names_str        : company-backups, financial-reports, customer-data
event_source_ip         : 198.51.100.99
region                  : us-east-1
```

## Immediate Response

1. **Suspend the acting principal immediately** — every minute of inaction means more deleted data
2. **Check S3 versioning** on affected buckets — if enabled, objects may be recoverable from delete markers
3. **Check S3 MFA Delete** — if enabled, delete markers can only be removed with MFA
4. **Enable versioning on any bucket not yet protected**
5. Notify data owners and legal/compliance based on data classification of affected buckets
