# CDET-009 — S3 Bucket Replication Configured to External Account

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-009 |
| **Severity** | High |
| **Confidence** | High |
| **Tactic** | Exfiltration |
| **Technique** | T1537 — Transfer Data to Cloud Account |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 15 minutes |

## Detection Logic

S3 Cross-Region Replication (CRR) and Same-Region Replication (SRR) can be configured to automatically copy all new objects from a source bucket to a destination bucket in a different AWS account. An adversary with `s3:PutBucketReplication` access can silently configure this to forward all data written to a sensitive bucket to their own S3 bucket — indefinitely, until discovered.

The detection parses the `replicationConfiguration` JSON in the `PutBucketReplication` request parameters to extract the destination account ID. If the destination account is not in the `approved_aws_accounts` lookup, an alert is generated.

This is a high-confidence detection: `PutBucketReplication` with a cross-account destination has very few legitimate use cases outside documented DR and archival workflows.

## Example Alert Output

```
detection_id          : CDET-009
alert_title           : [CDET-009] S3 Bucket Replication Configured to External Account
severity              : high
bucket_name           : company-financial-data
destination_bucket_arn: arn:aws:s3:::attacker-exfil-bucket
destination_account_id: 999888777666
principal_arn         : arn:aws:iam::123456789012:user/compromised-developer
event_source_ip       : 203.0.113.99
region                : us-east-1
```

## Containment Guidance

1. Remove the replication configuration immediately:
   ```bash
   aws s3api delete-bucket-replication --bucket <bucket-name>
   ```
2. Determine how long the replication was active — check creation timestamp vs. current time
3. Enumerate all objects in the source bucket that were created after the replication was configured (these were exfiltrated)
4. Notify data owners of the affected bucket
5. Assess whether any data was covered by regulatory notification requirements
