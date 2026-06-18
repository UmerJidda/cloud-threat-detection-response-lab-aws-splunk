# CDET-009 — S3 Replication to External Account

**Tactic:** Exfiltration  
**MITRE ATT&CK:** T1537 — Transfer Data to Cloud Account  
**Severity:** Critical  
**Data Source:** AWS CloudTrail

---

## Technique Overview

S3 Cross-Region and Cross-Account Replication is a legitimate AWS feature that continuously copies objects from a source bucket to a destination bucket. Attackers abuse this feature to establish a persistent, automated exfiltration channel that operates silently after a single configuration change. Unlike bulk download attacks, replication requires no ongoing attacker interaction — the victim's own AWS infrastructure performs the data transfer on the attacker's behalf.

---

## How S3 Replication Works (and Why It Is Dangerous)

AWS S3 Replication works via a replication configuration attached to the source bucket. Once configured:

1. Every new object written to the source bucket is automatically copied to the destination bucket.
2. The copy occurs asynchronously — within seconds to minutes for most objects.
3. The transfer uses AWS's internal network, not the public internet, making it invisible to network-level exfiltration detection.
4. The source objects are **not deleted** — this is a copy operation, not a move.
5. The replication continues indefinitely until the configuration is removed.

From an attacker's perspective, this is ideal: a single API call (`PutBucketReplication`) establishes a pipeline that will deliver all future data to an account they control, indefinitely, without any further action required.

---

## Evasion of Volume-Based Detection

Traditional data exfiltration detection measures data volume transferred — large S3 `GetObject` requests from an unusual IP address, or a spike in outbound bytes. S3 replication defeats this approach because:

- **Individual objects are not deleted**: Volume-based "data loss" metrics see no reduction in the source bucket.
- **No GetObject API calls occur**: The replication is performed by the AWS S3 service itself (principal: `s3.amazonaws.com`), not by the attacker's IAM identity. There is no attacker IP address in the transfer events.
- **Incremental transfers are small**: Each individual replication event copies one object — the same size as the legitimate write that created it. There is no burst of unusual activity.
- **Cloudwatch data transfer alarms may not fire**: Replication uses AWS internal bandwidth and may not appear in the same metrics as outbound internet transfers.

The **only reliable detection point** is the `PutBucketReplication` API call, which is a management plane event recorded in CloudTrail.

---

## Required Permissions

To configure S3 replication, an attacker needs:

**On the source bucket (victim account)**:
- `s3:PutReplicationConfiguration` — to add the replication configuration
- `s3:GetReplicationConfiguration` — to read existing configuration
- An IAM role with `s3:ReplicateObject` permission that S3 can assume

**On the destination bucket (attacker account)**:
- The destination bucket must exist and be in a different account (or region)
- The destination bucket policy must grant `s3:ReplicateObject` to the source account's replication role

This means an attacker who has compromised a role with `s3:PutReplicationConfiguration` can configure exfiltration without needing write access to the destination account beyond initial setup.

---

## Attacker Account Setup

Before executing this technique, the attacker prepares:

1. **Creates a destination bucket** in their own AWS account (or a compromised third account). The bucket name does not need to resemble the source bucket.

2. **Configures the destination bucket policy** to allow `s3:ReplicateObject` from the victim account's S3 replication role:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::VICTIM_ACCOUNT:role/replication-role"
       },
       "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
       "Resource": "arn:aws:s3:::attacker-bucket/*"
     }]
   }
   ```

3. **Enables versioning** on the destination bucket (required for replication).

The attacker's account setup is done entirely outside the victim's AWS environment — it generates no CloudTrail events in the victim account.

---

## Recovery Complexity

Once replication has been running, removing it is straightforward (`DeleteBucketReplication`), but recovery is not:

- **Objects replicated before discovery cannot be un-replicated**: The attacker retains copies in their account regardless of remediation actions in the victim account.
- **Identifying what was exfiltrated** requires checking S3 replication metrics or object inventory — which may not have been enabled.
- **No data deletion notice**: The victim's S3 bucket retains all original objects. Without proactive monitoring, the organization may not realize exfiltration occurred until the attacker uses the data.
- **Ongoing replication until detected**: If the replication configuration is not discovered promptly, weeks or months of new data may have been copied.

---

## Persistence Characteristic

This technique exemplifies "configure-and-forget" exfiltration. Compared to an attacker manually downloading data:

| Factor | Manual Download (GetObject) | S3 Replication |
|--------|----------------------------|----------------|
| Ongoing attacker presence | Required | Not required |
| Network-based detection | Possible (unusual IP) | Not possible |
| Volume spike | Yes | No |
| Detectable API calls | Per-file GetObject | Single PutBucketReplication |
| Scope | Historical data only | All future writes |
| Duration | Limited by session | Permanent until removed |

---

## References

- MITRE ATT&CK T1537: https://attack.mitre.org/techniques/T1537/
- AWS S3 Replication Documentation: https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html
- AWS Cross-Account Replication: https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-walkthrough-2.html
