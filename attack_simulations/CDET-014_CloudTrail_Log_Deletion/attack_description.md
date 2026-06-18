# CDET-014 — CloudTrail Log File Deleted from S3

**Tactic:** Defense Evasion  
**MITRE ATT&CK:** T1070.004 — Indicator Removal: File Deletion  
**Severity:** Critical  
**Data Source:** AWS CloudTrail (ironically), S3 data events

---

## Technique Overview

Deleting CloudTrail log files from the S3 destination bucket is an anti-forensic technique where an attacker attempts to destroy the evidence of their prior activity. Because AWS CloudTrail writes audit logs to an S3 bucket, an attacker who gains sufficient permissions can permanently delete those log files, removing the CloudTrail record that would reveal the full attack chain.

This is typically the **final phase** of a sophisticated attack — after achieving objectives (data exfiltration, privilege escalation, persistence establishment), the attacker attempts to cover their tracks before detection.

---

## Why Attackers Target CloudTrail S3 Logs

CloudTrail is the primary forensic data source for AWS incident response. Every API call made in the AWS account — including the attacker's own actions — is recorded as a JSON event and delivered to an S3 bucket. A successful CloudTrail deletion attack destroys:

- The record of which IAM user or role was used for the attack
- The source IP addresses of the attacker
- The exact API calls made (enumeration, privilege escalation, data access)
- The timestamp of each action (attack timeline)
- The `requestParameters` showing exactly what was targeted

From a forensic perspective, a successful CloudTrail deletion means the security team cannot reconstruct what happened, who did it, or what data was accessed. This makes incident response, legal proceedings, and breach notification filings significantly more difficult.

---

## The Time Window Problem

The critical limitation of this technique is the **SIEM ingestion window**:

Modern security operations centers use SIEM platforms (Splunk, Elastic, Microsoft Sentinel, Sumo Logic) that ingest CloudTrail events in near-real-time — typically within 1–15 minutes of the event occurring. CloudTrail delivers log files to S3 within approximately 15 minutes of the events they record.

**Attack timeline conflict**:
1. Attacker performs malicious actions (T=0)
2. CloudTrail records events (T=0 to T+15 minutes)
3. SIEM ingests the events from S3 (T+15 minutes)
4. Attacker deletes the log files from S3 (T+X hours)

If the SIEM has already ingested the events (step 3) before the attacker deletes them (step 4), the deletion achieves nothing — the evidence is already in the SIEM, and the deletion itself becomes additional evidence of the attack.

The only window where S3 deletion successfully destroys evidence is if the attacker deletes the log files **within 15 minutes** of their actions — before the SIEM ingests them. This is extremely difficult to achieve operationally and requires the attacker to know the exact timing of SIEM ingestion.

**Practical result**: In organizations with functioning SIEMs, CloudTrail S3 deletion almost never successfully destroys evidence. It does, however, create a high-fidelity detection signal itself — deleting an S3 object with the CloudTrail log key pattern (`AWSLogs/*/CloudTrail/*`) is automatically suspicious.

---

## S3 Object Lock as Prevention

S3 Object Lock prevents deletion of objects before the retention period expires:

**Governance mode**: Protects against most deletion attempts. Can be bypassed by IAM principals with `s3:BypassGovernanceRetention` permission. An attacker who compromises an account administrator may be able to bypass this.

**Compliance mode**: Provides absolute protection. **No one** — including the root account, account administrators, or AWS Support — can delete or modify an object within the retention period. This is the gold standard for immutable CloudTrail logs.

**Recommended retention**: 90–365 days for compliance logs. NIST 800-53 and CIS AWS Foundations Benchmark recommend at least 365 days for CloudTrail logs.

---

## Versioning + MFA Delete

S3 Versioning as a defense:
- Deleting a CloudTrail log file creates a DeleteMarker rather than permanently deleting the object
- The actual log data is preserved as a versioned object
- Recovery is possible by listing versions and restoring the prior version

When combined with **MFA Delete**:
- Permanent deletion (with explicit VersionId) requires a valid MFA token in addition to IAM credentials
- An attacker with a compromised access key but not the MFA device cannot permanently delete versioned objects
- MFA Delete is configured at the bucket level, requires root account to enable

---

## Cross-Account Log Delivery as Resilience

A mature CloudTrail architecture delivers logs to a **security account** separate from the account being audited:

```
Member Account (being audited)
    │
    │ CloudTrail delivery
    ▼
Security/Log Archive Account (separate AWS account)
    ├─ S3 bucket with Object Lock (Compliance mode)
    ├─ Bucket policy denies DeleteObject from member account
    └─ Only security team has access
```

In this architecture, even a fully compromised member account (including root-level compromise) cannot delete the logs because:
1. The S3 bucket is in a different AWS account
2. The bucket policy denies delete operations from the member account's principals
3. Object Lock provides a second layer of immutability

This is the recommended architecture for compliance-grade log preservation.

---

## What an Attacker Needs to Delete S3 Objects

To delete CloudTrail log files, an attacker needs:

**Minimum permissions**:
- `s3:DeleteObject` on the CloudTrail log bucket

**To permanently bypass versioning**:
- `s3:DeleteObjectVersion` (to delete specific versions)

**To disable versioning (and then delete)**:
- `s3:PutBucketVersioning`

**To bypass Object Lock (Governance mode only)**:
- `s3:BypassGovernanceRetention`

Note: `s3:DeleteObject` permission on the CloudTrail bucket is itself a policy risk that should be flagged in IAM reviews. The CloudTrail service delivery role should be the only principal that writes to the log bucket, and no human user should have deletion permissions on it.

---

## References

- MITRE ATT&CK T1070.004: https://attack.mitre.org/techniques/T1070/004/
- AWS S3 Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- AWS CloudTrail Best Practices: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
- CIS AWS Foundations Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services
