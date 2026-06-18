# CDET-010 — Mass S3 Object Deletion

**Tactic:** Impact  
**MITRE ATT&CK:** T1485 — Data Destruction  
**Severity:** Critical  
**Data Source:** AWS CloudTrail

---

## Technique Overview

Mass S3 object deletion is a data destruction attack where an adversary deletes large numbers of objects from victim S3 buckets, either to destroy valuable business data (sabotage), to eliminate evidence of prior activity, or as the "destruction" phase of a ransomware-style extortion scheme. When S3 versioning is disabled and S3 Object Lock is not configured, deletion is permanent and irreversible. Even with versioning enabled, attackers who know about DeleteMarkers can neutralize its protections.

---

## S3 Versioning: Protection and Its Bypass

### How Versioning Protects Data

When S3 versioning is enabled on a bucket, deleting an object does not actually remove the data — it creates a **DeleteMarker**, which is a special version marker that hides the object from standard `ListObjectsV2` and `GetObject` calls. The actual object data and all previous versions are preserved and can be recovered by listing versioned objects and restoring the desired version.

Versioning is the single most effective protection against accidental or malicious S3 deletion.

### How Attackers Bypass Versioning

A knowledgeable attacker can defeat versioning protection through **versioned deletion**:

1. First, `ListObjectVersions` — enumerate all versions and DeleteMarkers for every object.
2. Then, `DeleteObjects` with explicit version IDs — deletes the actual version, not just adds a marker.
3. Repeat until all versions of all objects are permanently removed.

This two-step process permanently destroys the data, bypassing versioning protection. The difference in API calls: `DeleteObject` (without version ID) creates a DeleteMarker and is reversible; `DeleteObjects` with explicit `VersionId` permanently destroys that version.

---

## S3 Object Lock as Stronger Protection

S3 Object Lock enforces a WORM (Write Once, Read Many) model and is the only S3-native control that can prevent permanent deletion even by account administrators:

**Governance mode**: Objects cannot be deleted before the retention period expires without special permissions (`s3:BypassGovernanceRetention`). An attacker with sufficient IAM permissions can bypass this.

**Compliance mode**: Objects cannot be deleted by anyone — including the root account, AWS Support, or any IAM policy — before the retention period expires. This is the strongest protection and is truly immutable.

Object Lock with Compliance mode means that even a fully compromised AWS account cannot destroy data within the retention window.

---

## MFA Delete

MFA Delete adds a second factor to the `DeleteObject` (permanent deletion) and `PutBucketVersioning` (disabling versioning) operations. When enabled, these operations require both valid IAM credentials and a valid MFA token. An attacker who has compromised an access key but not the MFA device cannot permanently delete versioned objects.

Limitation: MFA Delete can only be enabled or disabled by the root account and is therefore rarely configured in practice.

---

## The DeleteObjects Batch API

`DeleteObjects` (plural) is the attack's force multiplier. A single API call can permanently delete up to **1,000 objects**. For a bucket containing 1 million objects, an attacker needs only 1,000 API calls to destroy the entire bucket. At typical API call rates, this can be accomplished in seconds to minutes.

The batch API also reduces CloudTrail noise — 1,000 deletions appear as a single `DeleteObjects` event, though the event does contain the list of deleted keys in `requestParameters.delete.objects`.

---

## Ransomware-Style Exfiltrate-Then-Destroy Pattern

The most damaging variant of this attack follows a three-phase pattern:

**Phase 1 — Exfiltration**: The attacker copies all objects from the victim bucket to attacker-controlled storage (see CDET-009: S3 Replication, or bulk `GetObject` download). Now the attacker has a copy of all data.

**Phase 2 — Destruction**: The attacker permanently deletes all objects from the victim bucket using `DeleteObjects`. Without backups or versioning, the data is now exclusively in the attacker's possession.

**Phase 3 — Ransom**: The attacker contacts the victim and demands payment for the return of the data. This is cloud ransomware — the attack economics are identical to traditional ransomware but operate entirely within cloud storage APIs.

Real-world incidents following this pattern have been documented against misconfigured MongoDB instances, Elasticsearch clusters, and S3 buckets. Cloud storage ransomware targeting S3 buckets has been active since at least 2020.

---

## Why This Is Irreversible Without Versioning

Without versioning, `DeleteObject` is a permanent, unrecoverable operation:

- AWS does not maintain backup copies of S3 objects (unless you explicitly configure CRR or S3 Batch Replication backups)
- AWS Support cannot recover deleted objects without versioning
- S3 is not backed by a filesystem with a trash/recycle bin concept
- There is no "undo" operation

The only recovery path is a pre-existing backup in a separate location: a versioned bucket, a cross-region replication destination, or an external backup system.

---

## References

- MITRE ATT&CK T1485: https://attack.mitre.org/techniques/T1485/
- AWS S3 Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- AWS S3 Versioning: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
- AWS MFA Delete: https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html
