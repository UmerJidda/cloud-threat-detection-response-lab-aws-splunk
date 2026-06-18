# Detection to ATT&CK Mapping

## Overview

This document maps each planned and active detection to its primary MITRE ATT&CK technique, data sources, and detection approach. It is the authoritative cross-reference between the detection catalog and the ATT&CK framework.

---

## Mapping Table

| Detection ID | Detection Name | Tactic | Technique | Sub-Technique | Data Source | Status |
|-------------|---------------|--------|-----------|--------------|-------------|--------|
| CDET-001 | IAM User Created Outside Pipeline | Persistence | T1136 | T1136.003 | CloudTrail | Testing |
| CDET-002 | IAM Access Key Created for Existing User | Persistence | T1098 | T1098.001 | CloudTrail | Testing |
| CDET-003 | CloudTrail Logging Disabled | Defense Evasion | T1562 | T1562.008 | CloudTrail | Testing |
| CDET-004 | Admin Policy Attached to Principal | Privilege Escalation | T1078 | T1078.004 | CloudTrail | Testing |
| CDET-005 | Cross-Account Role Trust Modified | Privilege Escalation | T1484 | T1484.002 | CloudTrail | Testing |
| CDET-006 | Root Account Activity | Initial Access | T1078 | T1078.004 | CloudTrail | Testing |
| CDET-007 | EC2 Instance Metadata Credential Abuse | Credential Access | T1552 | T1552.005 | CloudTrail / GuardDuty | Testing |
| CDET-008 | Excessive API Enumeration | Discovery | T1580 | — | CloudTrail | Testing |
| CDET-009 | S3 Replication to External Account | Exfiltration | T1537 | — | CloudTrail | Testing |
| CDET-010 | Mass S3 Object Deletion | Impact | T1485 | — | CloudTrail | Testing |
| CDET-011 | Unauthorized Compute Resource Launch | Impact | T1496 | — | CloudTrail | Testing |
| CDET-012 | Cross-Account AssumeRole Chain | Lateral Movement | T1550 | T1550.001 | CloudTrail | Testing |
| CDET-013 | Security Group Opened to Public Internet | Defense Evasion | T1562 | T1562.007 | CloudTrail | Testing |
| CDET-014 | CloudTrail Log File Deleted from S3 | Defense Evasion | T1070 | T1070.004 | CloudTrail | Testing |

---

## Detailed Mappings

### CDET-001 — IAM User Created Outside Approved Pipeline

**ATT&CK:** T1136.003 — Create Account: Cloud Account

**Adversary Objective:** Establish persistence by creating a new IAM user with independent credentials that survive the original compromise vector being closed.

**Observable Signal:** `CreateUser` CloudTrail event from a principal not in the approved provisioning pipeline lookup.

**Key Fields:**
- `eventName = CreateUser`
- `userIdentity.arn` — must NOT be in `approved_iam_principals` lookup
- `userIdentity.type` — IAMUser or AssumedRole from unexpected source

**Evasion Techniques Adversaries May Use:**
- Using a compromised automation role to blend in with legitimate provisioning
- Timing creation to coincide with a change window
- Using a rarely-monitored service account

---

### CDET-002 — IAM Access Key Created for Existing User

**ATT&CK:** T1098.001 — Account Manipulation: Additional Cloud Credentials

**Adversary Objective:** Add a new access key to an existing IAM user to maintain persistent programmatic access after the original access method is revoked.

**Observable Signal:** `CreateAccessKey` CloudTrail event, especially for users with privileged policies or when created by a different principal than the key owner.

**Key Fields:**
- `eventName = CreateAccessKey`
- `requestParameters.userName` — the user receiving the new key
- `userIdentity.arn` — who created the key (may differ from key owner in attack scenarios)

---

### CDET-003 — CloudTrail Logging Disabled

**ATT&CK:** T1562.008 — Impair Defenses: Disable Cloud Logs

**Adversary Objective:** Eliminate the primary audit trail to hide subsequent actions.

**Observable Signal:** `StopLogging` or `DeleteTrail` CloudTrail events. Note: this detection records the disabling event itself before logging stops — the detection window is narrow.

**Key Fields:**
- `eventName IN (StopLogging, DeleteTrail, UpdateTrail)`
- `userIdentity.arn`
- `awsRegion` — adversaries may selectively disable logging in specific regions

**Critical Note:** This detection must be CRITICAL severity and have the shortest possible schedule (5-minute). A missed event can create a blind spot window.

---

### CDET-004 — Admin Policy Attached to User or Role

**ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts (privilege escalation variant)

**Adversary Objective:** Escalate privileges by attaching a highly permissive policy to a controlled principal.

**Observable Signal:** `AttachUserPolicy` or `AttachRolePolicy` where the attached policy is `AdministratorAccess` or equivalent custom admin policy.

**Key Fields:**
- `eventName IN (AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy)`
- `requestParameters.policyArn` — check against known admin policy ARNs
- `userIdentity.arn` — who performed the attachment

---

### CDET-005 — Cross-Account Role Trust Relationship Created

**ATT&CK:** T1484.002 — Domain or Tenant Policy Modification: Trust Modification

**Adversary Objective:** Allow a principal from an attacker-controlled account to assume a role in the victim account.

**Observable Signal:** `UpdateAssumeRolePolicy` or `CreateRole` events where the trust policy includes a principal from an account ID not in the approved accounts list.

**Key Fields:**
- `eventName IN (CreateRole, UpdateAssumeRolePolicy)`
- `requestParameters.policyDocument` — parse for external Account IDs
- Cross-reference account IDs against `approved_aws_accounts` lookup

---

### CDET-006 — Root Account Activity

**ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

**Adversary Objective:** Use the AWS root account — which cannot be restricted by IAM policies or SCPs — to perform privileged actions, create backdoor credentials, or disable security controls.

**Observable Signal:** Any CloudTrail event where `userIdentity.type = Root`, including API calls, console logins, and failed authentication attempts.

**Key Fields:**
- `userIdentity.type = Root` (via `root_activity` macro)
- `eventName` — classifies the specific action taken
- `additionalEventData.MFAUsed` — absence of MFA increases severity
- `root_action_category` — output field classifying the event type

---

### CDET-007 — EC2 Instance Metadata Service Abuse

**ATT&CK:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata

**Adversary Objective:** Steal IAM role credentials from the EC2 instance metadata service (IMDSv1) to gain cloud-level permissions.

**Observable Signal:** AssumeRole or API calls using EC2 instance role credentials from a source IP that is not the EC2 instance's private IP, or GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

**Key Fields:**
- GuardDuty finding type containing `InstanceCredentialExfiltration`
- CloudTrail: `userIdentity.type = AssumedRole` with `userIdentity.sessionContext.sessionIssuer.type = EC2Instance`
- `sourceIPAddress` not matching known EC2 private CIDR ranges

---

### CDET-008 — Excessive API Enumeration by Single Principal

**ATT&CK:** T1580 — Cloud Infrastructure Discovery

**Adversary Objective:** Enumerate cloud resources to identify targets, understand the environment's attack surface, or locate sensitive data stores.

**Observable Signal:** High volume of List/Describe/Get API calls across multiple services by a single principal within a short time window.

**Threshold:** ≥ 50 List/Describe calls AND ≥ 5 unique API names within 1 hour.

---

### CDET-009 — S3 Bucket Replication to External Account

**ATT&CK:** T1537 — Transfer Data to Cloud Account

**Adversary Objective:** Exfiltrate data by configuring ongoing S3 bucket replication to an attacker-controlled account.

**Observable Signal:** `PutBucketReplication` CloudTrail event where the destination bucket ARN belongs to an account not in the approved accounts list.

---

### CDET-010 — Mass S3 Object Deletion

**ATT&CK:** T1485 — Data Destruction

**Adversary Objective:** Destroy data for ransomware, competitive sabotage, or to cover tracks.

**Observable Signal:** High volume of `DeleteObject` or `DeleteObjects` events within a short time window. Threshold: ≥ 1000 delete operations within 10 minutes.

---

### CDET-011 — Unauthorized Compute Resource Launch

**ATT&CK:** T1496 — Resource Hijacking

**Adversary Objective:** Launch EC2 instances or Lambda functions to mine cryptocurrency or conduct further attacks.

**Observable Signal:** `RunInstances` or `CreateFunction` from principals not typically associated with compute provisioning, especially for large instance types or GPU instances.

---

### CDET-012 — Cross-Account AssumeRole Chain

**ATT&CK:** T1550.001 — Use Alternate Authentication Material: Application Access Token

**Adversary Objective:** Move laterally through multiple AWS accounts by chaining AssumeRole calls, each hop providing access to the next account.

**Observable Signal:** AssumeRole events where the session context shows a multi-hop chain — a principal that is itself an assumed role assuming another role across an account boundary.

---

### CDET-013 — Security Group Opened to Public Internet

**ATT&CK:** T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall

**Adversary Objective:** Open network access to a resource to enable direct connectivity from attacker infrastructure.

**Observable Signal:** `AuthorizeSecurityGroupIngress` event creating a rule with `0.0.0.0/0` on sensitive ports (22, 3389, 5432, 3306, 6379).

---

### CDET-014 — CloudTrail Log File Deleted from S3

**ATT&CK:** T1070.004 — Indicator Removal: File Deletion

**Adversary Objective:** Retroactively delete CloudTrail log files from S3 to remove evidence of prior activity.

**Observable Signal:** `DeleteObject` events on the CloudTrail S3 bucket by a principal other than the CloudTrail service principal.
