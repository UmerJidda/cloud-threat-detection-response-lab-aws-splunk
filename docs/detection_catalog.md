# Detection Catalog

**Version:** 1.0.0  
**Last Updated:** 2024-01-15  
**Total Detections:** 14  
**Status Summary:** 14 Testing | 0 Active | 0 Deprecated

---

## Overview

This catalog documents all detections in the Cloud Threat Detection & Response Lab. Each detection targets real AWS adversary behavior using CloudTrail, GuardDuty, and Security Hub telemetry. All SPL queries use the [standard macro set](../docs/splunk/index_strategy.md) and [suppression lookup framework](../docs/detection_engineering/tuning_guidelines.md).

Detections are organized by MITRE ATT&CK tactic. For technique-to-detection mapping see [`docs/mitre_mapping/detection_to_attack_mapping.md`](mitre_mapping/detection_to_attack_mapping.md).

---

## Quick Reference Table

| ID | Detection Name | Tactic | Technique | Severity | Confidence | Schedule | Status |
|----|---------------|--------|-----------|----------|------------|----------|--------|
| [CDET-001](#cdet-001) | IAM User Created Outside Pipeline | Persistence | T1136.003 | High | Medium | 15m | Testing |
| [CDET-002](#cdet-002) | IAM Access Key Created for Existing User | Persistence | T1098.001 | High | Medium | 15m | Testing |
| [CDET-003](#cdet-003) | CloudTrail Logging Disabled | Defense Evasion | T1562.008 | Critical | High | 5m | Testing |
| [CDET-004](#cdet-004) | Admin Policy Attached to Principal | Privilege Escalation | T1078.004 | Critical | High | 10m | Testing |
| [CDET-005](#cdet-005) | Cross-Account Role Trust Modified | Privilege Escalation | T1484.002 | High | Medium | 15m | Testing |
| [CDET-006](#cdet-006) | Root Account Activity | Initial Access | T1078.004 | Critical | High | 5m | Testing |
| [CDET-007](#cdet-007) | EC2 Instance Metadata Credential Abuse | Credential Access | T1552.005 | High | High | 5m | Testing |
| [CDET-008](#cdet-008) | Excessive API Enumeration | Discovery | T1580 | Medium | Medium | 60m | Testing |
| [CDET-009](#cdet-009) | S3 Replication to External Account | Exfiltration | T1537 | High | High | 15m | Testing |
| [CDET-010](#cdet-010) | Mass S3 Object Deletion | Impact | T1485 | Critical | High | 5m | Testing |
| [CDET-011](#cdet-011) | Unauthorized Compute Resource Launch | Impact | T1496 | High | Medium | 15m | Testing |
| [CDET-012](#cdet-012) | Cross-Account AssumeRole Chain | Lateral Movement | T1550.001 | High | Medium | 30m | Testing |
| [CDET-013](#cdet-013) | Security Group Opened to Public Internet | Defense Evasion | T1562.007 | High/Critical | High | 10m | Testing |
| [CDET-014](#cdet-014) | CloudTrail Log File Deleted from S3 | Defense Evasion | T1070.004 | Critical | High | 5m | Testing |

---

## Detections by Tactic

### Initial Access

---

#### CDET-006

**IAM Root Account Activity**

| | |
|--|--|
| **Detection ID** | CDET-006 |
| **ATT&CK Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Severity** | Critical |
| **Confidence** | High |
| **Schedule** | Every 5 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** Any use of the AWS root account, including console login, API calls, or failed authentication attempts. The root account has unrestricted access to all AWS resources and cannot be restricted by IAM policies or SCPs. Its use outside of documented break-glass procedures is always anomalous.

**Key logic:** Uses the `root_activity` macro which filters for `userIdentity.type=Root`. No suppression by design — root activity is never expected and every alert should be reviewed.

**Required lookups:** None

**Suppression fields:** None (intentionally unsuppressed)

**Key output fields:**
- `root_action_category` — classifies the event type (console login, access key usage, API call, failed login)
- `mfa_used` — whether MFA was present for the session

**Files:**
- [`detections/initial_access/CDET-006_root_account_activity/detection.yaml`](../detections/initial_access/CDET-006_root_account_activity/detection.yaml)
- [`detections/initial_access/CDET-006_root_account_activity/detection.spl`](../detections/initial_access/CDET-006_root_account_activity/detection.spl)
- [`detections/initial_access/CDET-006_root_account_activity/README.md`](../detections/initial_access/CDET-006_root_account_activity/README.md)

---

### Persistence

---

#### CDET-001

**IAM User Created Outside Pipeline**

| | |
|--|--|
| **Detection ID** | CDET-001 |
| **ATT&CK Technique** | T1136.003 — Create Account: Cloud Account |
| **Severity** | High |
| **Confidence** | Medium |
| **Schedule** | Every 15 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** IAM user creation (`CreateUser`) from principals not in the approved-principal or automation-role lookups. Adversaries create new IAM users to establish persistence — a new user credential that survives even if the original compromised key is rotated.

**Key logic:** Dual-lookup suppression checks both `principal_arn` and `session_issuer_arn` to handle AssumedRole sessions from approved pipeline roles. Confidence is dynamically adjusted based on whether the creator is a human user (lower) or an automated role (higher, as automation should be in the suppression list).

**Required lookups:** `approved_iam_principals`, `automation_role_arns`

**Files:**
- [`detections/persistence/CDET-001_iam_user_created_outside_pipeline/`](../detections/persistence/CDET-001_iam_user_created_outside_pipeline/)

---

#### CDET-002

**IAM Access Key Created for Existing User**

| | |
|--|--|
| **Detection ID** | CDET-002 |
| **ATT&CK Technique** | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| **Severity** | High |
| **Confidence** | Medium |
| **Schedule** | Every 15 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** Access key creation (`CreateAccessKey`) targeting users other than the key creator, or creation for users in the `privileged_iam_users` lookup. This pattern indicates an adversary adding credentials to an existing account to avoid detection (no new user created).

**Key logic:** Uses a string pattern match to detect self-rotation vs. cross-user key creation (`like(creator_arn, "%" + key_owner_name)`). Elevated confidence when key is created for a privileged user.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`, `privileged_iam_users`

**Files:**
- [`detections/persistence/CDET-002_iam_access_key_created_for_existing_user/`](../detections/persistence/CDET-002_iam_access_key_created_for_existing_user/)

---

### Privilege Escalation

---

#### CDET-004

**Admin Policy Attached to Principal**

| | |
|--|--|
| **Detection ID** | CDET-004 |
| **ATT&CK Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Severity** | Critical |
| **Confidence** | High |
| **Schedule** | Every 10 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** Attachment of admin-equivalent managed policies (`AttachUserPolicy`, `AttachRolePolicy`) where the policy ARN is in `admin_policy_arns.csv`, or inline policy creation (`PutUserPolicy`, `PutRolePolicy`) containing wildcard `Action: *` with `Resource: *`. Both managed and inline escalation paths are covered.

**Key logic:** Managed policies are checked via lookup; inline policies are scanned with regex for `"Action":"*"` and `"Resource":"*"` patterns in the `policyDocument` request parameter.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`, `admin_policy_arns`

**Files:**
- [`detections/privilege_escalation/CDET-004_admin_policy_attached_to_principal/`](../detections/privilege_escalation/CDET-004_admin_policy_attached_to_principal/)

---

#### CDET-005

**Cross-Account Role Trust Modified**

| | |
|--|--|
| **Detection ID** | CDET-005 |
| **ATT&CK Technique** | T1484.002 — Domain or Tenant Policy Modification: Trust Modification |
| **Severity** | High |
| **Confidence** | Medium |
| **Schedule** | Every 15 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** Role creation or trust policy modification (`CreateRole`, `UpdateAssumeRolePolicy`) that includes a trust relationship to an account ID not in `approved_aws_accounts.csv`. This is the configuration step that enables cross-account lateral movement.

**Key logic:** Extracts account IDs from the trust policy JSON using `rex`. Excludes `.amazonaws.com` service principals (these are legitimate service trust relationships). Cross-references extracted account IDs against the approved accounts lookup.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`, `approved_aws_accounts`

**Files:**
- [`detections/privilege_escalation/CDET-005_cross_account_role_trust_modified/`](../detections/privilege_escalation/CDET-005_cross_account_role_trust_modified/)

---

### Credential Access

---

#### CDET-007

**EC2 Instance Metadata Credential Abuse**

| | |
|--|--|
| **Detection ID** | CDET-007 |
| **ATT&CK Technique** | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| **Severity** | High |
| **Confidence** | High |
| **Schedule** | Every 5 minutes |
| **Data Source** | CloudTrail + GuardDuty |
| **Splunk Index** | `aws_cloudtrail`, `aws_security` |

**What it detects:** EC2 instance role credentials being used from an IP address outside the EC2 private range (indicating credential theft and use from an external system), OR GuardDuty `InstanceCredentialExfiltration` findings.

**Key logic:** Two-branch detection using `| append [ search ... ]` to merge CloudTrail anomaly signals with GuardDuty finding events. Branch A fires on AssumedRole sessions with `sessionIssuer.type=EC2` whose source IP is not in `ec2_private_cidr_ranges`. Branch B fires directly on GuardDuty findings.

**Required lookups:** `ec2_private_cidr_ranges`, `approved_iam_principals`

**Files:**
- [`detections/credential_access/CDET-007_ec2_instance_metadata_credential_abuse/`](../detections/credential_access/CDET-007_ec2_instance_metadata_credential_abuse/)

---

### Discovery

---

#### CDET-008

**Excessive API Enumeration**

| | |
|--|--|
| **Detection ID** | CDET-008 |
| **ATT&CK Technique** | T1580 — Cloud Infrastructure Discovery |
| **Severity** | Medium |
| **Confidence** | Medium |
| **Schedule** | Every 60 minutes (2-hour lookback) |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** A principal making ≥ 50 API calls across ≥ 5 distinct API names within a 2-hour window, indicating automated reconnaissance. Adversaries run enumeration scripts (Pacu, ScoutSuite, CloudMapper) that call dozens of read-only APIs in rapid succession.

**Key logic:** Aggregates by `principal_arn` with `stats count AS total_calls, dc(eventName) AS unique_api_calls`. Classifies enumeration intensity (moderate, high, extreme) based on volume. Scheduled hourly with 2-hour lookback to catch spread-out enumeration.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`

**Files:**
- [`detections/discovery/CDET-008_excessive_api_enumeration/`](../detections/discovery/CDET-008_excessive_api_enumeration/)

---

### Lateral Movement

---

#### CDET-012

**Cross-Account AssumeRole Chain**

| | |
|--|--|
| **Detection ID** | CDET-012 |
| **ATT&CK Technique** | T1550.001 — Use Alternate Authentication Material: Application Access Token |
| **Severity** | High (Critical if chained + multiple targets) |
| **Confidence** | Medium |
| **Schedule** | Every 30 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** `sts:AssumeRole` calls from principals not in approved-principal/automation-role lookups that target AWS account IDs not in `approved_aws_accounts.csv`. Escalates to critical when the caller is already an `AssumedRole` session (chained assumption pattern) targeting multiple unapproved accounts.

**Key logic:** Extracts target account IDs from `requestParameters.roleArn` using `rex`. Aggregates by `principal_arn` to count `distinct_target_accounts`. Dual-lookup suppression for both `principal_arn` and `session_issuer_arn`.

**Required lookups:** `approved_aws_accounts`, `approved_iam_principals`, `automation_role_arns`

**Files:**
- [`detections/lateral_movement/CDET-012_cross_account_assumerole_chain/`](../detections/lateral_movement/CDET-012_cross_account_assumerole_chain/)

---

### Exfiltration

---

#### CDET-009

**S3 Replication to External Account**

| | |
|--|--|
| **Detection ID** | CDET-009 |
| **ATT&CK Technique** | T1537 — Transfer Data to Cloud Account |
| **Severity** | High |
| **Confidence** | High |
| **Schedule** | Every 15 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** S3 cross-region or cross-account replication configuration (`PutBucketReplication`) where the destination S3 bucket belongs to an AWS account ID not in the approved-accounts list. This is a sophisticated, persistent exfiltration technique — once configured, data flows continuously without further attacker interaction.

**Key logic:** Extracts the destination account ID from the `replicationConfiguration` JSON blob using `rex`. Cross-references against `approved_aws_accounts`. The source bucket name and target bucket ARN are both captured for IR.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`, `approved_aws_accounts`

**Files:**
- [`detections/exfiltration/CDET-009_s3_replication_to_external_account/`](../detections/exfiltration/CDET-009_s3_replication_to_external_account/)

---

### Defense Evasion

---

#### CDET-003

**CloudTrail Logging Disabled**

| | |
|--|--|
| **Detection ID** | CDET-003 |
| **ATT&CK Technique** | T1562.008 — Impair Defenses: Disable or Modify Cloud Logs |
| **Severity** | Critical |
| **Confidence** | High |
| **Schedule** | Every 5 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** CloudTrail being stopped (`StopLogging`), deleted (`DeleteTrail`), or degraded (`UpdateTrail` with `enableLogFileValidation=false`, `isMultiRegionTrail=false`, or `includeGlobalServiceEvents=false`). All three are common adversary anti-forensics techniques.

**Key logic:** The `disable_reason` eval field classifies exactly why the alert fired (stopped, deleted, or which trail property was degraded). UpdateTrail only fires when the change reduces coverage — benign trail updates (e.g., changing S3 prefix) do not trigger.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`

**Files:**
- [`detections/defense_evasion/CDET-003_cloudtrail_logging_disabled/`](../detections/defense_evasion/CDET-003_cloudtrail_logging_disabled/)

---

#### CDET-013

**Security Group Opened to Public Internet**

| | |
|--|--|
| **Detection ID** | CDET-013 |
| **ATT&CK Technique** | T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall |
| **Severity** | High / Critical (port-dependent) |
| **Confidence** | High |
| **Schedule** | Every 10 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** `AuthorizeSecurityGroupIngress` events that add `0.0.0.0/0` or `::/0` CIDR ranges from principals not in the approved-principal lookups. Elevates to Critical for remote-access ports (22, 3389) and database ports (3306, 5432, 1433, 27017, 6379) and all-traffic protocol (-1).

**Key logic:** Uses `spath` and `mvexpand` to extract individual IP permission entries from the nested `ipPermissions` structure. The `high_risk_port` eval field classifies the exposure type. Approved CIDR ranges (e.g., corporate VPN IPs) can be excluded via `approved_cidr_ranges.csv`.

**Required lookups:** `approved_iam_principals`, `approved_cidr_ranges`, `automation_role_arns`

**Files:**
- [`detections/defense_evasion/CDET-013_security_group_opened_to_internet/`](../detections/defense_evasion/CDET-013_security_group_opened_to_internet/)

---

#### CDET-014

**CloudTrail Log File Deleted from S3**

| | |
|--|--|
| **Detection ID** | CDET-014 |
| **ATT&CK Technique** | T1070.004 — Indicator Removal: File Deletion |
| **Severity** | Critical |
| **Confidence** | High |
| **Schedule** | Every 5 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** Any `DeleteObject`, `DeleteObjects`, or `DeleteBucket` event targeting a bucket in the `cloudtrail_log_buckets.csv` lookup, from any non-AWSService principal. This is evidence tampering — the attacker is attempting to destroy forensic evidence of their activity.

**Key logic:** Requires the `cloudtrail_log_buckets.csv` lookup to be populated with all CloudTrail S3 delivery bucket names. S3 lifecycle policy deletions (`userIdentity.type=AWSService`) are explicitly excluded. Minimal suppression by design — this alert is almost never a false positive.

**Required lookups:** `cloudtrail_log_buckets`, `approved_iam_principals`

**Files:**
- [`detections/defense_evasion/CDET-014_cloudtrail_log_deleted_from_s3/`](../detections/defense_evasion/CDET-014_cloudtrail_log_deleted_from_s3/)

---

### Impact

---

#### CDET-010

**Mass S3 Object Deletion**

| | |
|--|--|
| **Detection ID** | CDET-010 |
| **ATT&CK Technique** | T1485 — Data Destruction |
| **Severity** | Critical |
| **Confidence** | High |
| **Schedule** | Every 5 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** A principal deleting ≥ 100 estimated S3 objects or making ≥ 20 delete API calls within a 10-minute window. This pattern is characteristic of ransomware-style data destruction in AWS. The `DeleteObjects` API is weighted at 100 estimated objects per call (batch deletion); `DeleteBucket` is weighted at 1000.

**Key logic:** Aggregates by `principal_arn` with `stats sum(objects_in_call) AS estimated_objects_deleted`. Classifies `destruction_scope` based on number of buckets targeted and total estimated objects. AWSService deletions from lifecycle policies are excluded.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`

**Files:**
- [`detections/impact/CDET-010_mass_s3_object_deletion/`](../detections/impact/CDET-010_mass_s3_object_deletion/)

---

#### CDET-011

**Unauthorized Compute Resource Launch**

| | |
|--|--|
| **Detection ID** | CDET-011 |
| **ATT&CK Technique** | T1496 — Resource Hijacking |
| **Severity** | High |
| **Confidence** | Medium |
| **Schedule** | Every 15 minutes |
| **Data Source** | CloudTrail |
| **Splunk Index** | `aws_cloudtrail` |

**What it detects:** `RunInstances` (EC2) or `CreateFunction` (Lambda) calls from principals not in approved-principal or automation-role lookups. Confidence and severity escalate when the launched instance type is in `suspicious_instance_types.csv` (GPU/high-CPU types commonly used for cryptocurrency mining).

**Key logic:** The `suspicious_instance_types.csv` lookup contains instance type prefixes mapped to `is_suspicious_type` and `abuse_category`. The `instance_count` field (from `maxCount`) enables detection of large-scale parallel instance launches.

**Required lookups:** `approved_iam_principals`, `automation_role_arns`, `suspicious_instance_types`

**Files:**
- [`detections/impact/CDET-011_unauthorized_compute_resource_launch/`](../detections/impact/CDET-011_unauthorized_compute_resource_launch/)

---

## Suppression Lookup Reference

All detections use the following shared lookup tables. Populate each with environment-specific data before promoting detections to Active status.

| Lookup File | Purpose | Used By |
|-------------|---------|---------|
| `approved_iam_principals.csv` | Principals authorized for sensitive operations | All detections |
| `automation_role_arns.csv` | Pipeline/automation roles — suppress routine ops | Most detections |
| `admin_policy_arns.csv` | Managed policy ARNs considered admin-equivalent | CDET-004 |
| `approved_aws_accounts.csv` | Authorized AWS account IDs for cross-account ops | CDET-005, CDET-009, CDET-012 |
| `privileged_iam_users.csv` | Users with elevated IAM permissions | CDET-002 |
| `ec2_private_cidr_ranges.csv` | RFC1918 + metadata IP ranges for EC2 | CDET-007 |
| `approved_cidr_ranges.csv` | Corporate VPN/proxy CIDRs for security group rules | CDET-013 |
| `approved_regions.csv` | AWS regions the organization uses | CDET-008 (enrichment) |
| `cloudtrail_log_buckets.csv` | S3 buckets used for CloudTrail log delivery | CDET-014 |
| `suspicious_instance_types.csv` | EC2 types commonly used for abuse | CDET-011 |

> **Lookup files are located in:** `splunk/lookups/`

---

## Validation Status

All 14 detections are in **Testing** status. Promotion to **Active** requires:

1. Suppression lookups populated with environment-specific data
2. Minimum 14-day testing period in non-production Splunk environment
3. False positive rate < 5% over the testing period
4. At least one successful validation test (positive + negative cases) documented in `data/validation_results/`

See [`docs/detection_engineering/tuning_guidelines.md`](detection_engineering/tuning_guidelines.md) for full promotion criteria.

---

## Coverage Summary

| Tactic | Detections | Techniques |
|--------|-----------|------------|
| Initial Access | 1 | T1078.004 |
| Persistence | 2 | T1136.003, T1098.001 |
| Privilege Escalation | 2 | T1078.004, T1484.002 |
| Credential Access | 1 | T1552.005 |
| Discovery | 1 | T1580 |
| Lateral Movement | 1 | T1550.001 |
| Exfiltration | 1 | T1537 |
| Defense Evasion | 4 | T1562.008, T1562.007, T1070.004 |
| Impact | 2 | T1485, T1496 |
| **Total** | **14** | **10 unique techniques** |
