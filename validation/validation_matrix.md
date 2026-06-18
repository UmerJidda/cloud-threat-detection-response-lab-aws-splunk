# Validation Matrix — Cloud Threat Detection Lab

**Version:** 1.0.0
**Date:** 2026-06-18
**Status:** All detections in Testing phase (not yet promoted to production)
**Maintainer:** Detection Engineering

---

## Table of Contents

1. [Summary Status Table](#1-summary-status-table)
2. [Per-Detection Test Case Summary](#2-per-detection-test-case-summary)
3. [Validation Coverage Statistics](#3-validation-coverage-statistics)
4. [Open Items and Known Gaps](#4-open-items-and-known-gaps)

---

## 1. Summary Status Table

> All test cases are defined and sample data files exist. Splunk validation requires a live Splunk environment with the CloudTrail sourcetype and lookup tables deployed.
> Legend — Positive/Negative/Edge Test cells: **Defined** = test case authored, sample log created; **Validated** = run against live Splunk and alert behavior confirmed.

| CDET ID | Detection Name | Tactic | Technique | Positive Test | Negative Test | Edge Test | Splunk Validated | Status | Last Validated |
|---------|---------------|--------|-----------|--------------|--------------|----------|-----------------|--------|---------------|
| CDET-001 | IAM User Created Outside Pipeline | Persistence | T1136.003 | Defined | Defined | Defined | No | Testing | — |
| CDET-002 | IAM Access Key Created for Existing User | Persistence | T1098.001 | Defined | Defined | Defined | No | Testing | — |
| CDET-003 | CloudTrail Logging Disabled | Defense Evasion | T1562.008 | Defined | Defined | Defined | No | Testing | — |
| CDET-004 | Admin Policy Attached to Principal | Privilege Escalation | T1078.004 | Defined | Defined | Defined | No | Testing | — |
| CDET-005 | Cross Account Role Trust Modified | Privilege Escalation | T1484.002 | Defined | Defined | Defined | No | Testing | — |
| CDET-006 | Root Account Activity | Initial Access | T1078.004 | Defined | Defined | Defined | No | Testing | — |
| CDET-007 | EC2 Metadata Credential Abuse | Credential Access | T1552.005 | Defined | Defined | Defined | No | Testing | — |
| CDET-008 | Excessive API Enumeration | Discovery | T1580 | Defined | Defined | Defined | No | Testing | — |
| CDET-009 | S3 Replication to External Account | Exfiltration | T1537 | Defined | Defined | Defined | No | Testing | — |
| CDET-010 | Mass S3 Object Deletion | Impact | T1485 | Defined | Defined | Defined | No | Testing | — |
| CDET-011 | Unauthorized Compute Launch | Impact | T1496 | Defined | Defined | Defined | No | Testing | — |
| CDET-012 | Cross Account AssumeRole Chain | Lateral Movement | T1550.001 | Defined | Defined | Defined | No | Testing | — |
| CDET-013 | Security Group Opened to Internet | Defense Evasion | T1562.007 | Defined | Defined | Defined | No | Testing | — |
| CDET-014 | CloudTrail Log Deleted from S3 | Defense Evasion | T1070.004 | Defined | Defined | Defined | No | Testing | — |

---

## 2. Per-Detection Test Case Summary

---

### CDET-001 — IAM User Created Outside Pipeline

**Tactic:** Persistence | **Technique:** T1136.003 (Create Account: Cloud Account)

| Test Type | Description |
|-----------|-------------|
| Positive | An IAM user is created by a principal (e.g., `arn:aws:iam::123456789012:user/attacker`) that is neither in the `approved_iam_principals` lookup nor in the `automation_role_arns` lookup, confirming the alert fires. |
| Negative | An IAM user is created by an approved CI/CD pipeline role whose session issuer ARN is present in `automation_role_arns`, confirming the alert does not fire. |
| Edge | An AssumedRole session uses an approved role ARN (in `automation_role_arns`) but the session name is not in `approved_iam_principals`; documents whether the detection suppresses on the role ARN alone or requires the full session ARN. |

**Known Gaps / Limitations:**
- If an attacker compromises a host that can assume `DeploymentPipelineRole`, the resulting session issuer ARN matches the lookup and the event is suppressed — this is a documented blind spot requiring complementary lateral-movement detections.
- Geographic and region anomalies for pipeline role usage are out of scope for this detection and are not evaluated.
- No benign baseline dataset exists for this detection; the negative test relies solely on the lookup-suppressed log sample.

---

### CDET-002 — IAM Access Key Created for Existing User

**Tactic:** Persistence | **Technique:** T1098.001 (Account Manipulation: Additional Cloud Credentials)

| Test Type | Description |
|-----------|-------------|
| Positive | An IAM access key is created for a different (privileged) user by a cross-account principal not in `automation_role_arns`, confirming the alert fires with high or critical severity. |
| Negative | A non-privileged user creates an access key for themselves, confirming no alert is generated when neither the creator nor the target meets the suspicious criteria. |
| Edge | An AssumedRole session from an approved automation role creates a key for a privileged user; validates whether automation suppression takes precedence over the privileged-target trigger (a potential detection gap if suppression wins). |

**Known Gaps / Limitations:**
- If the SPL applies automation role suppression before checking privileged target, a legitimate-looking automation role can create keys for privileged users without alerting — this must be explicitly tested and the behavior documented.
- Service-linked role key rotations may generate false positives if `privileged_users` lookup is overly broad.

---

### CDET-003 — CloudTrail Logging Disabled

**Tactic:** Defense Evasion | **Technique:** T1562.008 (Impair Defenses: Disable Cloud Logs)

| Test Type | Description |
|-----------|-------------|
| Positive | A `StopLogging` event is generated against an active CloudTrail trail, confirming the detection fires immediately regardless of the calling principal. |
| Negative | An `UpdateTrail` call is made that changes only the S3 key prefix (a non-logging-degrading parameter), confirming no alert is generated. |
| Edge | An `UpdateTrail` call sets exactly one of the three degradation parameters (`MultiRegionTrailEnabled`, `LogFileValidationEnabled`, or `IncludeGlobalServiceEvents`) to false; validates whether the detection requires all three to be degraded or fires on any single degradation. |

**Known Gaps / Limitations:**
- No caller-based suppression exists by design; this means legitimate Terraform cost-optimization runs that disable multi-region trail collection may produce false positives — exceptions should be documented per trail ARN rather than suppressing the entire principal.
- `DeleteTrail` is covered separately by CDET-014; this detection focuses on degradation-in-place events.

---

### CDET-004 — Admin Policy Attached to Principal

**Tactic:** Privilege Escalation | **Technique:** T1078.004 (Valid Accounts: Cloud Accounts)

| Test Type | Description |
|-----------|-------------|
| Positive | `AttachUserPolicy` is called with `policyArn = arn:aws:iam::aws:policy/AdministratorAccess` by a non-approved principal, confirming the alert fires at critical severity. |
| Negative | A non-admin managed policy (e.g., `AmazonS3ReadOnlyAccess`) is attached to a user, or an inline policy is applied with only resource-scoped permissions, confirming no alert is generated. |
| Edge | An inline policy is applied with `Action: *` and `Resource: *` but `Effect: Deny`; validates whether the SPL correctly checks for `Effect: Allow` before triggering, preventing a false positive bug. |

**Known Gaps / Limitations:**
- `PowerUserAccess` (which grants nearly full AWS access minus IAM) is not included in the `admin_policy_arns` lookup by default — this is a documented gap where near-admin privilege escalation is not detected by this rule.
- Inline policy parsing depends on correct JSON extraction from the CloudTrail `requestParameters` field; malformed or deeply nested policy documents may be missed.
- The `approved_iam_principals` suppression does not remove the risk; attaching admin policies via approved principals remains a high-risk action and should generate at minimum a medium-severity informational alert.

---

### CDET-005 — Cross Account Role Trust Modified

**Tactic:** Privilege Escalation | **Technique:** T1484.002 (Domain or Tenant Policy Modification: Trust Modification)

| Test Type | Description |
|-----------|-------------|
| Positive | `UpdateAssumeRolePolicy` is called to add an external AWS account (not in `approved_external_accounts`) as a trusted principal in the `Principal.AWS` field, confirming the alert fires. |
| Negative | A trust policy update includes only the same account ID in the principal field, or the modified external account is present in the `approved_external_accounts` lookup, confirming no alert is generated. |
| Edge | A trust policy update includes both a same-account principal and an external account principal in a single statement; validates whether the detection correctly identifies the external account even when mixed with legitimate same-account entries. |

**Known Gaps / Limitations:**
- Trust policy JSON is embedded in `requestParameters` as an URL-encoded string; if the SPL JSON extraction is fragile, complex or non-standard policy structures may be missed.
- `CreateRole` events with external trust are covered by this detection but may have different field paths than `UpdateAssumeRolePolicy` — both event names must be validated separately.
- No benign baseline dataset covering multi-account organizational trust relationships (e.g., AWS Organizations StackSets).

---

### CDET-006 — Root Account Activity

**Tactic:** Initial Access | **Technique:** T1078.004 (Valid Accounts: Cloud Accounts)

| Test Type | Description |
|-----------|-------------|
| Positive | Any API call with `userIdentity.type = Root` is ingested, confirming the alert fires regardless of the specific API or whether MFA was used. |
| Negative | The same API calls (e.g., `DescribeInstances`, `ListBuckets`) are made by an IAM user or assumed role, confirming no alert is generated when the identity type is not root. |
| Edge | Root account activity occurs with MFA enabled and the session includes `mfaAuthenticated: true`; validates whether the detection correctly fires even for MFA-protected root sessions, and documents the expected behavior for planned root access (e.g., billing changes). |

**Known Gaps / Limitations:**
- No suppression is applied by design; all root activity is treated as suspicious. This will generate alerts for planned legitimate root actions (e.g., billing, support plan changes) that require an operational runbook to acknowledge.
- AWS-service-initiated events that appear with root identity type are rare but documented as a potential false positive source.
- No benign dataset for root account activity exists by definition (all root activity is out-of-policy in this environment).

---

### CDET-007 — EC2 Metadata Credential Abuse

**Tactic:** Credential Access | **Technique:** T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

| Test Type | Description |
|-----------|-------------|
| Positive | An EC2 instance role credential (session issuer type `EC2`) is used to make an API call from an external IP address not in the AWS IP range and not in `approved_egress_ips`, confirming the alert fires. |
| Negative | The same EC2 instance role makes API calls from an internal AWS IP address (within known EC2 egress ranges) or from a known instance IP, confirming no alert is generated. |
| Edge | The EC2 role credential is used from a corporate NAT gateway IP that is shared between internal and external traffic; validates whether the `approved_egress_ips` lookup correctly suppresses legitimate shared-egress IPs and documents the risk of over-suppression. |

**Known Gaps / Limitations:**
- The `approved_egress_ips` lookup must be maintained as NAT gateway EIPs are added or changed; stale entries create false negatives and stale absences create false positives.
- If the lookup does not exist or is empty, any EC2 role call from a NAT gateway IP will generate a false positive.
- GuardDuty `InstanceCredentialExfiltration` findings are a complementary signal but are not required for this detection to fire — the detection can operate on CloudTrail alone.

---

### CDET-008 — Excessive API Enumeration

**Tactic:** Discovery | **Technique:** T1580 (Cloud Infrastructure Discovery)

| Test Type | Description |
|-----------|-------------|
| Positive | A principal makes 55 total API calls spanning 7 unique API names within a 2-hour window, exceeding both thresholds (`total_calls >= 50` AND `unique_api_calls >= 5`), confirming the alert fires. |
| Negative | A principal exceeds total call count (60 calls) but uses only 3 unique API names, or uses 6 unique APIs but only 30 total calls — neither case meets both threshold conditions simultaneously, confirming no alert. |
| Edge | A principal makes exactly 50 total calls with exactly 5 unique API names (the boundary values); validates that the SPL uses `>=` comparisons rather than `>` so that the boundary case correctly fires. |

**Known Gaps / Limitations:**
- High-volume automation principals (e.g., monitoring agents, Config recorders) must be pre-populated in the `enumeration_suppression_arns` lookup before deployment or the detection generates significant noise.
- The 2-hour lookback window means a slow-and-low reconnaissance pattern that stays just below the per-window threshold will not be detected.
- Threshold values (50 total / 5 unique) are heuristic and should be tuned per environment based on baseline API usage volumes.

---

### CDET-009 — S3 Replication to External Account

**Tactic:** Exfiltration | **Technique:** T1537 (Transfer Data to Cloud Account)

| Test Type | Description |
|-----------|-------------|
| Positive | `PutBucketReplication` is called with a `Destination.Account` field containing an account ID not in the `approved_replication_accounts` lookup, confirming the alert fires. |
| Negative | A replication rule is configured with a destination bucket in the same account or in an approved partner account (present in `approved_replication_accounts`), confirming no alert is generated. |
| Edge | A replication rule is set without an explicit `Account` field in the destination (the account is implied by the bucket ARN ownership); validates whether the SPL falls back to parsing the account ID from the bucket ARN or whether this is a detection gap. |

**Known Gaps / Limitations:**
- If the replication configuration omits the explicit `Account` field and the SPL only checks that field, external replication to a bucket owned by a different account will not be detected — this is a documented gap requiring ARN-based account extraction as a fallback.
- Multi-rule replication configurations (some internal, some external) may cause the detection to partially match; the SPL must be validated to flag any rule containing an external destination, not just the first rule.
- `approved_replication_accounts` must include all legitimate third-party backup and DR accounts before deployment.

---

### CDET-010 — Mass S3 Object Deletion

**Tactic:** Impact | **Technique:** T1485 (Data Destruction)

| Test Type | Description |
|-----------|-------------|
| Positive | A principal performs `DeleteObjects` requests totaling 120 estimated objects deleted within the lookback window (exceeding the `estimated_objects_deleted >= 100` threshold), confirming the alert fires. |
| Negative | A principal with a session ARN in `deletion_suppression_arns` (an approved lifecycle automation role) performs bulk deletions well above the threshold, confirming suppression works correctly and no alert is generated. |
| Edge | A principal deletes exactly 100 estimated objects (`estimated_objects_deleted = 100`) and exactly 20 `DeleteObject`/`DeleteObjects` events (`total_delete_events = 20`); validates that the SPL uses `>=` for both thresholds so that boundary values fire correctly. |

**Known Gaps / Limitations:**
- `DeleteBucket` destroys all objects in the bucket in a single event; `estimated_objects_deleted` may show 0 for this call depending on SPL field extraction, creating a gap where catastrophic single-call bucket deletion is missed.
- The thresholds (100 objects, 20 events) require environment-specific tuning; the defaults are conservative for small environments but may be too low for environments with large-scale automated cleanup jobs.
- No benign dataset covering normal S3 lifecycle expiration patterns; negative test relies only on the suppression-lookup case.

---

### CDET-011 — Unauthorized Compute Launch

**Tactic:** Impact | **Technique:** T1496 (Resource Hijacking)

| Test Type | Description |
|-----------|-------------|
| Positive | `RunInstances` is called by a principal not in `approved_compute_principals` using a GPU instance type (e.g., `p3.8xlarge`) in `suspicious_instance_types`, confirming the alert fires at high severity. |
| Negative | `RunInstances` is called by a principal present in `approved_compute_principals` regardless of instance type, confirming suppression works and no alert is generated. |
| Edge | An unapproved principal launches a standard, non-suspicious instance type (e.g., `t3.micro`); validates whether the detection still fires (unapproved principal is sufficient) or requires a suspicious instance type (potential gap if only instance-type logic is evaluated). |

**Known Gaps / Limitations:**
- An approved compute principal launching in an unusual or non-standard AWS region is a documented detection gap for this rule; region anomaly detection requires a separate complementary detection.
- `CreateFunction` (Lambda) is listed as an in-scope event but Lambda cold-starts may generate different field structures than EC2 `RunInstances`; both must be validated separately.
- `suspicious_instance_types` lookup must be actively maintained as AWS releases new GPU, HPC, and inference instance families.

---

### CDET-012 — Cross Account AssumeRole Chain

**Tactic:** Lateral Movement | **Technique:** T1550.001 (Use Alternate Authentication Material: Application Access Token)

| Test Type | Description |
|-----------|-------------|
| Positive | `AssumeRole` is called targeting a role ARN in an account not present in `approved_assume_targets`, confirming the alert fires; a subsequent chained `AssumeRole` from the assumed session escalates severity to critical. |
| Negative | `AssumeRole` targets a role ARN and account ID both present in `approved_assume_targets`, or the role assumption is within the same account, confirming no alert is generated. |
| Edge | A role assumption chain proceeds from Account A to Account B and then back to Account A (boomerang pattern); validates that the detection correctly tracks the intermediate external-account hop and does not suppress because the final account is the origin account. |

**Known Gaps / Limitations:**
- Severity escalation for chained assumptions requires correlating multiple `AssumeRole` events across a time window; if the SPL correlation window is too short, multi-hop chains may only generate a single low-severity alert.
- The `approved_assume_targets` lookup must include all legitimate cross-account roles (e.g., shared services accounts, security tooling accounts) to avoid alert fatigue from routine multi-account operations.
- No benign dataset covering AWS Organizations cross-account role delegation patterns (e.g., AWS Control Tower enrollment).

---

### CDET-013 — Security Group Opened to Internet

**Tactic:** Defense Evasion | **Technique:** T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)

| Test Type | Description |
|-----------|-------------|
| Positive | `AuthorizeSecurityGroupIngress` is called adding a rule from `0.0.0.0/0` on port 22 (SSH), confirming the alert fires at critical severity with `high_risk_port = true`. |
| Negative | A security group ingress rule is added from a specific CIDR (e.g., `10.0.0.0/8`) rather than `0.0.0.0/0`, or the rule is added by a principal in `approved_sg_principals` for a security group in `approved_public_sg`, confirming no alert. |
| Edge | A security group rule is added with port range `0–65535` from `0.0.0.0/0`; validates that the SPL checks whether any high-risk port falls within the `from_port` to `to_port` range (not just exact port equality) so the alert fires at critical severity. |

**Known Gaps / Limitations:**
- If the SPL uses exact port matching rather than range overlap evaluation, a rule opening ports `0–65535` may not set `high_risk_port = true` — this is a known potential SPL bug that must be validated.
- IPv6 wildcard (`::/ 0`) must be handled separately from IPv4 `0.0.0.0/0`; the detection must be validated for both address families.
- `approved_public_sg` and `approved_sg_principals` lookups require maintenance as public-facing infrastructure is added (load balancers, CDN origins, bastion hosts).
- No benign baseline dataset for normal infrastructure-as-code security group management patterns.

---

### CDET-014 — CloudTrail Log Deleted from S3

**Tactic:** Defense Evasion | **Technique:** T1070.004 (Indicator Removal: File Deletion)

| Test Type | Description |
|-----------|-------------|
| Positive | `DeleteObject` is called on a key matching the CloudTrail log path pattern (e.g., `AWSLogs/*/CloudTrail/*`) in a bucket present in the `cloudtrail_log_buckets` lookup, by a non-AWS-service principal, confirming the alert fires. |
| Negative | `DeleteObject` is called on a non-CloudTrail S3 bucket, or the deletion is triggered by an AWS service principal (e.g., lifecycle expiration with `eventSource: s3.amazonaws.com` and service-managed identity), confirming no alert is generated. |
| Edge | A CloudTrail log file is deleted from a newly created trail bucket that has not yet been added to the `cloudtrail_log_buckets` lookup; documents this as a detection gap and validates the operational process for keeping the lookup current. |

**Known Gaps / Limitations:**
- Newly created CloudTrail trail buckets that are not yet in the `cloudtrail_log_buckets` lookup will not be covered; an operational process must exist to update the lookup whenever a new trail is created (complemented by CDET-003/CDET-005 detections that would alert on the trail creation itself).
- Approved principals performing legitimate CloudTrail log retention management may generate false positives if the `cloudtrail_log_buckets` bucket is used for purposes beyond CloudTrail delivery.
- S3 server-side replication delete markers are not the same as true object deletion; the detection must be validated to distinguish between delete markers and permanent deletions.

---

## 3. Validation Coverage Statistics

*As of 2026-06-18*

### Counts

| Metric | Value |
|--------|-------|
| Total detections in scope | 14 |
| Detections in Testing status | 14 |
| Detections promoted to production | 0 |
| Malicious sample log files created | 14 |
| Benign baseline sample log files created | 4 |
| Edge-case sample log files created | 14 |
| Total sample log files | 32 |
| Test cases defined (positive) | 14 |
| Test cases defined (negative) | 14 |
| Test cases defined (edge) | 14 |
| **Total test cases defined** | **42** |
| Test cases Splunk-validated | 0 |
| Detections with documented gaps | 14 |

### Coverage Formula Reference

The formulas below are defined in full detail in `docs/coverage_reporting/validation_metrics.md`.

```
Test Definition Coverage   = test_cases_defined / total_test_cases_planned
                           = 42 / 42 = 100%

Sample Data Coverage       = sample_logs_created / total_detections
                           = 32 / 42 ≈ 76%   (benign baseline only 4 of 14)

Splunk Validation Coverage = test_cases_splunk_validated / test_cases_defined
                           = 0 / 42 = 0%     (requires live Splunk environment)

Detection Promotion Rate   = detections_in_production / total_detections
                           = 0 / 14 = 0%     (all detections in Testing phase)
```

### Benign Baseline Coverage Gap

Only 4 of 14 detections have a dedicated benign baseline log file. The 10 detections without a standalone benign dataset are:

| CDET ID | Detection Name | Gap |
|---------|---------------|-----|
| CDET-001 | IAM User Created Outside Pipeline | No benign baseline; negative test uses suppression lookup only |
| CDET-003 | CloudTrail Logging Disabled | No benign baseline; negative test is a structurally different API call |
| CDET-005 | Cross Account Role Trust Modified | No benign baseline covering AWS Organizations StackSets delegation |
| CDET-006 | Root Account Activity | No benign baseline by design (all root activity is out-of-policy) |
| CDET-008 | Excessive API Enumeration | No benign baseline covering monitoring/Config agent API volumes |
| CDET-009 | S3 Replication to External Account | No benign baseline for approved partner-account replication |
| CDET-011 | Unauthorized Compute Launch | No benign baseline for approved multi-region compute operations |
| CDET-012 | Cross Account AssumeRole Chain | No benign baseline for AWS Organizations cross-account patterns |
| CDET-013 | Security Group Opened to Internet | No benign baseline for IaC-managed security group provisioning |
| CDET-014 | CloudTrail Log Deleted from S3 | No benign baseline for approved retention management |

---

## 4. Open Items and Known Gaps

### P1 — Blocking (Must resolve before production promotion)

| ID | Detection | Gap Description | Recommended Resolution |
|----|-----------|----------------|----------------------|
| GAP-001 | CDET-009 | Replication rules without explicit `Account` field are not detected; account must be inferred from bucket ARN | Add ARN-based account extraction to SPL as fallback; validate with edge case log |
| GAP-002 | CDET-014 | Newly created CloudTrail trail buckets not in `cloudtrail_log_buckets` lookup are not covered | Create operational runbook to update lookup on every `CreateTrail` event; add automation hook |
| GAP-003 | CDET-013 | SPL may use exact port matching rather than range overlap; rules opening 0–65535 may not set `high_risk_port = true` | Validate SPL range-overlap logic against edge case log; fix if confirmed |
| GAP-004 | CDET-010 | `DeleteBucket` may report `estimated_objects_deleted = 0`, missing catastrophic single-call bucket deletion | Add explicit `DeleteBucket` event-name condition to SPL as a high-severity independent branch |
| GAP-005 | CDET-002 | Automation role suppression may take precedence over privileged-target trigger, creating a bypass | Validate SPL operator precedence; ensure privileged target check fires even when automation role is the caller |

### P2 — Significant (Should resolve before production promotion)

| ID | Detection | Gap Description | Recommended Resolution |
|----|-----------|----------------|----------------------|
| GAP-006 | CDET-001 | Compromised pipeline role creates IAM user without triggering detection (suppressed on role ARN) | Add complementary detection for pipeline role used outside expected IaC workflow context |
| GAP-007 | CDET-007 | `approved_egress_ips` lookup requires active maintenance; stale entries produce false positives or negatives | Define a quarterly lookup review process; tie to network change management |
| GAP-008 | CDET-004 | `PowerUserAccess` and other near-admin policies are not covered by `admin_policy_arns` lookup | Audit and extend `admin_policy_arns` to include near-admin managed policies |
| GAP-009 | CDET-008 | High-volume automation principals not pre-populated in `enumeration_suppression_arns` will cause noise | Document baseline API call volumes for known automation principals before deployment |
| GAP-010 | CDET-011 | Approved compute principal launching in unusual region is not detected | Add region anomaly logic as an additional severity modifier or create CDET-015 for region anomalies |
| GAP-011 | CDET-012 | Short correlation window may miss multi-hop chains that span more than one lookback period | Validate lookback window length against realistic attack simulation timing |

### P3 — Low Priority (Backlog)

| ID | Detection | Gap Description |
|----|-----------|----------------|
| GAP-012 | All | Splunk validation (0 of 42 test cases run) is blocked pending live Splunk environment with lookup tables deployed |
| GAP-013 | CDET-003 | Legitimate Terraform cost-optimization disabling multi-region trail collection produces false positives; needs per-trail-ARN exception documentation |
| GAP-014 | CDET-005 | `CreateRole` event path differences from `UpdateAssumeRolePolicy` not yet validated separately |
| GAP-015 | CDET-006 | Need operational runbook for planned root access acknowledgment to prevent analyst fatigue |
| GAP-016 | CDET-013 | IPv6 wildcard (`::/0`) handling not yet validated; detection may only evaluate IPv4 `0.0.0.0/0` |
| GAP-017 | All | 10 of 14 detections have no dedicated benign baseline log file; negative tests rely only on suppression-lookup behavior |

### Missing Lookup Tables (Required Before Splunk Validation)

The following lookup tables must be created and populated in Splunk before any test case can be executed against a live environment:

| Lookup Table | Required By |
|-------------|-------------|
| `approved_iam_principals` | CDET-001, CDET-004 |
| `automation_role_arns` | CDET-001, CDET-002 |
| `privileged_users` | CDET-002 |
| `admin_policy_arns` | CDET-004 |
| `approved_external_accounts` | CDET-005 |
| `approved_egress_ips` | CDET-007 |
| `enumeration_suppression_arns` | CDET-008 |
| `approved_replication_accounts` | CDET-009 |
| `deletion_suppression_arns` | CDET-010 |
| `approved_compute_principals` | CDET-011 |
| `suspicious_instance_types` | CDET-011 |
| `approved_assume_targets` | CDET-012 |
| `high_risk_ports` | CDET-013 |
| `approved_sg_principals` | CDET-013 |
| `approved_public_sg` | CDET-013 |
| `cloudtrail_log_buckets` | CDET-014 |

---

*End of Validation Matrix v1.0.0 — 2026-06-18*
