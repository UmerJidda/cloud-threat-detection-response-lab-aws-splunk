# Detection Coverage Matrix

> This matrix is updated after each detection phase and validation run.
> Last updated: Phase 2 (Detection Engineering Library)
> Validation run: Not yet executed

---

## Status Legend

| Status | Meaning |
|--------|---------|
| Planned | Detection identified and mapped; not yet authored |
| Draft | Detection being authored; no test cases yet |
| Testing | SPL and test cases written; validation in progress |
| Active | Deployed to Splunk; all test cases pass |
| Deprecated | Retired; retained for reference |

## Validation Legend

| Validation Status | Meaning |
|------------------|---------|
| Not Tested | No validation run executed |
| Partial | Some test cases pass; others fail or missing |
| Passing | All test cases pass |
| Failing | One or more test cases fail |

---

## Full Coverage Matrix

| Detection ID | Detection Name | Data Source | ATT&CK Tactic | ATT&CK Technique | Severity | Confidence | Status | Validation Status |
|-------------|---------------|-------------|--------------|-----------------|---------|-----------|--------|------------------|
| CDET-001 | IAM User Created Outside Pipeline | CloudTrail | Persistence | T1136.003 | High | Medium | Testing | Not Tested |
| CDET-002 | IAM Access Key Created for Existing User | CloudTrail | Persistence | T1098.001 | High | Medium | Testing | Not Tested |
| CDET-003 | CloudTrail Logging Disabled | CloudTrail | Defense Evasion | T1562.008 | Critical | High | Testing | Not Tested |
| CDET-004 | Admin Policy Attached to Principal | CloudTrail | Privilege Escalation | T1078.004 | Critical | High | Testing | Not Tested |
| CDET-005 | Cross-Account Role Trust Modified | CloudTrail | Privilege Escalation | T1484.002 | High | Medium | Testing | Not Tested |
| CDET-006 | Root Account Activity | CloudTrail | Initial Access | T1078.004 | Critical | High | Testing | Not Tested |
| CDET-007 | EC2 Instance Metadata Credential Abuse | CloudTrail / GuardDuty | Credential Access | T1552.005 | High | High | Testing | Not Tested |
| CDET-008 | Excessive API Enumeration | CloudTrail | Discovery | T1580 | Medium | Medium | Testing | Not Tested |
| CDET-009 | S3 Replication to External Account | CloudTrail | Exfiltration | T1537 | High | High | Testing | Not Tested |
| CDET-010 | Mass S3 Object Deletion | CloudTrail | Impact | T1485 | Critical | High | Testing | Not Tested |
| CDET-011 | Unauthorized Compute Resource Launch | CloudTrail | Impact | T1496 | High | Medium | Testing | Not Tested |
| CDET-012 | Cross-Account AssumeRole Chain | CloudTrail | Lateral Movement | T1550.001 | High | Medium | Testing | Not Tested |
| CDET-013 | Security Group Opened to Public Internet | CloudTrail | Defense Evasion | T1562.007 | High/Critical | High | Testing | Not Tested |
| CDET-014 | CloudTrail Log File Deleted from S3 | CloudTrail | Defense Evasion | T1070.004 | Critical | High | Testing | Not Tested |

---

## Coverage by Tactic

| Tactic | Total Detections | Testing | Active | Coverage |
|--------|-----------------|---------|--------|---------|
| Initial Access | 1 | 1 | 0 | In Progress |
| Persistence | 2 | 2 | 0 | In Progress |
| Privilege Escalation | 2 | 2 | 0 | In Progress |
| Defense Evasion | 4 | 4 | 0 | In Progress |
| Credential Access | 1 | 1 | 0 | In Progress |
| Discovery | 1 | 1 | 0 | In Progress |
| Lateral Movement | 1 | 1 | 0 | In Progress |
| Exfiltration | 1 | 1 | 0 | In Progress |
| Impact | 2 | 2 | 0 | In Progress |
| **Total** | **14** | **14** | **0** | **In Progress** |

*Coverage % moves to Active after validation. Promotion requires passing all test cases per [`docs/detection_engineering/tuning_guidelines.md`](../detection_engineering/tuning_guidelines.md).*

---

## Coverage by Data Source

| Data Source | Total Detections | Notes |
|------------|-----------------|-------|
| CloudTrail | 14 | Primary detection data source |
| GuardDuty | 1 (shared with CloudTrail) | CDET-007 uses both |
| IAM (collector) | 0 | Used for posture, not real-time detection |
| Security Hub | 0 | Used for compliance tracking |
| Security Groups (collector) | 0 | Used for posture, not real-time detection |

---

## Coverage by Severity

| Severity | Count | % of Total |
|----------|-------|-----------|
| Critical | 5 | 36% |
| High | 8 | 57% |
| Medium | 1 | 7% |
| Low | 0 | 0% |

---

## Validation Progress

*No validation runs have been executed. All 14 detections are in Testing status as of Phase 2. Validation will be executed in Phase 3.*

| Run Date | Type | Detections Tested | Passed | Failed | Overall |
|----------|------|------------------|--------|--------|---------|
| — | — | — | — | — | — |

---

## Known Coverage Gaps

Techniques identified as relevant to this threat model that are not yet covered:

| Technique | Name | Gap Reason | Target Phase |
|-----------|------|-----------|-------------|
| T1087.004 | Account Discovery: Cloud Account | Overlaps with CDET-008; may be addressed as Tier 3 hunting query | Phase 6 |
| T1619 | Cloud Storage Object Discovery | High FP rate expected; Tier 3 hunt only | Phase 6 |
| T1530 | Data from Cloud Storage Object | Requires S3 access log ingestion not yet in scope | Phase 2+ |
| T1567.002 | Exfiltration to Cloud Storage | Requires S3 access log ingestion | Phase 2+ |
