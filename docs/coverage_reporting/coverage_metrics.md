# Detection Coverage Metrics

**Version:** 1.0.0
**Date:** 2026-06-18
**Owner:** Detection Engineering
**Audience:** Detection engineers, security operations lead, CISO
**Reporting Cadence:** Weekly team summary, Monthly executive report, Quarterly gap review

---

## Coverage Metrics Overview

### Purpose

This document defines the formal metrics program for the Cloud Threat Detection Lab. Each metric provides a quantitative answer to a specific quality or completeness question about the detection catalog. Metrics are computed automatically via Splunk saved searches and reviewed at the cadences defined in the [Reporting Cadence](#reporting-cadence) section.

Coverage metrics answer: *"Are we detecting the full threat landscape we committed to covering?"*

Validation metrics (see [`validation_metrics.md`](validation_metrics.md)) answer: *"Do individual detections work correctly when real or simulated events occur?"*

### Audience

| Role | Metrics Consumed | Primary Questions |
|------|-----------------|-------------------|
| Detection Engineer | All 5 metrics, gap analysis | Which CDETs are not yet active? Where are the ATT&CK gaps? |
| Security Operations Lead | Metrics 1–3, MTTV | Is the program on pace? Are data sources covered? |
| CISO / Executive | Metric 1, Metric 2 tactic table, SLO dashboard | What percentage of defined threats do we detect? |

### Reporting Cadence

| Report | Audience | Frequency | Day/Time | Splunk Saved Search |
|--------|----------|-----------|----------|---------------------|
| Detection Coverage Summary | Detection Eng team | Weekly | Monday 08:00 | `CDET-CoverageReport-Weekly` |
| ATT&CK Technique Breakdown | Detection Eng + Sec Ops | Weekly | Monday 08:00 | `CDET-ATTACKTechniquesCovered` |
| Tactic Coverage Breakdown | Security Ops Lead | Monthly | 1st of month | `CDET-TacticCoverageBreakdown` |
| Data Source Coverage | Security Ops Lead | Monthly | 1st of month | `CDET-DataSourceCoverage` |
| Executive Coverage Summary | CISO | Monthly | 1st of month | `CDET-MonthlyExecutiveSummary` |
| Coverage Gap Analysis | Detection Eng team | Quarterly | Quarter-end | `CDET-CoverageGapAnalysis` |

All saved searches reside in `splunk/savedsearches/coverage_reporting.conf`.

---

## Metric 1: Detection Coverage %

### Definition

The percentage of defined threat scenarios (CDETs in the detection catalog) that have been promoted to `status: active` in their `detection.yaml` and deployed to Splunk.

### Formula

```
Detection Coverage % = (Active Detections / Total Defined Threat Scenarios) × 100
```

**Numerator:** Count of `detection.yaml` files where `status: active`. A detection qualifies as active only when its Splunk saved search is deployed, validated against at least one positive test case, and the `detection.yaml` status field is updated to `active`.

**Denominator:** Total CDETs listed in `docs/detection_catalog.md`. Every merged detection YAML at any status contributes to this count.

### Target

≥80% of defined CDETs must reach Active status within 90 days of their creation date.

### Current State (2026-06-18)

| Field | Value |
|-------|-------|
| Total CDETs defined | 14 |
| Status: `active` | 0 |
| Status: `testing` | 14 |
| Status: `deprecated` | 0 |
| **Detection Coverage %** | **0%** |

All 14 detections are in `testing` state. SPL queries, test cases, and sample log data are complete. Promotion to `active` requires a live Splunk environment with CloudTrail ingestion, which is the Phase 3 deployment milestone.

### Calculation Examples

```
Current state:
  Detection Coverage % = (0 / 14) × 100 = 0.0%

After 7 promotions (halfway target):
  Detection Coverage % = (7 / 14) × 100 = 50.0%

At 80% target threshold:
  Detection Coverage % = (12 / 14) × 100 = 85.7%  [meets target]
  Detection Coverage % = (11 / 14) × 100 = 78.6%  [below target — warning threshold]
```

### SPL Saved Search Reference

```spl
| inputlookup detection_catalog.csv
| stats count as total_detections,
        count(eval(status="active")) as active_detections
| eval detection_coverage_pct = round((active_detections / total_detections) * 100, 1)
| eval status = case(
    detection_coverage_pct >= 80, "PASS",
    detection_coverage_pct >= 60, "WARNING",
    true(), "CRITICAL")
| table total_detections active_detections detection_coverage_pct status
```

*(Reference: `splunk/savedsearches/coverage_reporting.conf` search stanza `[CDET-CoverageReport-Weekly]`)*

---

## Metric 2: ATT&CK Coverage %

### Definition

The percentage of distinct MITRE ATT&CK techniques in scope (as defined by the detection catalog) that have at least one Active detection mapped to them.

### Formula

```
ATT&CK Coverage % = (Distinct Techniques With ≥1 Active Detection / Total Techniques in Scope) × 100
```

**Numerator:** Distinct `technique_id` values drawn from `detection.yaml` files where `status: active`.

**Denominator:** All distinct technique IDs present in the detection catalog across all CDETs at any status. Secondary techniques (mapped via `secondary_techniques`) count toward denominator and numerator.

### Current Technique Mapping (All 14 CDETs)

| CDET | Technique ID | Sub-Technique | Technique Name | Tactic |
|------|-------------|---------------|----------------|--------|
| CDET-001 | T1136 | T1136.003 | Create Account: Cloud Account | Persistence |
| CDET-002 | T1098 | T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence |
| CDET-003 | T1562 | T1562.008 | Impair Defenses: Disable Cloud Logs | Defense Evasion |
| CDET-004 | T1078 | T1078.004 | Valid Accounts: Cloud Accounts | Privilege Escalation |
| CDET-004 (secondary) | T1098 | T1098.003 | Account Manipulation: Additional Cloud Roles | Privilege Escalation |
| CDET-005 | T1484 | T1484.002 | Domain or Tenant Policy Modification: Trust Modification | Privilege Escalation |
| CDET-006 | T1078 | T1078.004 | Valid Accounts: Cloud Accounts | Initial Access |
| CDET-006 (secondary) | T1078 | T1078.003 | Valid Accounts: Local Accounts | Initial Access |
| CDET-007 | T1552 | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential Access |
| CDET-008 | T1580 | — | Cloud Infrastructure Discovery | Discovery |
| CDET-008 (secondary) | T1087 | T1087.004 | Account Discovery: Cloud Account | Discovery |
| CDET-009 | T1537 | — | Transfer Data to Cloud Account | Exfiltration |
| CDET-010 | T1485 | — | Data Destruction | Impact |
| CDET-011 | T1496 | — | Resource Hijacking | Impact |
| CDET-012 | T1550 | T1550.001 | Use Alternate Authentication Material: Application Access Token | Lateral Movement |
| CDET-013 | T1562 | T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |
| CDET-014 | T1070 | T1070.004 | Indicator Removal: File Deletion | Defense Evasion |

**Distinct primary technique IDs in scope:** T1136, T1098, T1562, T1078, T1484, T1552, T1580, T1537, T1485, T1496, T1550, T1070, T1087, T1484 — **14 distinct technique IDs** (13 primary + T1087 from CDET-008 secondary).

### Tactic-Level Breakdown

| Tactic | CDET Count | Techniques Covered | Target (≥1 technique) | Current Active |
|--------|------------|-------------------|----------------------|----------------|
| Persistence | 2 | T1136.003, T1098.001 | Yes (2 techniques) | 0 active |
| Defense Evasion | 3 | T1562.008, T1562.007, T1070.004 | Yes (3 techniques) | 0 active |
| Privilege Escalation | 2 | T1078.004, T1484.002 | Yes (2 techniques) | 0 active |
| Initial Access | 1 | T1078.004 | Yes (1 technique) | 0 active |
| Credential Access | 1 | T1552.005 | Yes (1 technique) | 0 active |
| Discovery | 1 | T1580, T1087.004 | Yes (2 techniques) | 0 active |
| Exfiltration | 1 | T1537 | Yes (1 technique) | 0 active |
| Impact | 2 | T1485, T1496 | Yes (2 techniques) | 0 active |
| Lateral Movement | 1 | T1550.001 | Yes (1 technique) | 0 active |

**Total represented tactics: 9**

### Current State (2026-06-18)

| Field | Value |
|-------|-------|
| Distinct techniques in scope | 14 |
| Tactics represented | 9 |
| Techniques with Active detection | 0 |
| **ATT&CK Coverage %** | **0%** |

### Target

- All 9 represented tactics must have at least 1 Active detection.
- Overall ATT&CK Coverage % must reach ≥75% of in-scope techniques within 90 days.

### Calculation Example

```
After all 14 CDETs promoted to Active:
  ATT&CK Coverage % = (14 / 14) × 100 = 100%

At minimum acceptable coverage (11 of 14 techniques active):
  ATT&CK Coverage % = (11 / 14) × 100 = 78.6%  [meets ≥75% target]
```

### SPL Saved Search Reference

```spl
| inputlookup detection_catalog.csv
| where status="active"
| dedup technique_id
| stats count as techniques_covered
| appendcols
    [ | inputlookup detection_catalog.csv
    | dedup technique_id
    | stats count as total_techniques_in_scope ]
| eval attack_coverage_pct = round((techniques_covered / total_techniques_in_scope) * 100, 1)
| table techniques_covered total_techniques_in_scope attack_coverage_pct
```

*(Reference: `splunk/savedsearches/coverage_reporting.conf` stanzas `[CDET-ATTACKTechniquesCovered]` and `[CDET-TacticCoverageBreakdown]`)*

---

## Metric 3: Data Source Coverage %

### Definition

The percentage of available security data sources in scope that have at least one Active detection ingesting events from them.

### Formula

```
Data Source Coverage % = (Data Sources With ≥1 Active Detection / Total Available Data Sources in Scope) × 100
```

**Numerator:** Count of distinct `data_sources` values from `detection.yaml` files where `status: active`.

**Denominator:** Total distinct data source identifiers defined in the lab scope, regardless of whether any detection references them.

### Data Sources in Scope

| Data Source | Splunk Index | Sourcetype | CDETs Using It | Role |
|-------------|-------------|------------|---------------|------|
| AWS CloudTrail | `aws_cloudtrail` | `aws:cloudtrail:normalized` | CDET-001 through CDET-014 (all 14) | Primary telemetry — all API call activity |
| AWS GuardDuty | `aws_guardduty` | `aws:guardduty` | CDET-007 (secondary correlation) | Threat intelligence enrichment for credential abuse |
| AWS Security Hub | `aws_securityhub` | `aws:securityhub` | Cross-detection enrichment reference | Compliance posture and aggregated findings |
| VPC Flow Logs | `aws_vpc_flow` | `aws:vpc:flow` | Planned (Phase 4+) | Network-layer lateral movement and exfiltration |

**Total data sources in scope: 4**

### Current State (2026-06-18)

| Data Source | Detections Defined | Active Detections | Covered (Active) |
|-------------|-------------------|------------------|-----------------|
| CloudTrail | 14 | 0 | No |
| GuardDuty | 1 (CDET-007 correlation) | 0 | No |
| Security Hub | Reference enrichment only | 0 | No |
| VPC Flow Logs | 0 (planned Phase 4) | 0 | No |
| **Total** | **14+** | **0** | **0 / 4** |

**Data Source Coverage % = 0%** (pending Phase 3 promotion to active).

### Target

- CloudTrail and GuardDuty must both reach "covered" status (≥1 Active detection each) within Phase 3.
- Security Hub coverage (active detection consuming it) is a Phase 4 goal.
- VPC Flow Logs coverage is a Phase 4+ goal.
- **Minimum acceptable at 90-day mark: 2 of 4 sources = 50%.**

### Calculation Example

```
After CDET-001 through CDET-014 promoted to Active:
  CloudTrail = covered (14 active detections)
  GuardDuty  = covered (CDET-007 active)
  Security Hub = not covered (reference only, no active detection)
  VPC Flow Logs = not covered (not yet defined)

  Data Source Coverage % = (2 / 4) × 100 = 50%
```

### SPL Saved Search Reference

```spl
| inputlookup detection_catalog.csv
| where status="active"
| mvexpand data_sources
| stats dc(id) as active_detection_count by data_sources
| rename data_sources as data_source
| eval covered = if(active_detection_count > 0, 1, 0)
| appendcols
    [ | makeresults
    | eval data_source="VPC Flow Logs", active_detection_count=0, covered=0
    | append
        [ | makeresults
        | eval data_source="Security Hub", active_detection_count=0, covered=0 ] ]
| stats sum(covered) as sources_covered, count as total_sources
| eval data_source_coverage_pct = round((sources_covered / total_sources) * 100, 1)
| table sources_covered total_sources data_source_coverage_pct
```

*(Reference: `splunk/savedsearches/coverage_reporting.conf` stanza `[CDET-DataSourceCoverage]`)*

---

## Metric 4: Validation Pass Rate %

### Definition

The percentage of test cases that produce the expected outcome when executed against a detection in Splunk. A test case passes when:

- **Positive test:** the detection fires (alert generated) when the simulated malicious event is ingested.
- **Negative test:** the detection does not fire when a benign/approved event is ingested.
- **Edge test:** the detection behaves correctly for a boundary or ambiguous scenario.

### Formula

```
Validation Pass Rate % = (Test Cases Passing / Total Test Cases Executed) × 100
```

Separate pass rates are tracked and SLO'd independently:

| Test Category | Formula | Target |
|---------------|---------|--------|
| Positive Pass Rate | (Positive tests passing / Total positive tests) × 100 | 100% |
| Negative Pass Rate | (Negative tests passing / Total negative tests) × 100 | 100% |
| Edge Pass Rate | (Edge tests passing / Total edge tests) × 100 | ≥80% |
| **Overall Pass Rate** | (All passing / All executed) × 100 | **≥95%** |

### Test Case Inventory (Expected After Phase 3 Deployment)

Each CDET is expected to have at minimum 3 test cases (1 positive, 1 negative, 1 edge). Specific counts per CDET are tracked in `docs/validation/validation_matrix.md`.

| Category | Expected Count | Minimum Pass Count for Target |
|----------|---------------|-------------------------------|
| Positive tests | 14 (1 per CDET) | 14 / 14 = 100% |
| Negative tests | 14 (1 per CDET) | 14 / 14 = 100% |
| Edge tests | 14 (1 per CDET) | 12 / 14 = 85.7% (≥80%) |
| **Total** | **42** | **≥40 / 42 = ≥95%** |

### Current State (2026-06-18)

No validation runs executed. Requires live Splunk environment with CloudTrail ingestion (Phase 3 prerequisite). All test case definitions exist in detection YAML files and associated test scripts.

### SPL Saved Search Reference

```spl
| inputlookup validation_results.csv
| stats count as total_tests,
        count(eval(result="pass")) as passing_tests,
        count(eval(result="fail")) as failing_tests
        by test_type
| eval pass_rate_pct = round((passing_tests / total_tests) * 100, 1)
| eval slo_target = case(
    test_type="positive", 100,
    test_type="negative", 100,
    test_type="edge", 80,
    true(), 95)
| eval slo_status = if(pass_rate_pct >= slo_target, "PASS", "FAIL")
| table test_type total_tests passing_tests failing_tests pass_rate_pct slo_target slo_status
```

*(Reference: `splunk/savedsearches/coverage_reporting.conf` stanza `[CDET-ValidationPassRate]`)*

---

## Metric 5: Mean Time to Validate (MTTV)

### Definition

The average number of calendar days from a detection's creation date to the date it reaches `status: active`. This metric measures the engineering velocity of the detection promotion pipeline.

### Formula

```
MTTV (days) = Sum(validation_completed_date - detection_created_date) / N

Where:
  validation_completed_date = date the detection.yaml status was changed to "active"
  detection_created_date    = value of the "created" field in detection.yaml
  N                         = count of detections that have been promoted to Active
```

### Target

≤14 calendar days from detection creation date to Active status promotion.

### Date Fields Used

Each `detection.yaml` contains:

- `created` — set at authoring time; never changes.
- `modified` — updated on every change; set to the promotion date when status changes to `active`.

When `status: active` is recorded, the diff between `modified` and `created` is the per-detection validation cycle time.

### Current State (2026-06-18)

MTTV is undefined — no detections have been promoted to Active status. The earliest CDET creation dates will anchor the measurement once Phase 3 promotion begins.

**Projected MTTV risk:** All 14 CDETs were created during Phase 1/Phase 2 development. If Phase 3 promotion occurs more than 14 days after creation, CDETs may breach the MTTV SLO. This is an expected portfolio-lab condition rather than an operational failure, since Phase 3 depends on a deployed AWS environment rather than individual engineering throughput.

### Calculation Example

```
Suppose 3 CDETs are promoted on 2026-07-01:
  CDET-001 created 2026-06-01, promoted 2026-07-01 → 30 days
  CDET-002 created 2026-06-05, promoted 2026-07-01 → 26 days
  CDET-003 created 2026-06-08, promoted 2026-07-01 → 23 days

MTTV = (30 + 26 + 23) / 3 = 26.3 days  [exceeds 14-day target — SLO breach]

If promoted within 14 days of creation:
  CDET-001 promoted 2026-06-15 → 14 days
  CDET-002 promoted 2026-06-19 → 14 days
  CDET-003 promoted 2026-06-22 → 14 days

MTTV = (14 + 14 + 14) / 3 = 14.0 days  [meets SLO exactly]
```

### SPL Saved Search Reference

```spl
| inputlookup detection_catalog.csv
| where status="active"
| eval created_epoch    = strptime(created_date, "%Y-%m-%d")
| eval promoted_epoch   = strptime(promoted_date, "%Y-%m-%d")
| eval days_to_validate = round((promoted_epoch - created_epoch) / 86400, 1)
| stats avg(days_to_validate) as mttv_days,
        max(days_to_validate) as max_days,
        min(days_to_validate) as min_days,
        count as promotions_measured
| eval slo_status = if(mttv_days <= 14, "PASS", "BREACH")
| table mttv_days max_days min_days promotions_measured slo_status
```

*(Reference: `splunk/savedsearches/coverage_reporting.conf` stanza `[CDET-MTTV]`)*

---

## Coverage Gap Analysis

### ATT&CK Tactics With Zero Coverage (as of 2026-06-18)

The following standard ATT&CK for Cloud tactics have no CDETs defined in the current catalog. These represent gaps relative to the full MITRE ATT&CK Enterprise matrix.

| Tactic | Reason for Gap | Recommended Future Detection | Priority |
|--------|---------------|------------------------------|----------|
| Collection | Not scoped in Phase 1–3 | T1530 — Data from Cloud Storage (mass S3 GetObject) | High |
| Execution | Not scoped in Phase 1–3 | T1648 — Serverless Execution (Lambda invocation abuse) | Medium |
| Command and Control | Hard to detect via CloudTrail alone; requires VPC Flow Logs | T1071 — Application Layer Protocol over HTTPS | Medium |
| Reconnaissance | External recon not visible in CloudTrail; partial coverage via CDET-008 | T1595 — Active Scanning (requires perimeter data) | Low |

### ATT&CK Tactics With Only 1 Detection

These tactics are covered by a single CDET. Loss or failure of that detection would leave the tactic entirely undetected.

| Tactic | Single CDET | Technique | Risk if CDET Fails |
|--------|-------------|-----------|-------------------|
| Initial Access | CDET-006 | T1078.004 (Root Account Activity) | No coverage for console/API initial access |
| Credential Access | CDET-007 | T1552.005 (IMDS Credential Abuse) | No coverage for key theft or credential stuffing |
| Discovery | CDET-008 | T1580 / T1087.004 (API Enumeration) | No coverage for resource listing activity |
| Exfiltration | CDET-009 | T1537 (S3 Replication) | No coverage for data transfer out of account |
| Lateral Movement | CDET-012 | T1550.001 (AssumeRole Chain) | No coverage for cross-account pivoting |

**Recommendation:** After Phase 3 promotion, each single-CDET tactic should have a second detection authored to provide redundancy. Priority order: Credential Access, Lateral Movement, Initial Access.

### Tactics Meeting Multi-Detection Coverage

| Tactic | CDET Count | Status |
|--------|------------|--------|
| Defense Evasion | 3 (CDET-003, CDET-013, CDET-014) | Healthy — 3 distinct techniques covered |
| Persistence | 2 (CDET-001, CDET-002) | Acceptable — 2 distinct techniques covered |
| Privilege Escalation | 2 (CDET-004, CDET-005) | Acceptable — 2 distinct techniques covered |
| Impact | 2 (CDET-010, CDET-011) | Acceptable — 2 distinct techniques covered |

---

## Metric Thresholds and SLOs

| Metric | Green (Pass) | Yellow (Warning) | Red (Critical) | SLO Breach Action |
|--------|-------------|-----------------|----------------|-------------------|
| Detection Coverage % | ≥80% | 60–79% | <60% | Escalate to security ops lead; block new detections until gap closed |
| ATT&CK Coverage % | ≥75% | 55–74% | <55% | Gap analysis review; assign CDETs to uncovered techniques |
| Data Source Coverage % | ≥75% | 50–74% | <50% | Review data ingestion pipeline; confirm index availability |
| Positive Validation Pass Rate | 100% | 95–99% | <95% | Failing detection pulled from Active; root cause required within 24h |
| Negative Validation Pass Rate | 100% | 95–99% | <95% | Failing detection pulled from Active; false positive investigation required |
| Edge Validation Pass Rate | ≥80% | 65–79% | <65% | Engineering review; edge cases documented and triaged |
| Overall Validation Pass Rate | ≥95% | 85–94% | <85% | Detection program halt pending review |
| MTTV | ≤14 days | 15–21 days | >21 days | Engineering velocity review; backlog grooming required |

### SLO Measurement Period

All percentage-based SLOs are evaluated against a **rolling 90-day window** from the date of the oldest CDET creation. MTTV is computed as a cumulative average across all promoted detections.

---

## Splunk Saved Search Summary

All saved searches that populate these metrics are defined in `splunk/savedsearches/coverage_reporting.conf`. The following table maps each search stanza to the metric it populates.

| Search Stanza | Metric(s) Populated | Schedule |
|---------------|--------------------|---------:|
| `CDET-CoverageReport-Weekly` | Metric 1: Detection Coverage % | `0 8 * * 1` |
| `CDET-ATTACKTechniquesCovered` | Metric 2: ATT&CK Coverage % (technique level) | `0 8 * * 1` |
| `CDET-TacticCoverageBreakdown` | Metric 2: ATT&CK Coverage % (tactic breakdown) | `0 0 1 * *` |
| `CDET-DataSourceCoverage` | Metric 3: Data Source Coverage % | `0 0 1 * *` |
| `CDET-ValidationPassRate` | Metric 4: Validation Pass Rate % (all subtypes) | `0 8 * * 1` |
| `CDET-MTTV` | Metric 5: Mean Time to Validate | `0 0 1 * *` |
| `CDET-MonthlyExecutiveSummary` | Metrics 1, 2, 3 combined rollup | `0 0 1 * *` |
| `CDET-CoverageGapAnalysis` | Gap analysis — uncovered tactics and techniques | `0 0 1 1 *` |

---

## Related Documents

- [`validation_metrics.md`](validation_metrics.md) — Validation quality metrics (pass rate detail, per-CDET test results)
- [`../detection_coverage/coverage_matrix.md`](../detection_coverage/coverage_matrix.md) — Per-detection status matrix with promotion history
- [`../../splunk/savedsearches/`](../../splunk/savedsearches/) — Splunk saved search definitions
- [`../../docs/detection_catalog.md`](../../docs/detection_catalog.md) — Authoritative detection catalog (denominator source)
- [`../../docs/mitre_mapping/`](../../docs/mitre_mapping/) — ATT&CK tactic and technique mapping detail
- [`../../validation/validation_matrix.md`](../../validation/validation_matrix.md) — Test case status and pass/fail history
