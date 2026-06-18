# Validation Quality Metrics

**Version:** 1.0.0
**Last Updated:** 2026-06-18
**Owner:** Detection Engineering
**Reporting Cadence:** Per validation run + weekly aggregate

---

## Overview

Validation metrics measure whether each detection works correctly — whether it fires when it should, stays silent when it should, and produces complete alert output. These metrics are distinct from coverage metrics (which measure *what* is detected) — validation metrics measure *how well* it is detected.

**Relationship to coverage_metrics.md:** A detection is only counted in Detection Coverage % if it passes validation. A detection in Testing state with failing validation does not contribute to coverage.

---

## Metric 1: Positive Test Pass Rate

**Definition:** Percentage of positive test cases where the detection fires correctly on malicious sample data.

**Formula:**

```
Positive Pass Rate % = (Positive test cases that PASS / Total positive test cases executed) × 100
```

**Passing definition:** Detection fires, produces at least one alert, and all required fields in `expected_alert.json` are populated with correct values.

**Failure modes:**

| Failure Mode | Likely Cause | Remediation |
|-------------|-------------|-------------|
| Detection does not fire | SPL logic error, field name mismatch, wrong index | Review SPL against raw event field names |
| Wrong severity in alert | Severity eval logic incorrect | Review SPL `eval severity` expression |
| Missing required fields | `| table` statement incomplete | Add missing fields to `| table` clause |
| Wrong field values | Field extraction incorrect | Check `spath` or `rex` extraction commands |

**Per-detection tracking (as of 2026-06-18):**

| CDET ID | Detection Name | Positive Test Status | Last Run | Notes |
|---------|---------------|---------------------|----------|-------|
| CDET-001 | IAM User Created Outside Pipeline | Pending | — | Awaiting Splunk environment |
| CDET-002 | IAM Access Key Created for Existing User | Pending | — | — |
| CDET-003 | CloudTrail Logging Disabled | Pending | — | — |
| CDET-004 | Admin Policy Attached to Principal | Pending | — | — |
| CDET-005 | Cross Account Role Trust Modified | Pending | — | — |
| CDET-006 | Root Account Activity | Pending | — | — |
| CDET-007 | EC2 Metadata Credential Abuse | Pending | — | — |
| CDET-008 | Excessive API Enumeration | Pending | — | Count-based logic requires stats window |
| CDET-009 | S3 Replication to External Account | Pending | — | — |
| CDET-010 | Mass S3 Object Deletion | Pending | — | Count-based logic requires stats window |
| CDET-011 | Unauthorized Compute Launch | Pending | — | — |
| CDET-012 | Cross Account AssumeRole Chain | Pending | — | Multi-event correlation |
| CDET-013 | Security Group Opened to Internet | Pending | — | — |
| CDET-014 | CloudTrail Log Deleted from S3 | Pending | — | — |

**Target:** 100% positive test pass rate before any detection is promoted to Active.

---

## Metric 2: Negative Test Pass Rate

**Definition:** Percentage of negative test cases where the detection correctly does NOT fire on suppressed or benign data.

**Formula:**

```
Negative Pass Rate % = (Negative test cases that PASS / Total negative test cases executed) × 100
```

**Passing definition:** Detection produces zero alerts when run against the benign sample NDJSON file. Suppression lookups match correctly.

**Failure modes (False Positive indicators):**

| Failure Mode | Likely Cause | Remediation |
|-------------|-------------|-------------|
| Detection fires on approved pipeline events | Lookup CSV missing the suppression ARN | Add ARN to `approved_iam_principals.csv` or `automation_role_arns.csv` |
| Detection fires on same-account events | Cross-account comparison logic inverted | Review account ID comparison in SPL |
| Detection fires on read-only events | `readOnly=true` filter missing | Add `where readOnly=false` or `errorCode=null` filter |

**Per-detection tracking (as of 2026-06-18):**

| CDET ID | Negative Sample File | Expected: No Alerts | Status |
|---------|---------------------|--------------------|----|
| CDET-001 | `CDET-001_pipeline_createuser.ndjson` | YES | Pending |
| CDET-002 | `CDET-002_self_key_creation.ndjson` | YES | Pending |
| CDET-003 | `CDET-003_benign_updatetrail.ndjson` | YES | Pending |
| CDET-004 | `CDET-004_benign_policy_attach.ndjson` | YES | Pending |
| CDET-005 | `CDET-005_same_account_trust.ndjson` | YES | Pending |
| CDET-006 | `CDET-006_non_root_activity.ndjson` | YES | Pending |
| CDET-007 | `CDET-007_ec2_internal_api_call.ndjson` | YES | Pending |
| CDET-008 | `CDET-008_below_threshold.ndjson` | YES | Pending |
| CDET-009 | `CDET-009_same_account_replication.ndjson` | YES | Pending |
| CDET-010 | `CDET-010_routine_deletion.ndjson` | YES | Pending |
| CDET-011 | `CDET-011_approved_launch.ndjson` | YES | Pending |
| CDET-012 | `CDET-012_approved_assumerole.ndjson` | YES | Pending |
| CDET-013 | `CDET-013_scoped_sg_rule.ndjson` | YES | Pending |
| CDET-014 | `CDET-014_non_cloudtrail_deletion.ndjson` | YES | Pending |

**Target:** 100% negative test pass rate.

**False Positive Rate formula:**

```
FP Rate % = (True False Positives per day / Total alerts per day) × 100
```

Where "True FP" = analyst dispositioned as false_positive in the SIEM.

**FP Rate targets:**

| Threshold | Action |
|-----------|--------|
| FP Rate < 5% | No action required |
| FP Rate 5–15% | Review suppression lookups, add tuning entries |
| FP Rate > 15% | Immediate detection review; consider suspending until tuned |

---

## Metric 3: Edge Test Pass Rate

**Definition:** Percentage of edge test cases where detection behavior matches the documented expectation.

**Formula:**

```
Edge Pass Rate % = (Edge tests with expected behavior / Total edge tests) × 100
```

**Important:** An edge test "passes" when behavior matches the **documented expectation** — this may include expected gaps. If an edge case documents that the detection *does not fire* due to a known limitation, and it indeed does not fire, the test passes.

**Edge cases by detection:**

| CDET ID | Edge Scenario | Expected Behavior | Status |
|---------|--------------|-------------------|--------|
| CDET-001 | Approved role in unusual region | No alert (documented gap) | Pending |
| CDET-002 | Key rotation same day | Alert fires | Pending |
| CDET-003 | UpdateTrail without disabling | No alert | Pending |
| CDET-004 | ReadOnly policy attached | No alert | Pending |
| CDET-005 | Same-account trust update | No alert | Pending |
| CDET-006 | Root performs read-only action | Alert fires | Pending |
| CDET-007 | IMDSv2 on-instance token use | No alert (documented gap) | Pending |
| CDET-008 | Lambda automated burst | May alert (threshold-dependent) | Pending |
| CDET-009 | Replication to same-org account | No alert | Pending |
| CDET-010 | Partial deletion below threshold | No alert | Pending |
| CDET-011 | Approved type + approved region | No alert | Pending |
| CDET-012 | Single hop within same account | No alert | Pending |
| CDET-013 | Security group internal-only | No alert | Pending |
| CDET-014 | Versioned object delete on AWSLogs/ | Alert fires | Pending |

**Target:** ≥80% edge test pass rate. The 20% buffer accounts for documented known gaps that are expected non-fires.

---

## Metric 4: Field Coverage Rate

**Definition:** Percentage of required alert output fields that are populated (non-null) in each alert.

**Formula:**

```
Field Coverage Rate % = (Required fields populated in alert / Total required fields in schema) × 100
```

**Required fields (from `validation/validation_schema.md`):**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `detection_id` | string | YES | Pattern: CDET-NNN |
| `alert_title` | string | YES | Pattern: [CDET-NNN] name |
| `severity` | enum | YES | critical/high/medium/low/informational |
| `urgency` | int | YES | 1-4 |
| `confidence` | enum | YES | high/medium/low |
| `tactic` | string | YES | MITRE tactic name |
| `technique` | string | YES | MITRE technique ID |
| `technique_name` | string | YES | MITRE technique name |
| `event_source_ip` | string | YES | Source IP of the event |
| `region` | string | YES | AWS region |
| `_time` | string | YES | Event timestamp |
| `actor_arn` | string | Conditional | Required for IAM/STS events |

**Target:** 100% field coverage for all required fields. Conditional fields must be populated when the condition applies.

**SPL to check field coverage:**

```spl
search index=cdet_alerts earliest=-24h
| eval missing_fields = mvappend(
    if(isnull(detection_id), "detection_id", null()),
    if(isnull(severity), "severity", null()),
    if(isnull(tactic), "tactic", null()),
    if(isnull(technique), "technique", null()),
    if(isnull(event_source_ip), "event_source_ip", null()),
    if(isnull(region), "region", null())
  )
| where isnotnull(missing_fields)
| stats count by detection_id missing_fields
```

*(Reference: `splunk/savedsearches/detection_validation.conf` → `[CDET-FieldCoverageCheck]`)*

---

## Validation Run History

A validation run is the execution of all test cases for one or more detections. Runs are identified by a run_id (8-char hex) and stored in `data/validation_results/`.

**Run history table:**

| Run ID | Date | Total Tests | Passed | Failed | Pass Rate % | Notes |
|--------|------|------------|--------|--------|-------------|-------|
| *(no runs yet)* | — | — | — | — | — | Awaiting Splunk environment |

**Run history format (JSON):**

```json
{
  "run_id": "a1b2c3d4",
  "run_timestamp": "2026-06-18T15:00:00Z",
  "detections_tested": 14,
  "tests_total": 42,
  "tests_passed": 40,
  "tests_failed": 2,
  "pass_rate_pct": 95.2,
  "positive_pass_rate_pct": 100.0,
  "negative_pass_rate_pct": 100.0,
  "edge_pass_rate_pct": 85.7,
  "results": [...]
}
```

---

## False Positive Tracking

**Daily FP tracking formula:**

```
FP Rate % per detection = (FP dispositions in past 7 days / Total alerts in past 7 days) × 100
```

**Escalation thresholds:**

| FP Rate | Action Required |
|---------|----------------|
| 0–5% | Normal — no action |
| 5–15% | Engineer reviews suppression lookups within 48h |
| >15% | Detection suspended, reviewed within 24h, re-tested before re-activation |

**SPL for FP rate monitoring:**

```spl
search index=cdet_alerts earliest=-7d
| stats count as total_alerts,
        count(eval(disposition="false_positive")) as fp_count
  by detection_id
| eval fp_rate = round((fp_count / total_alerts) * 100, 1)
| where fp_rate > 5
| table detection_id total_alerts fp_count fp_rate
| sort -fp_rate
```

*(Reference: `splunk/savedsearches/detection_health.conf` → `[CDET-HealthCheck-FalsePositiveRate]`)*

---

## Metric Lifecycle

Validation metrics flow into promotion decisions as follows:

```
1. Detection created (status: testing)
        ↓
2. Sample data ingested → positive test PASS
        ↓
3. Negative test PASS (zero FPs on benign data)
        ↓
4. Edge test PASS or gap documented
        ↓
5. Field coverage = 100%
        ↓
6. Peer review sign-off
        ↓
7. detection.yaml status → active
        ↓
8. Active monitoring: FP rate tracked daily
        ↓
9. If FP rate > 15% → status → suspended → fix → re-test → active
```

*(Full workflow in [`validation/validation_workflow.md`](../../validation/validation_workflow.md))*

---

## Related Documents

- [`coverage_metrics.md`](coverage_metrics.md) — Coverage scope metrics
- [`../../validation/validation_matrix.md`](../../validation/validation_matrix.md) — Test case status per detection
- [`../../validation/validation_schema.md`](../../validation/validation_schema.md) — Alert schema definitions
- [`../../splunk/savedsearches/detection_validation.conf`](../../splunk/savedsearches/detection_validation.conf) — Splunk validation searches
- [`../../splunk/savedsearches/detection_health.conf`](../../splunk/savedsearches/detection_health.conf) — Splunk health monitoring searches
