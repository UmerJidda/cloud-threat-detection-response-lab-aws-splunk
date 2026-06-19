# Detection Engineering Program Dashboard — Documentation

**File:** `splunk/dashboards/detection_engineering_dashboard.xml`
**Refresh:** 3600 seconds (1 hour)
**Theme:** Dark

## Purpose

The Detection Engineering Program Dashboard is the primary health and quality view for the detection engineering team. It answers four categories of operational questions:

1. **Coverage** — What percentage of the 14 CDET detections are active? Which ATT&CK tactics are covered, and which have gaps?
2. **Quality** — What is the false positive rate per detection? Which detections are failing their test cases?
3. **Operational health** — Are the supporting lookup tables populated? Are validation jobs running and producing results?
4. **Change tracking** — Which detections have been modified in the last 30 days?

This dashboard is not used for live incident triage. It is reviewed during sprint planning, after detection deployments, after major environment changes, and at a minimum weekly to ensure program health.

## Intended Audience

- Detection engineers (primary users)
- Security engineering leads and program managers
- Red team engineers validating coverage before exercises

## Refresh Strategy

The 1-hour refresh is appropriate because the underlying data sources (detection_catalog.csv, cdet_validation_results, cdet_alerts disposition data) do not change at sub-hourly intervals under normal operations. Analysts who need fresher data can manually refresh individual panels. The high refresh interval also reduces Splunk resource consumption since several panels run inputlookup commands that read from disk.

## Dependencies

### Indexes

| Index | Purpose |
|---|---|
| `cdet_alerts` | False positive rate calculation (Panels 5) |
| `cdet_validation_results` | Test case results and validation trend (Panels 4, 6) |

### Lookup Tables (all must be populated for Panel 7 to show OK status)

| Lookup File | Purpose |
|---|---|
| `detection_catalog.csv` | Master detection registry — source for Panels 1, 2, 3, 8 |
| `approved_iam_principals.csv` | IAM principal allowlist |
| `automation_role_arns.csv` | Automation role exclusions |
| `admin_policy_arns.csv` | High-privilege policy names |
| `approved_aws_accounts.csv` | Approved AWS account IDs |
| `approved_cidr_ranges.csv` | Approved CIDR blocks |
| `suspicious_instance_types.csv` | Instance types flagged as anomalous |
| `approved_regions.csv` | Approved AWS regions |
| `cloudtrail_log_buckets.csv` | Expected CloudTrail S3 bucket names |

### Saved Searches (for validation data to exist)

The `cdet_validation_results` index is populated by scheduled validation runs defined in `splunk/savedsearches/detection_validation.conf`. If these are not scheduled and running, Panels 4 and 6 will be empty.

---

## Panel Reference

### Panel 1 — Detection Coverage %

**Objective:** Track the proportion of the 14-detection portfolio that is in Active status. The program target is 80% active coverage. This is the headline KPI for the detection engineering program.

**SPL:**
```spl
| inputlookup detection_catalog.csv
| eval is_active=if(status="Active", 1, 0)
| stats sum(is_active) AS active_count, count AS total_count
| eval coverage_pct=round((active_count / total_count) * 100, 1)
| fields coverage_pct
```

**Threshold Configuration:**

| Color | Range | Meaning |
|---|---|---|
| Red | < 60% | Significant coverage gaps — program at risk |
| Yellow | 60–79% | Below target — prioritize promotion of Testing detections |
| Green | >= 80% | At or above target |

**Interpretation:**
- Coverage below 80% does not mean the environment is undefended — Testing detections still generate alerts. But they may have known tuning issues and should not be relied upon as authoritative.
- Coverage at exactly the number of Active detections / 14 will not naturally increase without engineering effort — this panel should trend up over time as Testing detections are validated and promoted.
- A sudden drop in coverage % indicates either a detection was deprecated or an Active detection was demoted to Testing/Draft, likely due to a regression found in CI/CD.

**Response Actions:**
- Below 80%: review Panel 3 (Validation Status Matrix) to identify Testing detections closest to Active promotion.
- Coverage drop since last review: check Panel 8 (Recently Modified Detections) to find what changed.
- Zero coverage (0%) indicates a `detection_catalog.csv` loading failure — run `| inputlookup detection_catalog.csv` manually to diagnose.

---

### Panel 2 — ATT&CK Tactic Coverage

**Objective:** Show how many detections cover each MITRE ATT&CK tactic. This drives gap analysis and sprint prioritization — tactics with fewer than 2 detections are under-covered.

**SPL:**
```spl
| inputlookup detection_catalog.csv
| stats count AS detection_count values(detection_id) AS detection_ids by tactic
| eval detection_ids=mvjoin(detection_ids, ", ")
| sort -detection_count
| rename tactic AS "ATT&CK Tactic"
         detection_count AS "Detection Count"
         detection_ids AS "Detection IDs"
```

**Interpretation:**
- The CDET program covers 9 of 14 ATT&CK tactics. Tactics with zero detections represent acknowledged gaps — document the rationale for each gap (out of scope, no applicable data source, compensating control).
- Tactics with only one detection have single-point-of-failure coverage — if that detection is deprecated or begins generating excessive FPs, the tactic becomes uncovered.
- Initial Access and Execution tactics tend to be harder to detect at the cloud API layer; data source limitations may be the root cause of low coverage there.

**Response Actions:**
- For any tactic with 0 detections: ensure there is a documented rationale in the detection engineering backlog.
- For any tactic with 1 detection: prioritize adding a second detection covering a different technique within the same tactic during the next sprint.
- Use this panel as an input to the quarterly detection roadmap presentation.

---

### Panel 3 — Validation Status Matrix

**Objective:** Provide a per-detection view of current status and last validation date, enabling engineers to identify detections that are overdue for re-validation.

**SPL:**
```spl
| inputlookup detection_catalog.csv
| table detection_id name tactic technique status last_validated
| sort detection_id
| rename detection_id AS "Detection ID"
         name AS "Detection Name"
         tactic AS "ATT&CK Tactic"
         technique AS "Technique"
         status AS "Status"
         last_validated AS "Last Validated"
```

**Status Definitions:**

| Status | Meaning | Color |
|---|---|---|
| Active | Detection is deployed, validated, and trusted for production alerting | Green |
| Testing | Detection is deployed but still being tuned or awaiting final validation | Yellow |
| Draft | Detection is written but not yet deployed to Splunk | Blue |
| Deprecated | Detection has been retired — kept for historical reference | Red |

**Interpretation:**
- Detections with status=Active and `last_validated` more than 90 days ago are at risk — environment changes may have broken them without generating alerts.
- A detection that stays in Testing for more than 30 days without being promoted likely has a persistent FP problem; escalate to the owning engineer.
- Deprecated detections should not generate alerts; if they appear in the SOC dashboard alert queue, the alert action was not disabled at deprecation time.

**Response Actions:**
- For stale Active detections (>90 days since validation): run the detection's test cases manually and update `last_validated` in the catalog.
- For long-running Testing detections: review Panel 5 (FP Rate by Detection) to determine whether the FP issue has been resolved.
- Maintain this catalog; it is the authoritative source for the Executive Dashboard coverage metrics.

---

### Panel 4 — Test Case Results (Last Validation Run)

**Objective:** Show the pass/fail outcome of automated test cases for each detection from the most recent 7-day validation window. This is the primary quality gate before promoting a detection from Testing to Active.

**SPL:**
```spl
index=cdet_validation_results earliest=-7d
| stats count AS total
        sum(eval(if(result="PASS",1,0))) AS passed
        sum(eval(if(result="FAIL",1,0))) AS failed
        by detection_id
| eval pass_rate=round((passed / total) * 100, 1)
| eval status=case(
    pass_rate=100,         "ALL_PASS",
    pass_rate >= 80,       "MOSTLY_PASS",
    pass_rate >= 50,       "PARTIAL",
    true(),                "FAILING"
  )
| sort detection_id
| rename detection_id AS "Detection ID"
         total AS "Total Tests"
         passed AS "Passed"
         failed AS "Failed"
         pass_rate AS "Pass Rate %"
         status AS "Status"
```

**Status Definitions:**

| Status | Threshold | Color |
|---|---|---|
| ALL_PASS | 100% | Green |
| MOSTLY_PASS | 80–99% | Yellow |
| PARTIAL | 50–79% | Orange |
| FAILING | < 50% | Red |

**Interpretation:**
- No detection should be promoted to Active unless it achieves ALL_PASS or MOSTLY_PASS with documented rationale for any failing test cases.
- A previously ALL_PASS detection that regresses to PARTIAL or FAILING after an environment change indicates the detection logic has a dependency on environment-specific data that changed.
- If the entire panel is empty, the validation saved searches are not scheduled or the `cdet_validation_results` index has not been created.

**Response Actions:**
- For FAILING detections: run `index=cdet_validation_results detection_id="<id>" result="FAIL" | table _time test_case_id error_message` to diagnose the specific test case failure.
- For ALL_PASS detections in Testing status: review with the owning engineer and promote to Active if all criteria are met.
- For an empty panel: check `splunk/savedsearches/detection_validation.conf` to verify schedules are active.

---

### Panel 5 — False Positive Rate by Detection (Last 30 Days)

**Objective:** Rank all detections by their false positive rate over the last 30 days. This is the primary input for detection tuning prioritization.

**SPL:**
```spl
index=cdet_alerts earliest=-30d
| eval is_fp=if(disposition="false_positive", 1, 0)
| stats sum(is_fp) AS fp_count, count AS total_alerts by detection_id
| eval fp_rate=round((fp_count / total_alerts) * 100, 1)
| sort -fp_rate
| rename detection_id AS "Detection ID", fp_rate AS "FP Rate %"
```

**Interpretation:**
- Detection FP rates above 15% are high priority for tuning — they erode analyst trust and inflate the SOC workload.
- FP rate of 0% should be treated skeptically if the detection is also showing high alert volume — analysts may not be properly dispositing alerts.
- FP rates can be calculated accurately only if analysts consistently update the `disposition` field. Monitor analyst workflow compliance if the FP rate appears artificially low.
- Common FP root causes: overly broad SPL logic (missing exclusions for known-good automation), incorrect threshold values, or stale lookup tables.

**Response Actions:**
- For any detection above 15% FP rate: open a detection engineering ticket with the detection ID, current FP rate, and the most common actor/source patterns in the FP events.
- Run `index=cdet_alerts detection_id="<id>" disposition=false_positive earliest=-30d | stats count by actor_arn sourceIPAddress` to identify the FP-generating principals — these likely need to be added to the relevant exclusion lookup.
- After tuning, re-measure FP rate over the following 7 days before closing the ticket.

---

### Panel 6 — Detection Validation Trend (Last 30 Days)

**Objective:** Show whether the volume of PASS and FAIL test case results has been trending in a healthy direction over the past 30 days. A healthy trend shows increasing PASS counts and stable or decreasing FAIL counts.

**SPL:**
```spl
index=cdet_validation_results earliest=-30d
| timechart span=1d count by result
```

**Interpretation:**
- A flat line across all result types indicates validation is not running daily — check the schedule of the validation saved searches.
- An increasing FAIL trend after a sprint deployment indicates that new or modified detections introduced regressions.
- A sudden spike in PASS results on a single day may indicate that a large batch of previously failing test cases were fixed — confirm this corresponds to a known code change.

**Response Actions:**
- Downward PASS trend: review recent commits to detection logic in the detection catalog and saved searches.
- Consistently flat (no data): validate that `splunk/savedsearches/detection_validation.conf` contains scheduled searches pointing to `index=cdet_validation_results` with an `action.script` or similar write-back mechanism.

---

### Panel 7 — Lookup Table Health

**Objective:** Verify that all 8 supporting lookup tables are populated with at least one entry. An empty lookup table silently causes detections that depend on it to misfire — either generating all alerts or no alerts depending on the logic.

**SPL:**
```spl
| union
  [| inputlookup approved_iam_principals.csv    | eval lookup_name="approved_iam_principals.csv"]
  [| inputlookup automation_role_arns.csv        | eval lookup_name="automation_role_arns.csv"]
  [| inputlookup admin_policy_arns.csv           | eval lookup_name="admin_policy_arns.csv"]
  [| inputlookup approved_aws_accounts.csv       | eval lookup_name="approved_aws_accounts.csv"]
  [| inputlookup approved_cidr_ranges.csv        | eval lookup_name="approved_cidr_ranges.csv"]
  [| inputlookup suspicious_instance_types.csv   | eval lookup_name="suspicious_instance_types.csv"]
  [| inputlookup approved_regions.csv            | eval lookup_name="approved_regions.csv"]
  [| inputlookup cloudtrail_log_buckets.csv      | eval lookup_name="cloudtrail_log_buckets.csv"]
| stats count by lookup_name
| eval health=if(count=0, "EMPTY - ACTION REQUIRED", "OK (" . count . " entries)")
| eval status=if(count=0, "EMPTY", "OK")
```

**Interpretation:**
- All tables should show "OK" during normal operations. Any "EMPTY" status means the lookup was either never populated or was accidentally cleared.
- `approved_iam_principals.csv` being empty would cause detections that exclude approved principals to generate FPs on all legitimate IAM activity.
- `approved_regions.csv` being empty would cause CDET-013 (Unauthorized Region Activity) to alert on all activity.

**Response Actions:**
- For any EMPTY lookup: immediately repopulate from your source of truth (infrastructure-as-code repository, CMDB, or ITSM).
- After repopulating: run the affected detection's test cases (Panel 4) to confirm correct behavior has been restored.
- Implement a scheduled alert that fires if any lookup has row count = 0 to catch this proactively in the future.

---

### Panel 8 — Recently Modified Detections (Last 30 Days)

**Objective:** Track which detections have been changed in the last 30 days to support change management, regression investigation, and audit trails.

**SPL:**
```spl
| inputlookup detection_catalog.csv
| eval last_modified_epoch=strptime(last_modified, "%Y-%m-%d")
| where last_modified_epoch >= relative_time(now(), "-30d")
| table detection_id name status last_modified
| sort -last_modified
| rename detection_id AS "Detection ID"
         name AS "Detection Name"
         status AS "Status"
         last_modified AS "Last Modified"
```

**Interpretation:**
- A detection that was modified and simultaneously shows a regression in Panel 4 (test results) or Panel 5 (FP rate) is a clear root cause — review the change.
- Modifications without a corresponding change in test results may indicate the `detection_catalog.csv` was updated but the actual Splunk saved search was not (or vice versa) — verify synchronization.
- If no detections have been modified in 30 days, the program may be stagnant — review the backlog for pending tuning items.

**Response Actions:**
- For each modified detection: verify the change is reflected in both the saved search configuration (`splunk/savedsearches/`) and the catalog.
- Cross-reference modifications with Panel 4 (test pass rates) from the same date range to confirm the change did not introduce regressions.
- Maintain a changelog comment in `detection_catalog.csv` (via a `change_notes` column if available) for audit trail purposes.
