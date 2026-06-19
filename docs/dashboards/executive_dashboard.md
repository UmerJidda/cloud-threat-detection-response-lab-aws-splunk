# Cloud Security Executive Dashboard — Documentation

**File:** `splunk/dashboards/executive_dashboard.xml`
**Refresh:** 3600 seconds (1 hour)
**Theme:** Dark

## Purpose

The Cloud Security Executive Dashboard delivers CISO-level security metrics for the Cloud Threat Detection Lab. It answers the four questions an executive audience asks at a program review:

1. **Volume** — How many security alerts has the program generated this month?
2. **Severity** — Have there been any critical incidents requiring board-level awareness?
3. **Coverage** — What percentage of the MITRE ATT&CK framework does the program detect against?
4. **Trends** — Is the threat landscape improving or worsening? What are the top threats?

This dashboard is not designed for real-time operations. It is designed to be static and stable — a monthly read-out artifact that can be exported to PDF or shown in a slide deck. The hourly refresh ensures that when the dashboard is opened for a monthly review meeting, the data is current without requiring a manual refresh.

## Intended Audience

- CISO and deputy CISO
- VP of Engineering / CTO (security briefings)
- Risk and compliance officers
- External auditors or assessors reviewing the security program
- Program managers producing monthly reporting artifacts

## Refresh Strategy

Hourly refresh is appropriate because executive metrics do not need real-time precision. The underlying 30-day aggregation queries change minimally from hour to hour, and the high refresh interval keeps Splunk resource consumption low for what is primarily a reporting dashboard rather than an operational one. For monthly reporting exports, manually open the dashboard and allow one full refresh cycle before taking a screenshot or PDF export.

## Dependencies

| Index | Purpose |
|---|---|
| `cdet_alerts` | All alert KPI panels (Panels 1, 2, 5, 6) |

| Lookup | Purpose |
|---|---|
| `detection_catalog.csv` | ATT&CK coverage and tactic breakdown (Panels 3, 4) |

No VPC Flow or secondary security index data is required for this dashboard. The executive view intentionally sources from `cdet_alerts` (processed, enriched alerts) rather than raw `aws_cloudtrail` to surface the de-noised, analyst-reviewed picture of security activity.

---

## Panel Reference

### Panel 1 — Total Alerts This Month

**Objective:** Provide the headline monthly alert volume as a single number. This is the first thing an executive audience looks at — it frames the scale of security activity the SOC is handling.

**SPL:**
```spl
index=cdet_alerts earliest=-30d
| stats count
```

**Interpretation:**
- This number reflects total alert firings, not unique incidents. A single incident may generate alerts from multiple detections.
- Month-over-month comparisons are the most meaningful reading: is the number growing, shrinking, or stable?
- A sudden spike vs. the prior month may indicate a new campaign, a newly deployed noisy detection, or an environment change (e.g., a new AWS account was added to monitoring).
- A dramatic drop may indicate a data pipeline outage, not a security improvement — always cross-reference with the SOC Dashboard ingestion health panel.

**Response Actions:**
- For a significant spike: prepare a one-paragraph narrative explaining the root cause (new detection deployed, known campaign, false positive storm, etc.) for the executive summary.
- For a significant drop: verify that the cdet_alerts index is receiving data before presenting the number as a positive trend.
- Include the prior-month count as context; this panel's sparkline provides the 30-day daily trend visually.

---

### Panel 2 — Critical Incidents This Month

**Objective:** Surface the count of critical-severity alerts as a standalone KPI. Critical alerts require the most senior analyst attention and may have business impact; executives need to know this number immediately.

**SPL:**
```spl
index=cdet_alerts earliest=-30d enriched_severity=critical
| stats count
```

**Threshold Configuration:**

| Color | Condition | Meaning |
|---|---|---|
| Green | 0 | No critical alerts this month |
| Red | >= 1 | One or more critical alerts — requires narrative |

**Interpretation:**
- Any non-zero value on this panel means at least one event was assessed at critical severity. The executive report must include a brief status statement for each critical alert: was it a true positive, false positive, or under investigation?
- A critical alert count that persists month-over-month without resolution may indicate an unresolved detection gap or a persistent threat actor.
- The color threshold is intentionally binary: zero is green, anything else is red. Executives should not need to assess whether a number is "acceptable" — any critical alert warrants explanation.

**Response Actions:**
- Non-zero count: prepare a critical incident summary table listing `detection_id`, `actor_arn`, `aws_region`, date/time, and resolution status for each critical alert.
- Zero count: document this as a positive finding in the monthly report, but verify by cross-referencing with the SOC dashboard FP rate — a zero count with a high FP rate may indicate critical alerts were incorrectly dispositioned.

---

### Panel 3 — ATT&CK Tactic Coverage

**Objective:** Show the percentage of MITRE ATT&CK tactics that the detection program actively covers. This is the primary "are we protecting against the right things?" metric for a technical executive audience.

**SPL:**
```spl
| inputlookup detection_catalog.csv
| where status="Active"
| stats dc(tactic) AS covered_tactics
| eval total_tactics=14
| eval coverage_pct=round((covered_tactics / total_tactics) * 100, 0)
| fields coverage_pct
```

**Threshold Configuration:**

| Color | Range | Meaning |
|---|---|---|
| Red | < 50% | Significant coverage gaps — major risk |
| Yellow | 50–69% | Below target — improvement plan needed |
| Green | >= 70% | Acceptable — continue improving |

**Interpretation:**
- The denominator (14) represents the total number of ATT&CK tactics tracked in the CDET program, not all ATT&CK tactics that exist. This is intentional — not all tactics are applicable to cloud environments.
- Coverage percentage is a lagging indicator of detection engineering investment. A steady upward trend quarter-over-quarter shows a maturing program.
- 100% coverage does not mean the organization cannot be compromised — it means every tactic in scope has at least one detection. Detection quality (FP rate, test pass rate) matters as much as coverage breadth.

**Response Actions:**
- Below 70%: include a detection roadmap in the monthly report showing which tactics will be covered in the next 1–2 sprints.
- At 70%+: highlight the coverage number as a program achievement while setting the expectation that quality improvement (tuning, validation) is the next priority.
- Use Panel 4 (Coverage by Tactic) in this same dashboard to explain which tactics have coverage and which are acknowledged gaps.

---

### Panel 4 — Detection Coverage by ATT&CK Tactic

**Objective:** Break down the aggregate coverage percentage (Panel 3) into per-tactic detail. This allows an executive audience to ask "why don't we cover X?" and receive a direct answer.

**SPL:**
```spl
| inputlookup detection_catalog.csv
| stats count AS total_detections
        sum(eval(if(status="Active",1,0))) AS active_detections
        by tactic
| eval coverage_pct=round((active_detections / total_detections) * 100, 0)
| eval coverage_label=case(
    coverage_pct=100,    "FULL",
    coverage_pct >= 50,  "PARTIAL",
    true(),              "MINIMAL"
  )
| sort tactic
| rename tactic AS "ATT&CK Tactic"
         total_detections AS "Total"
         active_detections AS "Active"
         coverage_pct AS "Coverage %"
         coverage_label AS "Coverage Level"
```

**Coverage Level Definitions:**

| Level | Meaning | Color |
|---|---|---|
| FULL | All detections for this tactic are Active | Green |
| PARTIAL | Some detections are Active, some are Testing/Draft | Yellow |
| MINIMAL | No Active detections for this tactic | Red |

**Interpretation:**
- MINIMAL tactics should always have a documented explanation in the executive briefing: either the tactic is not applicable to the cloud environment (acceptable), compensating controls exist (acceptable with caveat), or it is a known gap with a remediation timeline (requires action).
- PARTIAL tactics are the sweet spot for improvement — engineering effort to validate the remaining Testing detections can quickly move them to FULL.
- FULL tactics should be monitored for regression; a future deprecation could silently drop a tactic from FULL to PARTIAL or MINIMAL.

**Response Actions:**
- For each MINIMAL tactic: prepare a one-sentence justification for the executive briefing (scope exclusion, compensating control, or remediation plan).
- For PARTIAL tactics: escalate to the detection engineering team with a sprint target for Active promotion.
- After each sprint, this table should show at least one tactic improving; if not, the program has stalled.

---

### Panel 5 — Alert Volume Trend by Severity (Last 30 Days)

**Objective:** Show the day-by-day distribution of alerts by severity across the past 30 days as a stacked area chart. This is the trend visualization that answers "is the threat landscape getting better or worse?"

**SPL:**
```spl
index=cdet_alerts earliest=-30d
| timechart span=1d count by enriched_severity
```

**Interpretation:**
- A stable, low-critical, low-high profile over 30 days indicates a well-tuned detection program operating in a low-threat-activity environment.
- A spike across all severity levels simultaneously usually indicates either a mass event (e.g., a credential exposure incident causing widespread unauthorized access attempts) or a detection configuration change that temporarily increased alert volume across the board.
- A gradual increase in medium and low severity over time, without a corresponding increase in critical/high, may indicate detection tuning drift — more noise without more signal.
- Stacked area shows relative proportions as well as absolute volumes; watch for the critical band (red) growing relative to the total bar height.

**Response Actions:**
- For a single-day spike: open the SOC dashboard filtered to that day and identify the root cause (incident or detection change).
- For a multi-week upward trend in medium/low without corresponding critical/high: schedule a detection tuning sprint and target the noisiest detections using the Detection Engineering dashboard FP Rate panel.
- For a multi-week upward trend in critical/high: escalate to the CISO and prepare a threat briefing.

---

### Panel 6 — Top Threats This Month

**Objective:** Identify the 5 most-active threat patterns by alert volume over the past 30 days, linked to specific ATT&CK tactics and techniques. This gives the executive audience a concrete picture of "what are the actual threats we faced?"

**SPL:**
```spl
index=cdet_alerts earliest=-30d
| stats count by attack_tactic attack_technique detection_id enriched_severity
| sort -count
| head 5
| rename attack_tactic AS "ATT&CK Tactic"
         attack_technique AS "Technique"
         detection_id AS "Detection ID"
         enriched_severity AS "Severity"
         count AS "Alert Count"
```

**Interpretation:**
- This table should be read as a threat narrative: "The top 5 security threats we observed this month were..." followed by the tactic/technique name.
- A detection appearing here month-over-month without resolution suggests either a persistent threat actor or a detection with a high FP rate that has not been addressed.
- The `enriched_severity` field here reflects the detection's configured severity, not an analyst's assessment — verify that critical-rated detections on this list have been triaged.
- Tactics that appear on this list but are not in the top 5 on the Detection Coverage panel may indicate that attackers are gravitating toward your less-covered areas — this is an intelligence-driven reason to prioritize coverage in those tactics.

**Response Actions:**
- Include this table verbatim in the monthly executive report with a one-sentence analyst interpretation of each row.
- For any row with critical severity and high count: ensure a post-incident review or investigation note exists for the detection engineering record.
- Use this table to drive the detection roadmap: if Privilege Escalation repeatedly appears in the top 5, prioritize adding detections in that tactic.
- For rows where the detection_id maps to a detection currently in Testing status: the Testing detection is generating real signal and should be accelerated to Active promotion.
