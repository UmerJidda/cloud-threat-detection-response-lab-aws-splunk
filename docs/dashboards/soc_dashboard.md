# SOC Operations Dashboard — Documentation

**File:** `splunk/dashboards/soc_dashboard.xml`
**Refresh:** 300 seconds (5 minutes)
**Theme:** Dark

## Purpose

The SOC Operations Dashboard is the primary working view for tier-1 and tier-2 analysts during shift operations. It surfaces the live alert queue, severity distribution, per-detection firing cadence, false positive rate, top threat actors, regional activity, detection health, and CloudTrail data ingestion health in a single screen. Analysts should use this dashboard as their starting point at the beginning of each shift and refer back to it when triaging new alerts.

## Intended Audience

- Tier-1 SOC analysts (alert triage and initial enrichment)
- Tier-2 SOC analysts (investigation, escalation decisions)
- SOC shift leads (queue management, workload distribution)

## Dependencies

The following indexes must be receiving data for all panels to populate correctly:

| Index | Purpose |
|---|---|
| `cdet_alerts` | All CDET detection alert events |
| `aws_cloudtrail` | Raw CloudTrail events for ingestion health check |

The following saved searches must exist and be scheduled:

| Saved Search | Required By |
|---|---|
| `CDET-HealthCheck-AlertVolume` | Detection Health Status panel (referenced indirectly via alert volume thresholds) |

---

## Panel Reference

### Panel 1 — Alert Queue (Last 24h)

**Objective:** Provide an ordered list of every alert fired in the last 24 hours so analysts know exactly what needs to be triaged. The queue is sorted newest-first and includes the key triage fields: detection ID, severity, acting principal, region, and current disposition.

**SPL:**
```spl
index=cdet_alerts earliest=-24h
| table _time detection_id enriched_severity actor_arn aws_region disposition
| sort -_time
| rename _time AS "Time"
         detection_id AS "Detection ID"
         enriched_severity AS "Severity"
         actor_arn AS "Actor ARN"
         aws_region AS "Region"
         disposition AS "Disposition"
```

**Interpretation:**
- Alerts with `disposition` still empty or `new` are untriaged — prioritize these.
- Look for the same `actor_arn` appearing across multiple detection IDs; this may indicate multi-stage activity.
- Alerts in unexpected `aws_region` values (outside your organization's approved regions lookup) warrant immediate review.
- A queue with more than 20 untriaged critical/high alerts at shift start indicates a possible alert storm — check Detection Health Status before triaging individually.

**Response Actions:**
- Click any row to pivot into a raw Splunk search for that detection ID over the last 24 hours.
- Assign untriaged alerts to analysts using your ticketing integration.
- If the queue shows a sudden spike for a single detection_id, cross-reference the Detection Firing Rate panel (Panel 3) and the Detection Health Status panel (Panel 7) before spending time on individual triage.

---

### Panel 2 — Active Alerts by Severity (Last 24h)

**Objective:** Give shift leads an immediate at-a-glance count of alerts at each severity tier so they can make staffing and escalation decisions without scrolling through the queue.

**SPL (Critical count example — repeated for each severity):**
```spl
index=cdet_alerts earliest=-24h enriched_severity=critical
| stats count
```

**Threshold Configuration:**

| Tile | Green | Yellow | Orange/Red |
|---|---|---|---|
| Critical | 0 | 1–4 | 5+ |
| High | 0–2 | 3–9 | 10+ |
| Medium | 0–9 | 10–24 | 25+ |
| Low | 0–19 | 20–49 | 50+ |

**Interpretation:**
- Any non-zero critical count at shift start must be addressed before lower-severity items.
- A high count that is significantly larger than the prior day's count (visible via Panel 3) may indicate a new active threat campaign.
- Low counts that spike dramatically often indicate noisy detections; route to the detection engineering team for tuning.

**Response Actions:**
- Non-zero critical: immediately triage the Alert Queue (Panel 1) filtered to `enriched_severity=critical`.
- High count above threshold: check Panel 5 (Top Actors) to determine if the activity is concentrated on one principal.
- Escalate to Tier-2 if any severity block remains red for more than 30 minutes without analyst assignment.

---

### Panel 3 — Detection Firing Rate (Last 7 Days)

**Objective:** Show the daily cadence of each detection over the past week so analysts can distinguish a genuine spike from normal baseline variation and identify detections that have gone silent.

**SPL:**
```spl
index=cdet_alerts earliest=-7d
| timechart span=1d count by detection_id
```

**Interpretation:**
- A detection that fired consistently and then drops to zero may indicate a data pipeline issue — cross-reference with Panel 8 (ingestion health).
- A detection that spikes well above its 7-day baseline on a single day often corresponds to a real incident or a mass-exploitation attempt.
- Detections with near-zero counts across the full 7-day window may be misconfigured or targeting activity that does not occur in your environment — escalate to detection engineering.

**Response Actions:**
- For a new spike: drill into the Alert Queue filtered to that detection_id for the spike day.
- For a silent detection: open a detection engineering ticket and check the associated saved search syntax and index health.
- For sustained elevation across multiple detections on the same day: consider opening a major incident.

---

### Panel 4 — False Positive Rate (Last 7 Days)

**Objective:** Track the program-wide false positive rate as a single KPI. A rising FP rate directly degrades analyst trust in the detection program and increases workload.

**SPL:**
```spl
index=cdet_alerts earliest=-7d
| eval is_fp=if(disposition="false_positive",1,0)
| stats sum(is_fp) AS fp_count, count AS total_alerts
| eval fp_rate=round((fp_count / total_alerts) * 100, 1)
| eval fp_rate=if(isnull(fp_rate), 0, fp_rate)
| fields fp_rate
```

**Threshold Configuration:**

| Color | Meaning |
|---|---|
| Green (< 5%) | Acceptable — well-tuned program |
| Yellow (5–15%) | Needs attention — review top FP detections |
| Red (> 15%) | Action required — analyst trust at risk |

**Interpretation:**
- A sudden jump from green to red indicates a newly-deployed or regressed detection generating a flood of FPs.
- A sustained yellow state means tuning backlog is accumulating — prioritize the Detection Engineering dashboard FP chart to identify the culprits.
- Zero FP rate with high alert volume may indicate analysts are not updating dispositions; check workflow compliance.

**Response Actions:**
- Above 15%: immediately review Detection Engineering Dashboard Panel 5 (FP Rate by Detection) to identify the noisiest detections.
- Between 5–15%: schedule a detection tuning review within the current sprint.
- Ensure all analysts are disposting alerts; if total alerts are high but FP count is zero the workflow is broken.

---

### Panel 5 — Top Actors by Alert Count (Last 24h)

**Objective:** Identify the IAM principals generating the most alerts so analysts can quickly determine whether activity is concentrated on a single compromised or misbehaving account.

**SPL:**
```spl
index=cdet_alerts earliest=-24h
| stats count by actor_arn
| sort -count
| head 10
| rename actor_arn AS "Actor ARN", count AS "Alert Count"
```

**Interpretation:**
- A human user ARN at the top of this list is a high-priority investigation trigger — humans should rarely appear in the top 10 under normal operations.
- Automation role ARNs at the top are expected — verify against the `automation_role_arns.csv` lookup before escalating.
- An ARN that appears here but is absent from `approved_iam_principals.csv` warrants immediate investigation.

**Response Actions:**
- Search `index=cdet_alerts actor_arn="<suspect ARN>" earliest=-24h | table _time detection_id enriched_severity` to see the full alert timeline for that principal.
- If the actor ARN belongs to a human and has fired >3 distinct detection IDs, escalate to Tier-2 and consider initiating an account compromise response.
- Cross-reference source IPs in the raw CloudTrail events for the actor: `index=aws_cloudtrail userIdentity.arn="<ARN>" earliest=-24h | stats count by sourceIPAddress`.

---

### Panel 6 — Alerts by AWS Region (Last 24h)

**Objective:** Surface alerts by region to detect activity in regions that are not approved for use in the environment, which may indicate infrastructure creation by an adversary or a misconfigured workload.

**SPL:**
```spl
index=cdet_alerts earliest=-24h
| stats count by aws_region
| sort -count
| rename aws_region AS "AWS Region", count AS "Alert Count"
```

**Interpretation:**
- Regions that appear here but are absent from `approved_regions.csv` are high-priority — this is the primary signal for CDET-013 (Unauthorized Region Activity).
- A single region with a disproportionate share of alerts may indicate that an attacker has chosen that region specifically to avoid monitoring.
- Zero counts across all non-approved regions is the expected healthy state.

**Response Actions:**
- Click a region row to pivot into raw cdet_alerts for that region.
- If an unapproved region appears: search `index=aws_cloudtrail awsRegion="<region>" earliest=-24h | stats count by eventName userIdentity.arn` to understand what was done there.
- Notify the AWS account owner and consider adding a GuardDuty threat intel set for the region if activity is persistent.

---

### Panel 7 — Detection Health Status

**Objective:** Show per-detection alert volume for the last 24 hours and flag detections that have gone silent (potential pipeline failure) or are firing at unusually high volume (potential runaway detection).

**SPL:**
```spl
index=cdet_alerts earliest=-24h
| stats count AS alert_count by detection_id
| eval health=case(
    alert_count=0,    "NO_ALERTS",
    alert_count <= 10, "NORMAL",
    alert_count <= 50, "ELEVATED",
    true(),           "HIGH_VOLUME"
  )
| sort detection_id
| rename detection_id AS "Detection ID"
         alert_count AS "24h Alerts"
         health AS "Health Status"
```

**Health Status Definitions:**

| Status | Meaning | Color |
|---|---|---|
| NO_ALERTS | Detection has not fired in 24h — possible pipeline failure | Red |
| NORMAL | 1–10 alerts, expected operating range | Green |
| ELEVATED | 11–50 alerts, warrants review | Yellow |
| HIGH_VOLUME | >50 alerts, tuning likely required | Orange |

**Interpretation:**
- `NO_ALERTS` for a detection that fired regularly last week is an urgent data pipeline concern.
- `HIGH_VOLUME` detections should be reviewed for FP tuning before they overwhelm analyst capacity.
- If all detections show `NO_ALERTS`, the cdet_alerts index itself may have a pipeline outage — check Panel 8.

**Response Actions:**
- `NO_ALERTS`: run the detection's saved search manually against the underlying index to confirm whether it would generate results; if yes, the cdet_alerts alert action is broken.
- `HIGH_VOLUME`: filter the alert queue to that detection_id and review for common legitimate-activity patterns that need to be added to the relevant lookup exclusion table.

---

### Panel 8 — CloudTrail Ingestion Rate (Last 1h)

**Objective:** Confirm that AWS CloudTrail logs are flowing into Splunk at an acceptable rate. Zero or near-zero ingestion is an infrastructure failure that renders all cloud detections blind.

**SPL:**
```spl
index=aws_cloudtrail earliest=-1h
| stats count
```

**Threshold Configuration:**

| Color | Range | Meaning |
|---|---|---|
| Red | < 10 events | Pipeline failure — immediate action required |
| Yellow | 10–100 events | Degraded — investigate CloudTrail or HEC |
| Green | > 100 events | Normal ingestion |

**Interpretation:**
- A red ingestion panel while alerts are still appearing in the queue may indicate stale cached events; clear the cache and recheck.
- Low ingestion during off-peak hours (e.g., 2–4 AM) can be normal in smaller environments — calibrate thresholds to your baseline.
- If ingestion drops to red simultaneously with a detection showing `NO_ALERTS`, you have a confirmed pipeline outage.

**Response Actions:**
- Red state: check the Splunk HTTP Event Collector (HEC) health and the CloudTrail S3 bucket SQS queue depth.
- Verify that the CloudTrail trail is enabled in all required regions: `aws cloudtrail describe-trails --include-shadow-trails`.
- Page the infrastructure on-call if the outage persists beyond 15 minutes.
