# Splunk Dashboard Strategy

## Overview

This document defines the dashboard philosophy, planned dashboard catalog, and design standards for the Cloud Threat Detection Lab. Dashboards are implemented in a later phase; this document establishes the design contract they will fulfill.

---

## Dashboard Philosophy

Dashboards in this program serve three distinct audiences with different information needs:

1. **SOC Analyst** — Real-time triage and investigation support. Needs to quickly answer: "What is firing right now, and is it worth investigating?"
2. **Detection Engineer** — Program health monitoring. Needs to answer: "Are my detections working, and what is the quality of the signal?"
3. **Security Manager** — Program posture and trend reporting. Needs to answer: "How is the program performing, and where are the coverage gaps?"

Every dashboard is designed for one of these audiences. A dashboard that tries to serve all three ends up serving none.

---

## Planned Dashboard Catalog

### SOC Analyst Dashboards

**1. Security Operations Overview**
- Purpose: Single-pane view of the current alert queue
- Key panels:
  - Active Notable Events by severity (last 24 hours)
  - Unacknowledged alerts by detection ID
  - Alert volume trend (7-day sparkline)
  - Top alerting principals (by alert count)
  - Recent GuardDuty findings (by severity)
- Refresh: Real-time (30-second polling)

**2. Alert Investigation — CloudTrail Timeline**
- Purpose: Drill-down investigation view for a specific alert
- Input: Principal ARN (from Notable Event drilldown)
- Key panels:
  - All CloudTrail events for the principal (last 7 days)
  - Event timeline (scatter plot by event name)
  - Source IP map (geolocation)
  - IAM state at time of alert
  - Concurrent GuardDuty findings
- Refresh: On-demand

**3. Credential Exposure Triage**
- Purpose: IAM security posture at a glance
- Key panels:
  - Users without MFA (from IAM collector)
  - Access keys not used in 90+ days
  - Access keys older than 180 days
  - Users with admin policies attached
  - Roles with cross-account trust to unknown accounts
- Refresh: Daily

---

### Detection Engineering Dashboards

**4. Detection Coverage and Health**
- Purpose: Monitor detection program quality
- Key panels:
  - Detection coverage matrix (tactic × technique heat map)
  - Detections by status (active / testing / draft)
  - Validation results trend
  - False positive rate by detection (last 30 days)
  - Detections with no alerts in 30 days (possible data source gap)
- Refresh: Daily

**5. Detection Signal Quality**
- Purpose: Tune detections based on alert volume patterns
- Key panels:
  - Alert volume by detection (last 30 days bar chart)
  - True positive rate by detection (from labeled outcomes)
  - Top false positive sources by detection
  - Suppression lookup utilization (how often each lookup row fires)
- Refresh: Daily

---

### Security Manager Dashboards

**6. Security Posture Executive Summary**
- Purpose: Leadership-level program health view
- Key panels:
  - ATT&CK coverage heat map (technique-level)
  - Open incidents by severity (last 30 days)
  - Mean time to detect (MTTD) trend
  - Mean time to contain (MTTC) trend
  - Top affected resources
  - GuardDuty and Security Hub finding trends
- Refresh: Daily

---

## Design Standards

### Color Scheme

| Severity | Color | Hex |
|----------|-------|-----|
| Critical | Red | `#D93025` |
| High | Orange | `#F57C00` |
| Medium | Yellow | `#F9A825` |
| Low | Blue | `#1565C0` |
| Informational | Grey | `#757575` |

### Time Range Defaults

| Dashboard Type | Default Time Range |
|---------------|-------------------|
| SOC real-time | Last 24 hours |
| Investigation | Last 7 days (adjustable) |
| Engineering | Last 30 days |
| Executive | Last 30 days |

### Drilldown Standards

Every table row in a detection-related dashboard must drilldown to the Alert Investigation — CloudTrail Timeline dashboard with the `principal_arn` pre-populated as a filter.

### Performance Requirements

- All dashboards must load within 10 seconds with a full 24-hour data set
- Searches with `stats` over more than 90 days must use summary indexing or accelerated data models
- Real-time dashboards must not use `| real-time` search mode — use timed refresh with appropriate intervals instead

---

## Dashboard File Format

Dashboard definitions are stored as XML in `splunk/dashboards/` and follow the Splunk Simple XML schema. Each file is named:

```
{audience}_{dashboard_name}.xml
```

Examples:
- `soc_security_operations_overview.xml`
- `de_detection_coverage_health.xml`
- `mgmt_posture_executive_summary.xml`

Dashboards are imported via Splunk Web → Dashboards → Import, or deployed via the Splunk management API using scripts in `scripts/splunk_ops/`.
