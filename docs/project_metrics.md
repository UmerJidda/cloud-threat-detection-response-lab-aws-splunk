---
title: Project Metrics Summary
last_updated: 2026-06-19
phase: 4.5
---

# Cloud Threat Detection Lab — Project Metrics

Current totals as of Phase 4.5 completion. All counts are derived from the live repository.

---

## Detection Engineering

| Metric | Count | Notes |
|---|---|---|
| Total detections defined | 14 | CDET-001 through CDET-014 |
| Detections in Testing status | 14 | Awaiting Splunk promotion |
| Detections in Active status | 0 | Promoted after live validation |
| Detection YAMLs with full metadata | 14 | tactic, technique, severity, lookups, test_cases |
| Unique data sources covered | 4 | CloudTrail, GuardDuty, SecurityHub, VPC Flow |
| Services covered | 8 | IAM, STS, CloudTrail, EC2, S3, Organizations, VPC, EC2 Metadata |

---

## MITRE ATT&CK Coverage

| Metric | Count | Notes |
|---|---|---|
| ATT&CK tactics covered | 9 | See tactic breakdown below |
| ATT&CK techniques covered | 13 unique | One technique shared across CDET-004 and CDET-006 |
| ATT&CK sub-techniques | 10 | e.g. T1136.003, T1098.001, T1562.008 |
| Coverage against cloud scope | 13 / ~40 in-scope | ~33% of MITRE cloud technique universe |

**Tactic Breakdown:**

| Tactic | CDET IDs | Technique IDs |
|---|---|---|
| Persistence | CDET-001, CDET-002 | T1136.003, T1098.001 |
| Privilege Escalation | CDET-004, CDET-005 | T1078.004, T1484.002 |
| Defense Evasion | CDET-003, CDET-013, CDET-014 | T1562.008, T1562.007, T1070.004 |
| Credential Access | CDET-007 | T1552.005 |
| Discovery | CDET-008 | T1580 |
| Lateral Movement | CDET-012 | T1550.001 |
| Exfiltration | CDET-009 | T1537 |
| Impact | CDET-010, CDET-011 | T1485, T1496 |
| Initial Access | CDET-006 | T1078.004 |

---

## Validation Framework

| Metric | Count | Notes |
|---|---|---|
| Test cases per detection | 3 | positive, negative/benign, edge case |
| Total test cases | 42 | 14 CDETs × 3 test types |
| NDJSON positive sample files | 14 | sample_logs/cloudtrail/malicious/ |
| NDJSON benign sample files | 14 | sample_logs/cloudtrail/benign/ |
| NDJSON edge case files | 14 | sample_logs/cloudtrail/edge_cases/ |
| GuardDuty sample files | 2 | sample_logs/guardduty/malicious/ |
| SecurityHub sample files | 2 | sample_logs/securityhub/findings/ |
| Total sample log files | 53 | Across all categories |
| Splunk saved searches (validation) | 3 | detection_validation.conf |
| Splunk saved searches (coverage) | 5 | coverage_reporting.conf |
| Splunk saved searches (health) | 6 | detection_health.conf |
| Total Splunk saved searches | 14 | Across all 3 conf files |
| Splunk lookup tables | 11 | CSV files in splunk/lookups/ |

---

## Incident Response

| Metric | Count | Notes |
|---|---|---|
| Playbook directories | 14 | One per CDET |
| Playbook files | 56 | triage.md, investigation.md, containment.md, recovery.md × 14 |
| Report templates | 3 | executive, analyst, investigation_summary |
| Enrichment documents | 2 | enrichment_schema.md, enrichment_workflow.md |
| SOC runbooks | 4 | triage guide, escalation matrix, on-call procedures, investigation standards |

---

## Attack Simulation

| Metric | Count | Notes |
|---|---|---|
| Simulation packages | 14 | One per CDET |
| Files per package | 4 | simulate.py, attack_description.md, expected_events.md, simulation_steps.md |
| Total simulation files | 56 | |
| Simulations with Python automation | 14 | Each simulate.py uses boto3 default chain |
| Simulations with manual steps | 14 | Each simulation_steps.md |

---

## Security Automation (Python)

| Metric | Count | Notes |
|---|---|---|
| Main automation scripts | 5 | cloudtrail_parser, ioc_extractor, alert_enrichment, detection_validator, incident_report_generator |
| Collector modules | 9 | base, cloudtrail, iam, guardduty, securityhub, security_group, collect_cli, schema, __init__ |
| Total Python modules | 14 | |
| Lines using hardcoded credentials | 0 | All use boto3.Session() default chain |
| Detection heuristics (Python) | 14 | One detector function per CDET in detection_validator.py |
| IOC types extracted | 8 | IP, ARN, access key, account ID, S3 path, EC2 ID, assumed-role session, hostname |
| Report output formats | 3 | Markdown executive, Markdown analyst, JSON summary |

---

## Documentation

| Metric | Count | Notes |
|---|---|---|
| Architecture docs | 8 | docs/architecture/ |
| Detection engineering guides | 5 | docs/detection_engineering/ |
| MITRE mapping docs | 3 | docs/mitre_mapping/ |
| Coverage reporting docs | 2 | docs/coverage_reporting/ |
| SOC operations docs | 4 | docs/soc_operations/ |
| Splunk integration docs | 3 | docs/splunk/ |
| Validation guides | 3 | docs/validation/ |
| Total documentation files | ~45 | Across all docs/ subdirectories |

---

## Repository Health

| Metric | Value |
|---|---|
| Total Python dependencies | 28 |
| Credential security violations | 0 |
| Hardcoded AWS account IDs in code | 0 (test data only: 123456789012) |
| Detection YAML files with test_cases sections | 14 |
| Detection YAML files with validation sections | 14 |

---

## Phase Completion Status

| Phase | Deliverables | Status |
|---|---|---|
| Phase 1 — Architecture & Framework | Repo structure, detection templates, collector base | Complete |
| Phase 2 — Detection Library | 14 CDETs, 14 SPL queries, Splunk lookups | Complete |
| Phase 3 — Validation & Telemetry | 42 test cases, 53 sample logs, validation matrix | Complete |
| Phase 4 — IR & Automation | 56 playbooks, 5 scripts, 4 SOC runbooks, 3 report templates | Complete |
| Phase 4.5 — Integration Validation | End-to-end workflow docs, ingestion guides, portfolio evidence | Complete |
| Phase 5 — Dashboards | Splunk dashboards (4 planned) | Pending |
