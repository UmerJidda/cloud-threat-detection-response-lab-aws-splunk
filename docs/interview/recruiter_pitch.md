# Recruiter Pitch — Cloud Threat Detection Lab

---

## 60-Second Verbal Pitch (Phone Screen Script)

"I recently built a cloud threat detection lab from scratch to demonstrate the full detection engineering lifecycle in an AWS environment.

The project covers 14 production-style detections mapped across 9 MITRE ATT&CK tactics — everything from initial access through impact — using real AWS CloudTrail, GuardDuty, and Security Hub log sources.

I engineered the detections in Splunk SPL with lookup-based suppression tables so the SOC team can tune false positives without touching SPL code. On the automation side I wrote Python using boto3 to collect CloudTrail events, enrich alerts with IAM context and ATT&CK metadata, and run a pre-deployment quality gate that validates each detection's structure and field coverage before it ever reaches Splunk. I also built Splunk dashboards for detection health monitoring and ATT&CK coverage reporting.

Every detection ships with a four-file incident response playbook — triage, investigation, containment, and lessons learned — and a test matrix covering positive, negative, and edge-case scenarios.

This project is directly relevant to the role you are hiring for because it demonstrates not just writing detections but owning the entire pipeline: threat modelling, engineering, testing, tuning, and response documentation.

I would be happy to walk you through a specific detection end-to-end — say CDET-001 on IAM user creation or CDET-007 on EC2 instance metadata credential abuse — to show how all those layers fit together."

---

## Written Summary (LinkedIn / Portfolio / Email)

I designed and built a cloud threat detection and response lab covering the complete detection engineering lifecycle for AWS environments. The project delivers 14 detections mapped to MITRE ATT&CK across 9 tactics, implemented in Splunk SPL with lookup-based suppression for maintainable false-positive management. A Python automation layer handles CloudTrail collection via boto3, pre-deployment detection validation, and per-alert enrichment with IAM context and ATT&CK metadata. Each detection is supported by structured incident response playbooks, a three-tier test matrix, and Splunk dashboards for detection health and ATT&CK coverage visibility.

---

## Keyword Index

| Keyword / Technology | Project Evidence |
|---|---|
| **Detection Engineering** | 14 detections built through the full lifecycle: threat model, SPL authoring, test cases, tuning, and playbooks. |
| **MITRE ATT&CK** | All 14 detections mapped to ATT&CK techniques across 9 tactics; ATT&CK context injected at alert enrichment time via `alert_enrichment.py`. |
| **Splunk SPL** | Production-ready SPL in `detection.spl` files per detection; saved searches in `splunk/savedsearches/`; dashboards in `splunk/dashboards/`. |
| **AWS CloudTrail** | Primary log source for all 14 detections; ingested via `ingestion/cloudtrail_ingestion.md` collector using `boto3.client("cloudtrail").lookup_events()`. |
| **AWS GuardDuty** | Secondary log source documented in `ingestion/guardduty_ingestion.md`; GuardDuty findings used to cross-validate detections. |
| **AWS Security Hub** | Integrated as an aggregation layer; documented in `ingestion/securityhub_ingestion.md`. |
| **Python / boto3** | `scripts/alert_enrichment.py`, `validation/validator.py`, and ingestion collectors all use boto3 default credential chain exclusively. |
| **SIEM** | Splunk is the production SIEM; detection scheduling, alert indexes (`cdet_alerts`), and validation indexes (`aws_cloudtrail_test`) are fully configured. |
| **Incident Response** | Four-file playbook structure per detection (triage, investigation, containment, lessons learned) in `incident_response/playbooks/`. |
| **Threat Detection** | End-to-end detection engineering covering persistence, privilege escalation, defense evasion, lateral movement, credential access, discovery, exfiltration, and impact. |
| **Security Automation** | Alert enrichment pipeline in `scripts/alert_enrichment.py`; validation automation in `validation/validator.py`; automated positive/negative validation saved searches. |
| **Alert Triage** | Triage playbook files define a 10-minute triage workflow for each detection; enriched alert output includes recommended SPL investigation queries. |
| **False Positive Management** | Lookup-based suppression using `splunk/lookups/approved_iam_principals.csv` and `automation_role_arns.csv`; suppression reasons documented per detection YAML. |
| **IOC Extraction** | Alert enrichment extracts actor ARN, source IP, region, and target resource as structured IOC fields on every alert. |
| **Alert Enrichment** | `scripts/alert_enrichment.py` applies five enrichment stages: ATT&CK context, severity escalation, lookup context, IAM context via boto3, and investigation query generation. |
