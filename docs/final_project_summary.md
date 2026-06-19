---
title: Cloud Threat Detection Lab — Final Project Summary
version: "1.0.0"
last_updated: 2026-06-19
phase: Complete (Phase 4.5)
author: Umer Jidda
---

# Cloud Threat Detection Lab — Final Project Summary

---

## Executive Summary

The Cloud Threat Detection Lab is a production-quality cloud detection engineering program that implements the complete lifecycle of a mature Security Operations Center: telemetry collection from AWS, detection authoring in Splunk SPL, alert enrichment in Python, and structured incident response playbooks. The project spans 14 detection rules mapped to the MITRE ATT&CK framework, 9 adversary tactics, 13 unique techniques, and is supported by 42 automated test cases, 53 sample log files, 56 incident response playbook documents, and 14 attack simulation packages — all organized as a coherent, navigable engineering platform rather than a collection of ad-hoc scripts.

The core problem this project addresses is the gap that exists in most cloud security programs between detection ideas and operational detections. A detection idea that is never validated against realistic telemetry, never stress-tested against benign edge cases, never enriched with ATT&CK context, and never paired with a response playbook is not a functioning detection — it is a wish. This project demonstrates every discipline required to close that gap: Python-based telemetry collectors using the boto3 default credential chain, NDJSON test corpora that exercise each SPL rule before it reaches Splunk, layered suppression logic using lookup CSVs at query time and Python approval gates at runtime, and a reporting pipeline that produces audience-appropriate output (executive summary, analyst report, or JSON) from the same enriched alert object.

The technologies integrated span cloud infrastructure (AWS CloudTrail, GuardDuty, SecurityHub, IAM, EC2, S3, STS, Organizations), a commercial SIEM (Splunk Enterprise with SPL, savedsearches.conf, transforms.conf, props.conf, and Simple XML dashboards), and 28 Python dependencies organized around boto3, structlog, click, and rich. Throughout the entire codebase — across 14 detection YAML files, 14 simulate.py packages, 9 collector modules, and 5 main automation scripts — the hardcoded credential count is zero. Every AWS call resolves credentials through `boto3.Session()` using the platform-standard default provider chain.

---

## Complete Component Inventory

| Component | Count | Location | Purpose |
|---|---|---|---|
| Detection rules (YAML + SPL) | 14 | `detections/` | MITRE ATT&CK-mapped detection definitions with metadata, suppression lookups, and test case references |
| Splunk saved searches | 14 | `splunk/savedsearches/` | SPL-backed saved searches for validation, coverage reporting, and detection health monitoring |
| Splunk lookup tables (CSV) | 11 | `splunk/lookups/` | Suppression and context-enrichment lookup files (approved principals, CIDR ranges, privileged users, etc.) |
| Splunk dashboards | 4 | `splunk/dashboards/` | Simple XML dashboards for detection overview, coverage, health, and IR tracking |
| NDJSON sample log files | 53 | `sample_logs/` | Malicious, benign, and edge-case synthetic telemetry covering CloudTrail, GuardDuty, and SecurityHub |
| Test cases | 42 | `detections/*/detection.yaml` | Positive, negative, and edge-case test cases (3 per detection) with expected alert/suppress outcomes |
| Attack simulation packages | 14 | `attack_simulations/` | Per-CDET packages: simulate.py, attack_description.md, expected_events.md, simulation_steps.md |
| Incident response playbooks | 56 | `playbooks/` | Four-phase playbooks per detection: triage.md, investigation.md, containment.md, recovery.md |
| Python main scripts | 5 | `scripts/` | cloudtrail_parser.py, ioc_extractor.py, alert_enrichment.py, detection_validator.py, incident_report_generator.py |
| Python collector modules | 9 | `scripts/aws_collectors/` | base_collector.py, cloudtrail_collector.py, iam_collector.py, guardduty_collector.py, securityhub_collector.py, security_group_collector.py, collect_cli.py, schema.py, \_\_init\_\_.py |
| SOC runbooks | 4 | `docs/soc_operations/` | alert_triage_guide.md, escalation_matrix.md, on_call_procedures.md, investigation_standards.md |
| Report templates | 3 | `templates/` | Executive summary, analyst report, investigation summary |
| Architecture documents | 8 | `docs/architecture/` | Solution, detection, IR, repository design, telemetry flow, and telemetry pipeline documentation |
| MITRE ATT&CK mapping docs | 3 | `docs/mitre_mapping/` | Tactic/technique coverage maps and cloud ATT&CK scope analysis |
| Splunk integration docs | 3 | `docs/splunk/` | Index strategy, field mapping, and dashboard strategy |
| Validation guides | 3 | `docs/validation/` | Test methodology, NDJSON format specification, and validation matrix |
| Python dependencies | 28 | `requirements.txt` | boto3, splunk-sdk, click, rich, structlog, PyYAML, jsonschema, requests, and supporting libraries |
| Hardcoded credentials | 0 | Entire repository | No AWS access keys, secret keys, or account IDs in code (placeholder account 123456789012 in test data only) |

---

## MITRE ATT&CK Coverage Table

| Tactic | Technique ID | Technique Name | CDET ID | Detection Name | Severity |
|---|---|---|---|---|---|
| Persistence | T1136.003 | Create Account: Cloud Account | CDET-001 | IAM User Created Outside Approved Pipeline | High |
| Persistence | T1098.001 | Account Manipulation: Additional Cloud Credentials | CDET-002 | IAM Access Key Created for Existing User | Medium |
| Defense Evasion | T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | CDET-003 | CloudTrail Logging Disabled | Critical |
| Privilege Escalation | T1078.004 | Valid Accounts: Cloud Accounts | CDET-004 | Admin Policy Attached to Principal Outside Pipeline | High |
| Privilege Escalation | T1484.002 | Domain or Tenant Policy Modification: Trust Modification | CDET-005 | Cross-Account Role Trust Modified | High |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | CDET-006 | Root Account Activity | Critical |
| Credential Access | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | CDET-007 | EC2 Instance Metadata Credential Abuse | High |
| Discovery | T1580 | Cloud Infrastructure Discovery | CDET-008 | Excessive API Enumeration / Reconnaissance | Medium |
| Exfiltration | T1537 | Transfer Data to Cloud Account | CDET-009 | S3 Replication to External Account | High |
| Impact | T1485 | Data Destruction | CDET-010 | Mass S3 Object Deletion | Critical |
| Impact | T1496 | Resource Hijacking | CDET-011 | Unauthorized Compute Resource Launch | High |
| Lateral Movement | T1550.001 | Use Alternate Authentication Material: Application Access Token | CDET-012 | Cross-Account AssumeRole Chain | High |
| Defense Evasion | T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | CDET-013 | Security Group Rule Opens World-Accessible Port | Medium |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | CDET-014 | CloudTrail Log File Deleted from S3 | Critical |

**Coverage note:** T1078.004 (Valid Accounts: Cloud Accounts) is intentionally covered by two detections — CDET-004 and CDET-006 — because root account misuse and unauthorized IAM privilege escalation represent distinct adversary intents and require different response actions, even though MITRE maps both to the same technique identifier.

---

## Detection Engineering Lifecycle Demonstrated

The following walkthrough uses CDET-001 (IAM User Created Outside Approved Pipeline) as a concrete example of how each stage of the detection engineering lifecycle is represented in the repository.

**1. Threat Identification**
The threat hypothesis originates from the MITRE ATT&CK cloud matrix: an adversary who has obtained administrative credentials may create a new IAM user to establish durable persistence that survives credential rotation. The threat is documented in `attack_simulations/CDET-001_iam_user_created_outside_pipeline/attack_description.md`, which records the adversary objective, prerequisites, and expected blast radius.

**2. Telemetry Mapping**
The detection engineer identifies that `iam:CreateUser` API calls are recorded in CloudTrail with `eventSource=iam.amazonaws.com` and that the acting principal's identity is available in `userIdentity.arn`. The required fields and their source paths are codified in `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.yaml` under the `data_sources` and `required_fields` keys.

**3. Test Case Authoring (Test-First)**
Before writing SPL, three NDJSON test events are authored under `sample_logs/cloudtrail/malicious/`, `sample_logs/cloudtrail/benign/`, and `sample_logs/cloudtrail/edge_cases/`. The malicious event captures an unknown interactive principal creating a user. The benign event captures a Terraform pipeline role performing the same action — the suppression case. The edge case captures a `CreateUser` call that returned `AccessDenied`, which must not alert. The expected outcomes for all three are declared in `detection.yaml` under `test_cases`.

**4. SPL Detection Authoring**
`detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.spl` implements the rule. The search filters for `eventName=CreateUser` and `NOT errorCode=*` (successful calls only), normalizes the acting principal ARN, applies the `approved_iam_principals` and `automation_role_arns` lookup CSVs to suppress known-good pipeline activity, evaluates confidence based on whether MFA was in use, and appends detection metadata (`detection_id`, `tactic`, `technique`) to every alert row. The SPL does not embed any account IDs or hardcoded ARNs — all suppression is lookup-driven.

**5. Splunk Lookup Configuration**
Two lookup CSV files in `splunk/lookups/` back the suppression logic: `approved_iam_principals.csv` (IAM ARNs belonging to approved provisioning pipelines) and `automation_role_arns.csv` (CI/CD and automation roles). The lookup is registered in `splunk/savedsearches/` so that operators can manage suppression entries without touching SPL.

**6. Python Heuristic Validation**
`scripts/detection_validator.py` contains an independent Python implementation of the CDET-001 heuristic — a `detect_cdet001()` function that processes parsed CloudTrail events and applies the same approval-gate logic via an `_is_approved()` helper. This validator runs against the NDJSON test corpus without requiring a Splunk instance, enabling regression testing in CI before any SPL promotion.

**7. Attack Simulation**
`attack_simulations/CDET-001_iam_user_created_outside_pipeline/simulate.py` uses `boto3.Session()` (default credential chain, no hardcoded keys) to call `iam:CreateUser` from a non-pipeline identity. `simulation_steps.md` documents the manual equivalent for environments where automated simulation is not permitted. `expected_events.md` specifies the exact CloudTrail event shape the simulation should produce, enabling validation that the simulation actually generates the intended telemetry.

**8. Incident Response Playbook**
`playbooks/CDET-001_iam_user_created_outside_pipeline/` contains four documents. `triage.md` defines the initial severity assessment and immediate questions the analyst must answer within the first 15 minutes. `investigation.md` provides the step-by-step investigation procedure including SPL queries to pivot on the created user. `containment.md` describes disabling the user, revoking active sessions, and preserving the CloudTrail evidence chain. `recovery.md` covers post-containment remediation and lessons-learned capture.

**9. Enrichment and Reporting**
When an alert fires, `scripts/alert_enrichment.py` adds ATT&CK tactic and technique context from a local lookup, calls `scripts/ioc_extractor.py` to pull structured IOCs (ARN, IP, access key ID) from the alert fields, and optionally calls the IAM API to retrieve the created user's current permission state. `scripts/incident_report_generator.py` then produces three outputs from the same enriched alert object: a Markdown executive summary, a Markdown analyst report with full event detail, and a JSON summary for SOAR or ticketing system ingestion.

**10. Operational Monitoring**
The Splunk saved searches in `splunk/savedsearches/detection_health.conf` monitor the health of the detection itself: data freshness, event volume anomalies, and false-positive rate trends. The `splunk/savedsearches/coverage_reporting.conf` tracks ATT&CK tactic and technique coverage over time. The `docs/soc_operations/investigation_standards.md` runbook defines SLA expectations, escalation paths, and documentation requirements for every CDET-001 alert that reaches a human analyst.

---

## Technical Architecture Highlights

**1. Credential Security: boto3 Default Chain, Zero Hardcoded Credentials**
Every Python file in this repository — collectors, simulators, enrichment scripts, and report generators — obtains AWS credentials exclusively through `boto3.Session()` with no explicit credential arguments. This means the code supports all standard credential mechanisms (environment variables, `~/.aws/credentials`, EC2 instance profiles, ECS task roles, SSO) without modification. A grep for hardcoded key patterns across the entire repository returns zero results. The placeholder account ID `123456789012` appears only in NDJSON test data and is never referenced in production code paths.

**2. Test-Driven Detection: NDJSON Corpus Before SPL Deployment**
The validation philosophy mirrors software TDD: before a SPL rule is written, three NDJSON test events must exist — one that should fire, one that should be suppressed, and one that exercises a boundary condition. The `scripts/detection_validator.py` script runs Python heuristics against the full 53-file corpus and produces a pass/fail matrix. This Splunk-independent quality gate means a detection engineer can iterate on logic locally and catch regressions without deploying to a SIEM, which is critical in environments where Splunk promotion involves a change management process.

**3. Layered Suppression: Lookup CSV at SPL Time + `_is_approved()` at Python Time**
Suppression is implemented at two independent layers. In SPL, `| lookup approved_iam_principals` and `| lookup automation_role_arns` filter known-good pipeline principals before the alert is created. In Python, `detection_validator.py` implements the equivalent `_is_approved()` function that checks the same principal against an in-memory set loaded from the CSV files. This layering means a suppression entry added to the CSV takes effect both in Splunk (preventing noisy alerts) and in the Python test harness (preventing false test failures). Neither layer depends on the other being present, which makes both independently deployable and testable.

**4. Separation of Concerns: Collect → Parse → Detect → Enrich → Respond**
Each automation stage is a separate Python module with a defined input and output contract. `aws_collectors/cloudtrail_collector.py` writes raw NDJSON to `data/collected/`. `scripts/cloudtrail_parser.py` reads that NDJSON and emits a list of typed `ParsedEvent` dataclass instances. `scripts/detection_validator.py` consumes `ParsedEvent` lists and emits structured alert dicts. `scripts/alert_enrichment.py` consumes alert dicts and emits enriched alert dicts. `scripts/incident_report_generator.py` consumes enriched alert dicts and writes formatted reports. No module reaches into another module's stage. This means the collector can be replaced with a Splunk Heavy Forwarder, or the enrichment layer can be called from a Lambda, without touching any other component.

**5. Audience-Appropriate Outputs: Executive, Analyst, and JSON from One Enriched Alert**
`scripts/incident_report_generator.py` produces three output formats from the same enriched alert object. The executive report is a two-page Markdown summary emphasizing business risk, affected resources, and recommended executive actions with no SPL or API call details. The analyst report includes the full event timeline, raw CloudTrail fields, IOC table, ATT&CK technique description, and step-by-step investigation queries. The JSON summary is a flat key-value structure suitable for ingestion by a ticketing system, SOAR platform, or downstream analytics pipeline. The caller selects the format via a CLI flag; the enrichment logic runs once regardless of which format is requested.

---

## Data Sources and AWS Services

| AWS Service | Data Source | Collector Module | Splunk Index | CDETs Covered |
|---|---|---|---|---|
| CloudTrail | Management API events (all regions) | `cloudtrail_collector.py` | `aws_cloudtrail` | CDET-001 through CDET-014 (primary source for 12 of 14) |
| GuardDuty | ML-generated threat findings (ASFF) | `guardduty_collector.py` | `aws_guardduty` | CDET-007, CDET-008 (supplementary enrichment) |
| SecurityHub | Aggregated findings (ASFF, cross-account) | `securityhub_collector.py` | `aws_securityhub` | CDET-003, CDET-013 (compliance signal correlation) |
| IAM | User, role, and policy state snapshots | `iam_collector.py` | `aws_iam` | CDET-001, CDET-002, CDET-004, CDET-005 (enrichment) |
| EC2 / VPC | Security group rules, instance metadata | `security_group_collector.py` | `aws_vpc` | CDET-011, CDET-013 |
| S3 | Object-level access logs, bucket policy | CloudTrail (S3 data events) | `aws_cloudtrail` | CDET-009, CDET-010, CDET-014 |
| STS | AssumeRole session telemetry | CloudTrail (management events) | `aws_cloudtrail` | CDET-012 |
| Organizations | Cross-account trust relationships | CloudTrail (management events) | `aws_cloudtrail` | CDET-005, CDET-012 |

---

## Lessons Learned

**1. NDJSON per-line format is non-negotiable for Splunk ingestion.**
Early test files used JSON arrays (`[{...}, {...}]`), which Splunk ingests as a single event rather than multiple events. Switching to NDJSON (one JSON object per line, no array wrapper) caused each record to index as an independent event with its own `_time` field. This is not a Splunk quirk — it is the de facto standard for log streaming (used by CloudTrail S3 delivery, Kinesis Firehose, and most SIEM ingest pipelines). Documenting this in `docs/validation/` saved significant debugging time during the validation phase.

**2. `detection_validator.py` exists because Splunk is not always available.**
The original plan was to validate detections exclusively via Splunk's REST API. In practice, iterating on SPL logic requires a running Splunk instance, indexed test data, and a saved search promotion workflow. By implementing equivalent Python heuristics in `detection_validator.py`, detection logic could be validated against the NDJSON corpus in under a second with no external dependencies. This also revealed two cases where the SPL and the Python heuristic had subtly different `errorCode` filter semantics — discrepancies that would have produced false negatives in production.

**3. Edge-case test events are harder to author than positive tests.**
Writing a positive test event means capturing a real malicious action and verifying the detection fires. Writing an edge-case test event means reasoning about every boundary the detection might not handle correctly: an API call that failed authorization, an action performed by an approved principal through an unexpected session type, or a timing boundary in a rate-based detection. CDET-008 (Excessive API Enumeration) required four edge-case iterations before the threshold logic correctly distinguished a legitimate automated scanner running a compliance check from an adversary conducting reconnaissance. Edge cases directly informed two suppression lookup additions that would otherwise have generated analyst noise in production.

**4. Separating ATT&CK lookup enrichment from live IAM API calls was the right architectural choice.**
An early enrichment design called the IAM API during alert enrichment to retrieve the current state of the affected principal. This created a coupling between alert processing speed and IAM API rate limits — a problem in burst-alert scenarios. The final design separates enrichment into two layers: a fast, offline lookup against a local ATT&CK technique description table (no API calls, always available), and an optional slow layer that calls the IAM API only when the analyst explicitly requests additional context. This mirrors the pattern used in production SOAR playbooks, where automated enrichment is cheap and fast, while human-initiated enrichment is richer but slower.

**5. Suppression lookup governance is a continuous process, not a one-time configuration.**
The initial suppression lookups were populated with placeholder entries. During simulation testing, three legitimate CI/CD role ARNs generated alerts because they had not been added to `approved_iam_principals.csv`. This reinforced that suppression lookup maintenance must be a defined operational process — not an afterthought. The `docs/soc_operations/alert_triage_guide.md` runbook includes a dedicated section on lookup update procedures and the `investigation_standards.md` runbook requires analysts to evaluate whether each alert represents a suppression gap before closing a true-positive ticket.

**6. Detection YAML as the single source of truth simplifies everything downstream.**
Storing the detection's tactic, technique, severity, lookup dependencies, test case references, and playbook path in a single `detection.yaml` file per CDET means that coverage reports, validation matrices, and the project metrics document are all derived from the same authoritative source. When CDET-014 was reclassified from Medium to Critical severity, one field change in `detection.yaml` was reflected automatically in the coverage report, the Splunk saved search metadata, and the playbook preamble — rather than requiring four separate edits across four separate files.

**7. Realistic test data requires understanding what benign traffic actually looks like.**
The initial benign test events were minimal — just enough to not trigger the detection. Replacing them with realistic benign events (Terraform pipeline creating an IAM user, a scheduled Lambda rotating an access key, a CloudFormation stack deploying a service role) exposed false-positive scenarios that had not been considered during SPL authoring. Two SPL rules required suppression logic additions after realistic benign telemetry was introduced. This lesson reinforces that a detection validated only against malicious telemetry is half-validated.

---

## Production Considerations

The following changes would be required to deploy this detection program in a real enterprise environment:

**CI/CD Pipeline for Detection Regression Testing**
The Python validation framework in `scripts/detection_validator.py` is designed to run as a CI step. A production deployment would add a GitHub Actions or Jenkins pipeline that runs the full 42-test-case validation suite on every pull request to the `detections/` directory. A detection that breaks a previously passing test case cannot be merged. SPL promotion to the Splunk production environment would gate on a green CI run.

**Real-Time Ingestion via Splunk Add-on for AWS**
The current collector design polls AWS APIs on a configurable interval. A production deployment would replace the polling collectors with the [Splunk Add-on for Amazon Web Services](https://splunkbase.splunk.com/app/1876), which provides SQS-based CloudTrail delivery (sub-minute latency), native GuardDuty integration, and SecurityHub ASFF parsing with maintained field extraction. The `props.conf` and `transforms.conf` configuration in `splunk/` is already structured to be compatible with the Add-on's source type naming conventions.

**Multi-Account AWS Organizations Integration**
The current architecture targets a single AWS account. Enterprise deployments operate across tens or hundreds of accounts managed through AWS Organizations. The collector modules would need to be extended to iterate over the Organizations account list, assume a read-only cross-account role in each member account, and tag all collected events with the source account ID. The `approved_aws_accounts.csv` lookup in `splunk/lookups/` is pre-staged for this extension.

**SOAR/XSOAR Integration for Automated Containment**
The JSON output format from `scripts/incident_report_generator.py` is designed to be ingested by a SOAR platform. A production deployment would configure the SOAR to call the containment actions in `playbooks/*/containment.md` automatically for Critical-severity alerts (CDET-003, CDET-006, CDET-010, CDET-014) and semi-automatically (analyst approval required) for High-severity alerts. The `attack_simulations/*/simulate.py` scripts serve as the basis for SOAR playbook testing via Atomic Red Team integration.

**Threat Intelligence Feed Enrichment**
The IOC extractor in `scripts/ioc_extractor.py` outputs structured IOC objects (IPs, ARNs, access key IDs) but does not currently cross-reference them against threat intelligence feeds. A production deployment would add a TI enrichment step that queries a feed (MISP, Recorded Future, or an internal IOC database) for each extracted IP and access key, appending reputation scores and known-bad indicators to the enriched alert. This would enable automated severity escalation when a detected IP appears in an active threat campaign feed.

**SLA Enforcement and On-Call Rotation Tooling**
The `docs/soc_operations/on_call_procedures.md` runbook defines response SLAs (Critical: 15 minutes, High: 1 hour, Medium: 4 hours) but the current implementation has no automated SLA enforcement. A production deployment would integrate PagerDuty or OpsGenie with Splunk Adaptive Response to page on-call analysts when alerts breach their SLA threshold, and track mean time to acknowledge (MTTA) and mean time to resolve (MTTR) per detection rule.

**Detection Coverage Review Cadence**
The coverage reporting saved searches in `splunk/savedsearches/coverage_reporting.conf` produce ATT&CK gap analysis output, but a production program requires a defined review cadence. A quarterly detection coverage review would compare the current MITRE cloud technique universe against covered CDETs, prioritize new detections based on threat intelligence reporting and red team findings, and retire or tune detections whose false-positive rates exceed acceptable thresholds. The project metrics framework in `docs/project_metrics.md` is designed to feed directly into this review process.

---

## Project Timeline

| Phase | Description | Status |
|---|---|---|
| Phase 1 — Architecture and Framework | Established repository structure, detection YAML template, collector base class, Splunk index strategy, and the detection engineering lifecycle documentation. Deliverables: `docs/architecture/`, `scripts/aws_collectors/base_collector.py`, `detections/README.md`, `splunk/` configuration skeleton. | Complete |
| Phase 2 — Detection Library | Authored all 14 CDET detection rules, SPL queries, and supporting Splunk lookup tables. Each detection includes a complete YAML definition with ATT&CK mapping, severity, suppression lookup references, and test case declarations. Deliverables: `detections/` (all 14 CDETs), `splunk/lookups/` (11 CSV files), `splunk/savedsearches/` (14 saved searches across 3 conf files). | Complete |
| Phase 3 — Validation and Telemetry | Built the full NDJSON test corpus and Python validation framework. 53 synthetic sample log files across malicious, benign, and edge-case categories. 42 test cases exercising every suppression path and boundary condition. Deliverables: `sample_logs/` (53 NDJSON files), `scripts/detection_validator.py`, `docs/validation/`. | Complete |
| Phase 4 — IR and Automation | Authored 56 incident response playbook files across 14 CDET directories, 5 Python automation scripts, 3 report templates, and 4 SOC operations runbooks. Deliverables: `playbooks/` (56 .md files), `scripts/alert_enrichment.py`, `scripts/ioc_extractor.py`, `scripts/cloudtrail_parser.py`, `scripts/incident_report_generator.py`, `attack_simulations/` (14 packages, 56 files), `docs/soc_operations/`. | Complete |
| Phase 4.5 — Integration Validation | End-to-end workflow documentation, ingestion guides connecting the Python collectors to Splunk ingest, portfolio evidence artifacts, and the project metrics summary. Deliverables: `docs/integration/`, `docs/walkthrough/`, `docs/portfolio/`, `docs/project_metrics.md`. | Complete |
| Phase 5 — Dashboards | Four Splunk Simple XML dashboards covering detection overview, ATT&CK coverage, detection health, and incident response tracking. | Pending |

---

## Technologies and Skills Demonstrated

| Domain | Technologies |
|---|---|
| Cloud | AWS, CloudTrail (management and data events), GuardDuty (ML threat detection), SecurityHub (ASFF aggregation), IAM (user/role/policy management), EC2 (instance metadata, security groups), S3 (object storage, replication), STS (AssumeRole, session tokens), Organizations (multi-account trust) |
| SIEM | Splunk Enterprise, SPL (Search Processing Language), savedsearches.conf, props.conf, transforms.conf, inputs.conf, macros.conf, lookup commands, tstats, data model acceleration, Simple XML dashboards |
| Programming | Python 3.11, boto3, botocore, structlog, click, rich, dataclasses, type hints, PyYAML, jsonschema, requests, splunk-sdk |
| Frameworks | MITRE ATT&CK v15 (cloud matrix, tactic/technique/sub-technique mapping), Amazon Security Finding Format (ASFF), detection engineering lifecycle (identify → test → author → validate → simulate → respond → monitor) |
| Formats and Standards | NDJSON (per-line JSON for log streaming), YAML (detection definitions), JSON (alert enrichment schema, report output), Markdown (playbooks, runbooks, documentation), Mermaid (architecture diagrams in docs) |

---

*This document was authored as part of the Cloud Threat Detection Lab portfolio project. All metrics are derived from the live repository as of Phase 4.5 completion. The project repository is organized to support independent review of each component referenced above.*
