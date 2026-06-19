# Cloud Threat Detection Lab

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Splunk](https://img.shields.io/badge/splunk-9.x-green.svg)](https://www.splunk.com/)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail%20%7C%20GuardDuty%20%7C%20SecurityHub-orange.svg)](https://aws.amazon.com/security/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A production-quality cloud detection engineering program demonstrating the complete lifecycle: AWS telemetry collection → Splunk detection → alert enrichment → automated incident response. Built to reflect real-world enterprise cloud security operations.

---

## What This Project Demonstrates

This repository is a **complete cloud detection engineering program** — not a collection of scripts, but a structured platform with the same components a mature SOC operates:

| Capability | What's Built | Files |
|---|---|---|
| **AWS Telemetry Collection** | 9 Python collector modules, read-only boto3, all 4 major log sources | `scripts/aws_collectors/` |
| **Detection Library** | 14 MITRE ATT&CK–mapped Splunk detections across 9 tactics | `detections/` |
| **Sample Telemetry** | 53 NDJSON test files — malicious, benign, and edge-case variants | `sample_logs/` |
| **Detection Validation** | 42 test cases + Python heuristic validator + Splunk SPL tests | `validation/` |
| **Attack Simulations** | 14 documented simulation packages with executable Python | `attack_simulations/` |
| **Alert Enrichment** | ATT&CK context, IAM enrichment, severity escalation, IOC extraction | `scripts/alert_enrichment.py` |
| **Incident Response** | 56 playbook files (triage → investigation → containment → recovery) | `playbooks/` |
| **Automated Reporting** | 3 report formats: executive summary, analyst report, JSON | `scripts/incident_report_generator.py` |
| **Splunk Dashboards** | 4 production-ready dashboard XMLs with SPL-backed panels | `splunk/dashboards/` |
| **SOC Operations** | Escalation matrix, on-call procedures, investigation standards | `docs/soc_operations/` |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           AWS ENVIRONMENT                            │
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │ CloudTrail  │  │  GuardDuty  │  │ Security Hub │  │   IAM    │  │
│  │ (all APIs)  │  │  (ML alerts)│  │  (ASFF fmt)  │  │  state   │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘  └────┬─────┘  │
│         └────────────────┴─────────────────┴───────────────┘        │
│                                    │                                 │
└────────────────────────────────────┼─────────────────────────────────┘
                                     │ boto3 (aws configure)
                          ┌──────────▼──────────┐
                          │  Python Collectors   │
                          │  scripts/aws_collectors/
                          │  cloudtrail_collector│
                          │  guardduty_collector │
                          │  securityhub_collector
                          │  iam_collector       │
                          └──────────┬──────────┘
                                     │ NDJSON → data/collected/
                          ┌──────────▼──────────┐
                          │  CloudTrailParser    │
                          │  (cloudtrail_parser) │
                          │  → ParsedEvent list  │
                          └──────────┬──────────┘
                          ┌──────────▼──────────┐
                          │     Splunk SIEM      │
                          │  index=aws_cloudtrail│
                          │  index=aws_security  │
                          └──────────┬──────────┘
                 ┌────────────────────────────────────┐
                 │            Detection Layer          │
                 │  14 SPL searches — cron every 5min  │
                 │  11 lookup CSVs for suppression     │
                 │  index=cdet_alerts on match         │
                 └────────────────────┬───────────────┘
                          ┌──────────▼──────────┐
                          │   Alert Enrichment   │
                          │  ATT&CK context      │
                          │  IAM principal state │
                          │  Severity escalation │
                          │  IOC extraction      │
                          └──────────┬──────────┘
                 ┌────────────────────────────────────┐
                 │         Response Layer              │
                 │  Playbooks:  triage → investigate   │
                 │              contain → recover      │
                 │  Reports: executive / analyst / JSON│
                 │  SOC dashboards (4 XMLs)            │
                 └────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| Cloud Platform | AWS | — | CloudTrail, GuardDuty, SecurityHub, IAM, EC2, S3 |
| Telemetry Collection | Python + boto3 | 3.11 / 1.34 | Read-only API collection, NDJSON output |
| SIEM | Splunk Enterprise | 9.x | Detection, alerting, dashboards |
| Detection Logic | Splunk SPL | — | Correlation searches with lookup-based suppression |
| Validation | Python + pytest | 3.11 | Heuristic detectors mirroring SPL logic |
| Threat Framework | MITRE ATT&CK | v15 | TTP mapping, 9 tactics, 13 techniques |
| Structured Logging | structlog | 24.1 | Consistent log output across all Python modules |
| CLI | click + rich | 8.x / 13.x | Collector CLI, validation runner |

---

## Quick Start

### Prerequisites

- Python 3.11+
- AWS CLI configured (`aws configure`) — read-only Security Auditor role sufficient
- Splunk Enterprise 9.x (for live detection; sample data works offline)

```bash
git clone https://github.com/YOUR_USERNAME/CloudThreatDetectionLab.git
cd CloudThreatDetectionLab
pip install -r requirements.txt
aws configure          # enter your credentials once — all scripts use this
```

### Collect Live AWS Telemetry

```bash
# Collect CloudTrail events from the last 24 hours
python scripts/aws_collectors/collect_cli.py --service cloudtrail --region us-east-1

# Collect all sources
python scripts/aws_collectors/collect_cli.py --all --region us-east-1

# Output written to data/collected/cloudtrail_YYYYMMDD.ndjson
```

### Validate Detections Offline (No Splunk Required)

```bash
# Run Python heuristic validation against all 14 detections
python scripts/detection_validator.py

# Parse and inspect a sample log
python scripts/cloudtrail_parser.py
```

### Load Sample Data into Splunk

```bash
# Load a malicious sample to test CDET-001
/opt/splunk/bin/splunk add oneshot \
  sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson \
  -index aws_cloudtrail -sourcetype aws:cloudtrail:json

# Load all malicious samples at once
for f in sample_logs/cloudtrail/malicious/*.ndjson; do
  /opt/splunk/bin/splunk add oneshot "$f" -index aws_cloudtrail -sourcetype aws:cloudtrail:json
done
```

### Deploy Splunk Configuration

```bash
# Copy integration config to Splunk
cp splunk/integration/props.conf      $SPLUNK_HOME/etc/apps/cdet/default/
cp splunk/integration/transforms.conf $SPLUNK_HOME/etc/apps/cdet/default/
cp splunk/integration/inputs.conf     $SPLUNK_HOME/etc/apps/cdet/default/
cp splunk/lookups/*.csv               $SPLUNK_HOME/etc/apps/cdet/lookups/

# Import saved searches
cp splunk/savedsearches/*.conf        $SPLUNK_HOME/etc/apps/cdet/default/
/opt/splunk/bin/splunk restart
```

---

## Detection Coverage

14 detections across 9 MITRE ATT&CK tactics:

| ID | Detection Name | Tactic | Technique | Severity | Trigger Event |
|---|---|---|---|---|---|
| CDET-001 | IAM User Created Outside Pipeline | Persistence | T1136.003 | High | `CreateUser` |
| CDET-002 | Access Key Created for Another User | Persistence | T1098.001 | High | `CreateAccessKey` |
| CDET-003 | CloudTrail Logging Disabled | Defense Evasion | T1562.008 | **Critical** | `StopLogging` / `DeleteTrail` |
| CDET-004 | Admin Policy Attached Outside Pipeline | Privilege Escalation | T1078.004 | **Critical** | `AttachUserPolicy` |
| CDET-005 | Cross-Account Role Trust Modified | Privilege Escalation | T1484.002 | High | `UpdateAssumeRolePolicy` |
| CDET-006 | Root Account Activity | Initial Access | T1078.004 | **Critical** | Any (Root principal) |
| CDET-007 | EC2 Metadata Credential Abuse | Credential Access | T1552.005 | High | `AssumeRole` (EC2 role + ext IP) |
| CDET-008 | Excessive API Enumeration | Discovery | T1580 | Medium | `Describe*` / `List*` burst |
| CDET-009 | S3 Replication to External Account | Exfiltration | T1537 | High | `PutBucketReplication` |
| CDET-010 | Mass S3 Object Deletion | Impact | T1485 | **Critical** | `DeleteObjects` (≥50 keys) |
| CDET-011 | Unauthorized EC2 Instance Launch | Impact | T1496 | High | `RunInstances` |
| CDET-012 | Cross-Account Role Assumption Chain | Lateral Movement | T1550.001 | High | `AssumeRole` |
| CDET-013 | Security Group Opened to Internet | Defense Evasion | T1562.007 | High | `AuthorizeSecurityGroupIngress` |
| CDET-014 | CloudTrail Log File Deleted | Defense Evasion | T1070.004 | **Critical** | `DeleteObject` (AWSLogs/) |

### MITRE ATT&CK Coverage Map

```
Initial Access    ████░░░░░░  1/~10  (T1078.004)
Persistence       ████████░░  2/~8   (T1136.003, T1098.001)
Privilege Escal.  ████████░░  2/~8   (T1078.004, T1484.002)
Defense Evasion   ████████░░  3/~12  (T1562.008, T1562.007, T1070.004)
Credential Access ████░░░░░░  1/~6   (T1552.005)
Discovery         ████░░░░░░  1/~8   (T1580)
Lateral Movement  ████░░░░░░  1/~6   (T1550.001)
Exfiltration      ████░░░░░░  1/~6   (T1537)
Impact            ████████░░  2/~8   (T1485, T1496)
```

---

## Repository Structure

```
CloudThreatDetectionLab/
│
├── README.md                          # This file
├── requirements.txt                   # Python dependencies (28 packages)
│
├── scripts/
│   ├── aws_collectors/                # AWS telemetry collection
│   │   ├── base_collector.py          # Abstract base, CollectorResult, boto3 pattern
│   │   ├── cloudtrail_collector.py    # CloudTrail LookupEvents (paginated)
│   │   ├── iam_collector.py           # IAM users, roles, keys, policies
│   │   ├── guardduty_collector.py     # GuardDuty findings (all regions)
│   │   ├── securityhub_collector.py   # SecurityHub ASFF findings
│   │   ├── security_group_collector.py# EC2 security group rules
│   │   ├── schema.py                  # Shared dataclasses and enums
│   │   └── collect_cli.py             # click CLI entrypoint
│   ├── cloudtrail_parser.py           # NDJSON → ParsedEvent normalizer
│   ├── ioc_extractor.py               # IOC extraction (IPs, ARNs, access keys)
│   ├── alert_enrichment.py            # ATT&CK + IAM + severity enrichment
│   ├── detection_validator.py         # Python mirrors of all 14 SPL detections
│   └── incident_report_generator.py   # Executive / analyst / JSON report output
│
├── detections/                        # Detection rules organized by tactic
│   ├── persistence/                   # CDET-001, CDET-002
│   ├── privilege_escalation/          # CDET-004, CDET-005
│   ├── defense_evasion/               # CDET-003, CDET-013, CDET-014
│   ├── credential_access/             # CDET-007
│   ├── discovery/                     # CDET-008
│   ├── lateral_movement/              # CDET-012
│   ├── exfiltration/                  # CDET-009
│   ├── impact/                        # CDET-010, CDET-011
│   └── initial_access/                # CDET-006
│
├── sample_logs/                       # 53 NDJSON test files
│   ├── cloudtrail/malicious/          # 14 positive-test events (one per CDET)
│   ├── cloudtrail/benign/             # 14 negative-test events + 5 normal activity
│   ├── cloudtrail/edge_cases/         # 14 boundary-condition events
│   ├── guardduty/malicious/           # 2 GuardDuty finding samples
│   └── securityhub/findings/          # 2 SecurityHub ASFF samples
│
├── validation/
│   ├── schema.py                      # TestCase, ValidationResult dataclasses
│   ├── validator.py                   # Core validation runner
│   ├── validation_matrix.md           # Coverage matrix — all 14 CDETs
│   ├── test_cases/                    # 14 × 6 files = 84 test artifacts
│   │   └── CDET-XXX_*/
│   │       ├── expected_alert.json    # Required alert fields + values
│   │       ├── positive_case.md       # What should trigger
│   │       ├── negative_case.md       # What should be suppressed
│   │       ├── edge_case.md           # Boundary behaviour
│   │       └── checklist.md           # Promotion gate
│   └── results/                       # Per-CDET validation result docs (14 files)
│
├── attack_simulations/                # 14 packages × 4 files = 56 files
│   └── CDET-XXX_<name>/
│       ├── attack_description.md      # Adversary perspective and TTPs
│       ├── simulation_steps.md        # Manual step-by-step AWS CLI procedure
│       ├── expected_events.md         # CloudTrail events the attack generates
│       └── simulate.py                # Automated simulation (dry-run safe)
│
├── playbooks/                         # 14 × 4 files = 56 files
│   └── CDET-XXX_<name>/
│       ├── triage.md                  # First-responder checklist (10 min)
│       ├── investigation.md           # Technical deep-dive procedure
│       ├── containment.md             # Stop the attack (with approval gates)
│       └── recovery.md                # Restore and harden
│
├── splunk/
│   ├── dashboards/                    # 4 dashboard XMLs (Simple XML)
│   │   ├── soc_dashboard.xml          # Real-time alert queue, health KPIs
│   │   ├── cloud_security_dashboard.xml  # AWS coverage by service/region
│   │   ├── detection_engineering_dashboard.xml  # Validation metrics, coverage
│   │   └── executive_dashboard.xml    # Executive KPIs, tactic coverage
│   ├── lookups/                       # 11 suppression CSV tables
│   │   ├── approved_iam_principals.csv
│   │   ├── automation_role_arns.csv
│   │   ├── admin_policy_arns.csv
│   │   ├── approved_aws_accounts.csv
│   │   └── ...
│   ├── savedsearches/                 # 14 saved searches across 3 conf files
│   │   ├── detection_validation.conf
│   │   ├── coverage_reporting.conf
│   │   └── detection_health.conf
│   └── integration/                   # Splunk app configuration
│       ├── props.conf                 # Sourcetype + field alias definitions
│       ├── transforms.conf            # Lookup table registrations
│       ├── inputs.conf                # Monitor + HEC input stanzas
│       └── savedsearches.conf         # Integration smoke-test searches
│
├── enrichment/
│   ├── enrichment_schema.md           # EnrichedAlert field documentation
│   └── enrichment_workflow.md         # End-to-end enrichment pipeline guide
│
├── reports/
│   ├── executive_report_template.md
│   ├── analyst_report_template.md
│   └── investigation_summary_template.md
│
├── ingestion/                         # Per-source ingestion workflow guides
│   ├── cloudtrail_ingestion.md
│   ├── iam_ingestion.md
│   ├── securityhub_ingestion.md
│   └── guardduty_ingestion.md
│
└── docs/
    ├── project_metrics.md             # Repository-wide metrics summary
    ├── final_project_summary.md       # Project summary with lessons learned
    ├── integration/                   # End-to-end workflow documentation
    ├── architecture/                  # Architecture docs (8 files)
    ├── detection_engineering/         # DE standards, SPL guidelines (5 files)
    ├── soc_operations/                # SOC runbooks (4 files)
    ├── portfolio/                     # Recruiter and interview documentation
    ├── interview/                     # Interview preparation guides
    ├── dashboards/                    # Dashboard panel documentation
    ├── diagrams/                      # Mermaid architecture diagrams
    └── coverage_reporting/            # Coverage and validation metrics
```

---

## AWS Integration

All Python code uses `boto3`'s default credential chain. **No credentials are ever hardcoded.**

```bash
aws configure
# Prompts for: Access Key ID, Secret Access Key, region, output format
# A read-only Security Auditor role (or equivalent) is sufficient.
# All collectors use only describe/get/list API calls.
```

Minimum IAM permissions for full collection:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrailStatus",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "securityhub:GetFindings",
        "iam:GetUser",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Validation Framework

Every detection has three test types, each backed by a real NDJSON file:

| Test Type | File Location | Purpose |
|---|---|---|
| **Positive** | `sample_logs/cloudtrail/malicious/` | Confirms detection fires on attack data |
| **Negative** | `sample_logs/cloudtrail/benign/` | Confirms detection suppresses approved actors |
| **Edge case** | `sample_logs/cloudtrail/edge_cases/` | Confirms boundary behaviour is correct |

**Python offline validation** (no Splunk required):

```bash
python scripts/detection_validator.py
# Runs 14 heuristic detectors against sample data
# Each heuristic mirrors the SPL logic exactly
# Output: PASS/FAIL per detection per test type
```

**Splunk validation** (with Splunk available):

```spl
| savedsearch CDET-ValidatePositive-001
```

---

## Incident Response Capabilities

Every detection has a four-file playbook:

| File | Audience | Time to Complete |
|---|---|---|
| `triage.md` | On-call analyst | 5–10 minutes |
| `investigation.md` | Tier-2 analyst | 30–60 minutes |
| `containment.md` | Senior analyst + approval | 15–30 minutes |
| `recovery.md` | Engineer + analyst | 1–4 hours |

Automated enrichment runs in seconds:

```python
from scripts.alert_enrichment import AlertEnricher
from scripts.incident_report_generator import IncidentReportGenerator

enricher = AlertEnricher()          # uses aws configure credentials
enriched = enricher.enrich(alert)   # ATT&CK + IAM + severity + queries

gen = IncidentReportGenerator()
report = gen.generate(enriched)
gen.write_reports(report, output_dir=Path("reports/generated"))
# Writes: INC-CDET-001-20240115_executive.md
#         INC-CDET-001-20240115_analyst.md
#         INC-CDET-001-20240115_summary.json
```

---

## Screenshots

> **Note:** Screenshots are taken from a live Splunk environment with sample data loaded. See [`images/screenshots/README.md`](images/screenshots/README.md) for the full capture guide.

| Screenshot | Description |
|---|---|
| `splunk_indexes.png` | aws_cloudtrail, aws_security, cdet_alerts indexes with event counts |
| `collector_execution.png` | Terminal output from `collect_cli.py --all` |
| `cloudtrail_ingestion.png` | Splunk search showing normalized CloudTrail events |
| `detection_results.png` | CDET-001 detection firing on positive sample data |
| `soc_dashboard.png` | SOC dashboard — alert queue, detection health, KPIs |
| `cloud_security_dashboard.png` | Cloud security dashboard — coverage by service and region |
| `validation_workflow.png` | Validation matrix showing all 14 CDETs in Testing |
| `repo_architecture.png` | Repository structure showing component relationships |

---

## Portfolio Value

This project demonstrates the full detection engineering lifecycle that senior SOC and detection engineering roles require:

**What interviewers will see:**
- Detection-as-code: every detection has YAML metadata, SPL query, test cases, and a Python heuristic mirror
- Credential security discipline: zero hardcoded credentials in the entire codebase
- Layered suppression: lookup-based false-positive management at both SPL and Python layers
- Separation of concerns: collect → parse → detect → enrich → report, each as an independent module
- Test-driven detection development: positive/negative/edge tests before any detection goes live
- Production-ready Splunk: savedsearches.conf, props.conf, transforms.conf, inputs.conf
- Complete incident response: triage through recovery, automated enrichment and reporting

**Technology coverage demonstrated:**
AWS · CloudTrail · GuardDuty · SecurityHub · IAM · EC2 · S3 · STS · Splunk · SPL · MITRE ATT&CK · Python · boto3 · structlog · click · NDJSON · ASFF · Incident Response · Detection Engineering

---

## Project Metrics

| Metric | Count |
|---|---|
| Detections (CDET-001 – CDET-014) | 14 |
| MITRE ATT&CK tactics covered | 9 |
| MITRE ATT&CK techniques covered | 13 |
| Test cases (positive + negative + edge) | 42 |
| Sample NDJSON log files | 53 |
| Attack simulation packages | 14 |
| Incident response playbook files | 56 |
| Python automation modules | 14 |
| Splunk saved searches | 14 |
| Splunk lookup tables | 11 |
| Splunk dashboards | 4 |
| Report templates | 3 |
| SOC operations runbooks | 4 |

---

## Future Improvements

- **Phase 6 — Automated Response**: AWS Lambda functions for automated IAM key revocation, EC2 isolation, and Security Group rollback triggered via Splunk Adaptive Response
- **CI/CD Pipeline**: GitHub Actions workflow running `detection_validator.py` on every PR to prevent detection regressions
- **Threat Intelligence Integration**: Enrich alerts with IP reputation (GreyNoise, AbuseIPDB) in `alert_enrichment.py`
- **SOAR Integration**: Splunk SOAR (Phantom) playbooks calling the Python enrichment and response scripts
- **Extended Coverage**: Expand to 30+ CDETs covering CloudFormation abuse, KMS key deletion, RDS snapshot exfiltration

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This project is for **educational and authorized testing purposes only**. All attack simulations must be performed in isolated, owned environments with explicit written authorization. Never run simulation scripts against systems you do not own.

---

*MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*
