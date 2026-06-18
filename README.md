# Cloud Threat Detection & Response Lab

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Splunk](https://img.shields.io/badge/splunk-9.x-green.svg)](https://www.splunk.com/)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail%20%7C%20GuardDuty%20%7C%20SecurityHub-orange.svg)](https://aws.amazon.com/security/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A production-quality cloud detection engineering program demonstrating end-to-end threat detection, real AWS telemetry collection, detection validation, and automated response. Built to reflect real-world enterprise cloud security operations workflows.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Lab Components](#lab-components)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Detection Engineering Workflow](#detection-engineering-workflow)
- [Phases & Roadmap](#phases--roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This repository implements a cloud-native detection engineering program against a real AWS environment. It covers the full detection engineering lifecycle:

1. **Real AWS Telemetry Collection** — Python collectors using read-only APIs pull live CloudTrail, GuardDuty, Security Hub, IAM, and security group data
2. **Detection Development** — Splunk SPL searches modeled on real adversary TTPs, mapped to MITRE ATT&CK
3. **Detection Validation** — A validation framework tests detections against sample datasets, live CloudTrail history, and future attack simulation outputs
4. **Threat Hunting** — Hypothesis-driven hunts using MITRE ATT&CK as a framework
5. **Automated Response** — Python Lambda functions and Splunk Adaptive Response Actions
6. **Incident Response** — Documented playbooks mapping each detection to a response procedure

The project follows a **detection-first architecture**: all detection content and validation logic is fully implemented independently from attack execution. Attack simulations exist as code and documented procedures; live execution can be performed by a privileged operator without any changes to this repository.

### AWS Credential Model

All Python code uses `boto3`'s default credential chain. Configure credentials once with:

```bash
aws configure
```

No credentials are ever hardcoded, stored in environment variables, or committed to the repository. The minimum required permission set is a read-only security role (Security Auditor or equivalent).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS ENVIRONMENT                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  CloudTrail  │  │  GuardDuty   │  │   VPC Flow Logs      │  │
│  │  (All APIs)  │  │  (ML-based)  │  │   S3 Access Logs     │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └────────────┬────┘──────────────────────┘              │
│                      │                                          │
│              ┌───────▼────────┐                                 │
│              │   S3 Log Bucket │                                 │
│              │  (Centralized) │                                 │
│              └───────┬────────┘                                 │
│                      │  SQS Notification                        │
│                      ▼                                          │
│              ┌───────────────┐      ┌─────────────────────┐    │
│              │ Splunk Add-on │      │  Lambda Functions   │    │
│              │  for AWS (SA) │      │  (Auto-Response)    │    │
│              └───────┬───────┘      └──────────┬──────────┘    │
└──────────────────────┼──────────────────────────┼──────────────┘
                       │                          │
        ┌──────────────▼──────────────────────────▼─────────────┐
        │                    SPLUNK SIEM                         │
        │                                                        │
        │  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  │
        │  │  Correlation │  │    Threat    │  │  Dashboards │  │
        │  │   Searches  │  │    Hunting   │  │  & Reports  │  │
        │  │  (Detections)│  │   Notebooks  │  │             │  │
        │  └─────────────┘  └──────────────┘  └─────────────┘  │
        │                                                        │
        │  ┌──────────────────────────────────────────────────┐  │
        │  │          Adaptive Response Actions               │  │
        │  │   (Isolate EC2 | Revoke IAM | Block IP)          │  │
        │  └──────────────────────────────────────────────────┘  │
        └───────────────────────────────────────────────────────┘
```

---

## Lab Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| AWS Telemetry Collection | Python 3.11 + Boto3 (read-only APIs) | Live CloudTrail, GuardDuty, IAM, Security Hub, security group data |
| SIEM | Splunk Enterprise 9.x | Detection, alerting, hunting |
| Detection Language | Splunk SPL | Correlation search logic |
| Detection Validation | Python framework + sample datasets | Validate detections without live attack execution |
| Automation | Python 3.11 + AWS Lambda + Boto3 | Automated response actions |
| Threat Framework | MITRE ATT&CK v15 | TTP mapping and coverage analysis |
| Attack Simulation | Atomic Red Team + custom scripts (code only) | Documentation and procedures for future execution |
| IR Playbooks | Markdown + YAML | Structured incident response |
| Testing | pytest + moto (AWS mock) | Unit/integration tests for collectors and automation |

---

## MITRE ATT&CK Coverage

Current detection coverage mapped to MITRE ATT&CK for Cloud (IaaS):

| Tactic | Technique | Detection | Status |
|--------|-----------|-----------|--------|
| Initial Access | T1078.004 – Valid Accounts: Cloud Accounts | Impossible travel / unusual login geo | ✅ Active |
| Persistence | T1098.001 – Account Manipulation: Additional Cloud Credentials | New IAM key created for existing user | ✅ Active |
| Persistence | T1136.003 – Create Account: Cloud Account | New IAM user or role creation | ✅ Active |
| Privilege Escalation | T1078.004 – Valid Accounts (Escalation) | Privilege escalation via policy attachment | ✅ Active |
| Defense Evasion | T1562.008 – Impair Defenses: Disable Cloud Logs | CloudTrail logging disabled | ✅ Active |
| Defense Evasion | T1070.004 – Indicator Removal: File Deletion | S3 bucket or CloudTrail log deletion | ✅ Active |
| Credential Access | T1552.005 – Unsecured Credentials: Cloud Instance Metadata | EC2 metadata service abuse | ✅ Active |
| Discovery | T1580 – Cloud Infrastructure Discovery | Excessive DescribeInstances / ListBuckets | ✅ Active |
| Lateral Movement | T1550.001 – Use Alternate Authentication Material | Cross-account role assumption chain | ✅ Active |
| Exfiltration | T1537 – Transfer Data to Cloud Account | S3 bucket replication to external account | ✅ Active |
| Impact | T1485 – Data Destruction | Mass S3 object deletion | ✅ Active |
| Impact | T1496 – Resource Hijacking | EC2 / Lambda compute resource abuse | ✅ Active |

---

## Quick Start

### Prerequisites

- Splunk Enterprise 9.x with Splunk Add-on for AWS installed
- AWS account with CloudTrail, GuardDuty, and VPC Flow Logs enabled
- Python 3.11+ with `pip`
- AWS CLI configured with appropriate credentials

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CloudThreatDetectionLab.git
cd CloudThreatDetectionLab
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp config/lab_config.example.yaml config/lab_config.yaml
# Edit config/lab_config.yaml with your Splunk settings and AWS account ID
```

### 4. Configure AWS Credentials

```bash
aws configure
# Enter your Access Key ID, Secret Access Key, and default region.
# A read-only security role (Security Auditor) is sufficient.
```

### 5. Collect Live AWS Telemetry

```bash
# Collect all sources (last 24 hours of CloudTrail + current state)
python -m scripts.aws_collectors.collect_cli --all --region us-east-1 --output-dir data/collected

# Or collect a single source
python -m scripts.aws_collectors.collect_cli --collector guardduty --region us-east-1
```

### 6. Load Detections into Splunk

```bash
python scripts/splunk_ops/deploy_detections.py --env lab --validate
```

### 7. Validate Detections Against Sample Data

```bash
# Run the validation framework against all 14 detections
python -m validation.validator --all --output-dir data/validation_results/

# Run a single detection
python -m validation.validator --detection CDET-001
```

### 8. Load Sample Data into Splunk for Full Validation

```bash
# Load malicious sample for CDET-001 positive test
/opt/splunk/bin/splunk add oneshot \
  sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson \
  -index aws_cloudtrail -sourcetype aws:cloudtrail

# Run the detection SPL and compare to validation/test_cases/CDET-001_*/expected_alert.json
```

### 9. (Optional) Run Attack Simulations

```bash
# Dry-run: see what the simulation would do (no AWS calls)
python attack_simulations/CDET-001_iam_user_created_outside_pipeline/simulate.py \
  --username test-backdoor-user

# Read-only cloud enumeration (safe — generates CloudTrail events for CDET-008)
python attack_simulations/CDET-008_excessive_api_enumeration/simulate.py \
  --region us-east-1
```

---

## Project Structure

```
CloudThreatDetectionLab/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── CONTRIBUTING.md                    # Contribution guidelines
├── SECURITY.md                        # Security policy
├── CHANGELOG.md                       # Version history
├── requirements.txt                   # Python dependencies
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── detection_request.md       # New detection request template
│   │   ├── false_positive_report.md   # FP reporting template
│   │   └── bug_report.md              # Bug report template
│   ├── PULL_REQUEST_TEMPLATE.md       # PR checklist
│   └── workflows/
│       └── detection_ci.yml           # CI pipeline for detection validation
├── config/
│   ├── lab_config.example.yaml        # Example configuration
│   └── mitre_mappings.yaml            # ATT&CK technique → detection mappings
├── detections/
│   ├── README.md                      # Detection catalog overview
│   ├── initial_access/
│   ├── persistence/
│   ├── privilege_escalation/
│   ├── defense_evasion/
│   ├── credential_access/
│   ├── discovery/
│   ├── lateral_movement/
│   ├── exfiltration/
│   └── impact/
├── splunk/
│   ├── dashboards/                    # Splunk dashboard XMLs
│   ├── lookups/                       # Reference lookup tables
│   └── macros/                        # SPL macro definitions
├── automation/
│   ├── lambda/                        # AWS Lambda response functions
│   ├── response_actions/              # Splunk Adaptive Response scripts
│   └── enrichment/                    # IOC enrichment integrations
├── threat_hunting/
│   ├── hypotheses/                    # Hunt hypotheses (YAML)
│   └── notebooks/                     # Hunt notebooks (Markdown)
├── incident_response/
│   ├── playbooks/                     # IR playbooks per detection type
│   └── templates/                     # Incident ticket templates
├── attack_simulation/
│   ├── scenarios/                     # Attack scenario scripts
│   └── atomic_mappings/               # Atomic Red Team test mappings
├── scripts/
│   └── aws_collectors/                # Real AWS telemetry collectors (read-only)
│       ├── schema.py                  # Common normalized output schema
│       ├── base_collector.py          # Abstract base class + output writer
│       ├── cloudtrail_collector.py    # CloudTrail LookupEvents
│       ├── iam_collector.py           # Users, roles, access keys
│       ├── security_group_collector.py # Ingress/egress rules, public exposure
│       ├── securityhub_collector.py   # Security Hub findings
│       ├── guardduty_collector.py     # GuardDuty findings
│       └── collect_cli.py             # CLI entrypoint (python -m ...)
├── sample_logs/                       # Synthetic NDJSON datasets for validation
│   ├── cloudtrail/malicious/          # Events that SHOULD trigger detections
│   ├── cloudtrail/benign/             # Events that SHOULD NOT trigger (suppressed)
│   ├── guardduty/malicious/           # GuardDuty finding samples
│   ├── securityhub/findings/          # Security Hub ASFF samples
│   └── alerts/sample_alerts.ndjson   # Expected alert output for all 14 detections
├── attack_simulations/                # Attack simulation documentation and scripts
│   └── CDET-XXX_<name>/
│       ├── attack_description.md      # Technique explanation (threat actor perspective)
│       ├── simulation_steps.md        # Step-by-step AWS CLI procedure
│       ├── expected_events.md         # CloudTrail events the attack generates
│       └── simulate.py                # Executable simulation (dry-run by default)
├── validation/                        # Detection validation framework
│   ├── schema.py                      # TestCase, ValidationResult dataclasses
│   ├── validator.py                   # Main runner — evaluates detections vs. sample data
│   └── test_cases/CDET-XXX_<name>/
│       ├── expected_alert.json        # All required alert output fields
│       ├── positive_case.md           # What triggers the detection
│       ├── negative_case.md           # What is suppressed
│       ├── edge_case.md               # Boundary condition tests
│       └── checklist.md               # Promotion gate checklist
├── tests/
│   └── unit/                          # Unit tests for collectors
└── docs/
    ├── architecture/                  # Architecture documentation + Mermaid diagrams
    ├── detection_engineering/         # DE standards, severity framework, SPL guidelines
    ├── detection_coverage/            # Coverage matrix
    ├── mitre_mapping/                 # ATT&CK technique mapping
    ├── splunk/                        # Splunk index, field mapping, dashboard strategy
    ├── validation/                    # Validation guide and sample data guide
    └── walkthrough/                   # Project onboarding walkthrough
```

---

## Detection Engineering Workflow

This project follows a structured detection engineering lifecycle adapted from enterprise SOC practices:

```
1. IDENTIFY        Threat intelligence, red team findings, threat model gaps
       ↓
2. DESIGN          Hypothesis → data requirements → SPL logic draft
       ↓
3. VALIDATE        Run against attack simulation data, measure TPR/FPR
       ↓
4. TUNE            Adjust thresholds, add whitelists, reduce false positives
       ↓
5. DOCUMENT        MITRE mapping, data sources, response actions, runbook
       ↓
6. DEPLOY          Push to Splunk via CI/CD, enable alerting
       ↓
7. MONITOR         Track alert volume, FP rate, coverage metrics
       ↓
8. ITERATE         Continuous improvement loop driven by new intel
```

Each detection in this repository includes:
- **Metadata** — Author, creation date, last modified, confidence level, severity
- **Hypothesis** — What adversary behavior this detects and why
- **Data Sources** — Which AWS log sources are required
- **SPL Query** — The detection logic (annotated)
- **MITRE Mapping** — Tactic, technique, sub-technique
- **Tuning Notes** — Known false positives and how to suppress them
- **Response Actions** — Automated and manual response procedures
- **Test Cases** — How to validate the detection fires correctly

---

## Phases & Roadmap

| Phase | Title | Status |
|-------|-------|--------|
| Architecture | Real AWS Integration — boto3 + aws configure | ✅ Complete |
| Phase 1 | Security Architecture, Telemetry Foundation & Detection Framework | ✅ Complete |
| Phase 2 | Detection Engineering Library (14 MITRE-mapped SPL detections) | ✅ Complete |
| Phase 3 | Telemetry Generation, Sample Data & Detection Validation Framework | ✅ Complete |
| Phase 4 | Splunk Dashboards & Metrics | ⏳ Planned |
| Phase 5 | Threat Hunting Notebooks & Hypotheses | ⏳ Planned |
| Phase 6 | Automated Response (Lambda + Adaptive Response) | ⏳ Planned |
| Phase 7 | Incident Response Playbooks | ⏳ Planned |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Submitting new detections
- Reporting false positives
- Improving documentation
- Running the test suite locally

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This lab is for **educational and authorized testing purposes only**. All attack simulations must be performed in isolated, owned environments. Never run these scripts against systems you do not own or have explicit written permission to test.

---

*Built with the MITRE ATT&CK® framework. MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*
