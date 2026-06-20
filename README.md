# Cloud Threat Detection & Response Platform

[![CI](https://img.shields.io/github/actions/workflow/status/UmerJidda/CloudThreatDetectionLab/detection_ci.yml?label=CI&logo=github)](https://github.com/YOUR_USERNAME/CloudThreatDetectionLab/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Splunk](https://img.shields.io/badge/splunk-9.x-green.svg)](https://www.splunk.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-red.svg)](https://attack.mitre.org/)
[![mypy](https://img.shields.io/badge/type%20checked-mypy-blue)](http://mypy-lang.org/)
[![ruff](https://img.shields.io/badge/linted-ruff-purple)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A full-stack cloud detection engineering platform covering the complete operational lifecycle: AWS telemetry collection, Splunk-based detection, alert enrichment, IOC extraction, automated incident reporting, and SOC dashboards. Fourteen production-quality detections mapped to MITRE ATT&CK v15, each backed by validated SPL, Python heuristic mirrors, suppression lookups, attack simulations, and four-phase incident response playbooks.

---

## Platform Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AWS ENVIRONMENT                     │
│                                                          │
│  CloudTrail    GuardDuty    Security Hub    IAM / EC2    │
│  (mgmt events) (ML alerts)  (ASFF findings) (posture)   │
└──────────────────────────┬──────────────────────────────┘
                           │  boto3 default credential chain
                           │  (aws configure — no hardcoded creds)
               ┌───────────▼───────────┐
               │    Python Collectors   │  scripts/aws_collectors/
               │  CloudTrail · IAM      │  paginated APIs → typed
               │  GuardDuty · SecHub    │  dataclasses → NDJSON
               │  SecurityGroups        │
               └───────────┬───────────┘
                           │  data/collected/*.ndjson
               ┌───────────▼───────────┐
               │   Splunk Indexer       │  props.conf: SHOULD_LINEMERGE=false
               │  index=aws_cloudtrail  │  KV_MODE=json, CIM FIELDALIAS
               │  index=aws_security    │  transforms.conf: lookup registration
               └───────────┬───────────┘
                           │
          ┌────────────────▼────────────────┐
          │         Detection Layer          │
          │  14 SPL searches · cron/10–30m   │  detections/{tactic}/CDET-NNN/
          │  Macro expansion · event filter  │  detection.yaml + detection.spl
          │  Double lookup suppression       │  10 CSV suppression tables
          │  Confidence classification       │  index=cdet_alerts on match
          └────────────────┬────────────────┘
                           │
               ┌───────────▼───────────┐
               │    Alert Enrichment    │  scripts/alert_enrichment.py
               │  ATT&CK context        │  5 enrichment layers:
               │  Severity escalation   │  local dicts → CSV lookups →
               │  Live IAM API context  │  live IAM API (best-effort)
               │  Investigation queries │
               └───────────┬───────────┘
                           │
          ┌────────────────▼────────────────┐
          │         Response Layer           │
          │  IoCExtractor: deduped IOCs      │  scripts/ioc_extractor.py
          │  IncidentReportGenerator:        │  scripts/incident_report_generator.py
          │    executive.md / analyst.md /   │
          │    investigation.json            │
          │  Playbooks: triage → investigate │  playbooks/CDET-NNN_*/
          │    → contain → recover (56 files)│
          └────────────────┬────────────────┘
                           │
          ┌────────────────▼────────────────┐
          │          SOC Dashboards          │  splunk/dashboards/
          │  SOC Operations · Cloud Posture  │  Simple XML, dark theme
          │  Detection Engineering · Exec    │  4 audiences, 4 dashboards
          └─────────────────────────────────┘
```

---

## Detection Library

14 detections across 9 ATT&CK tactics. Each detection ships with: `detection.yaml` schema metadata, `detection.spl` query, Python heuristic mirror, positive/negative/edge-case test data, attack simulation, and incident response playbook.

| ID | Name | Tactic | Technique | Severity | Signal Event |
|---|---|---|---|---|---|
| CDET-001 | IAM User Created Outside Approved Pipeline | Persistence | T1136.003 | High | `CreateUser` |
| CDET-002 | Access Key Created for Another User | Persistence | T1098.001 | High | `CreateAccessKey` |
| CDET-003 | CloudTrail Logging Disabled or Trail Deleted | Defense Evasion | T1562.008 | **Critical** | `StopLogging` / `DeleteTrail` |
| CDET-004 | Admin Policy Attached to IAM Principal | Privilege Escalation | T1078.004 | **Critical** | `AttachUserPolicy` / `AttachRolePolicy` |
| CDET-005 | Cross-Account Role Trust Modified | Privilege Escalation | T1484.002 | High | `UpdateAssumeRolePolicy` |
| CDET-006 | Root Account Activity | Initial Access | T1078.004 | **Critical** | Any (Root principal) |
| CDET-007 | EC2 Instance Metadata Credential Abuse | Credential Access | T1552.005 | High | `AssumeRole` (EC2 issuer + external IP) |
| CDET-008 | Excessive API Enumeration | Discovery | T1580 | Medium | 50+ `List*/Describe*` calls across ≥5 APIs |
| CDET-009 | S3 Replication Configured to External Account | Exfiltration | T1537 | High | `PutBucketReplication` |
| CDET-010 | Mass S3 Object Deletion | Impact | T1485 | **Critical** | `DeleteObjects` (≥100 estimated keys) |
| CDET-011 | Unauthorized Compute Resource Launch | Impact | T1496 | High | `RunInstances` (GPU/HPC instance types) |
| CDET-012 | Cross-Account AssumeRole Chain | Lateral Movement | T1550.001 | High | `AssumeRole` across unapproved accounts |
| CDET-013 | Security Group Rule Opens Ingress to Internet | Defense Evasion | T1562.007 | High | `AuthorizeSecurityGroupIngress` (0.0.0.0/0) |
| CDET-014 | CloudTrail Log File Deleted from S3 | Defense Evasion | T1070.004 | **Critical** | `DeleteObject` matching `AWSLogs/*/CloudTrail/` |

### ATT&CK Tactic Coverage

```
Initial Access     ██░░░░░░░░  CDET-006
Persistence        ████░░░░░░  CDET-001, CDET-002
Privilege Escal.   ████░░░░░░  CDET-004, CDET-005
Defense Evasion    ██████░░░░  CDET-003, CDET-013, CDET-014
Credential Access  ██░░░░░░░░  CDET-007
Discovery          ██░░░░░░░░  CDET-008
Lateral Movement   ██░░░░░░░░  CDET-012
Exfiltration       ██░░░░░░░░  CDET-009
Impact             ████░░░░░░  CDET-010, CDET-011
```

---

## Engineering Design

### Credential Security

All AWS access uses `boto3.Session()` with no explicit credentials. The default chain resolves `~/.aws/credentials` (via `aws configure`) → instance profile → ECS/Lambda execution role. This is enforced architecturally: `BaseCollector.__init__` accepts no credentials parameter. No `.env` files. No environment variables. No exceptions.

### Detection-as-Code

Every detection is defined in two artifacts that must remain in sync:

- **`detection.yaml`** — machine-validated metadata: ATT&CK mapping, severity, required fields, suppression lookup references, test cases, schedule
- **`detection.spl`** — executable SPL validated by CI for data source references and schema compliance

The CI pipeline gates on both before any detection can merge.

### Lookup-Based Suppression

False positives are managed through version-controlled CSV lookup tables, not inline SPL logic. Every IAM detection performs a **double lookup suppression**: the direct actor ARN and the session issuer ARN. This correctly handles IaC tooling (Terraform, CDK) that runs as an IAM role and assumes secondary roles for specific operations.

```spl
| lookup approved_iam_principals arn AS principal_arn    OUTPUT approved
| lookup approved_iam_principals arn AS session_issuer_arn OUTPUT approved AS issuer_approved
| where (isnull(approved) OR approved!="true")
    AND (isnull(issuer_approved) OR issuer_approved!="true")
```

### Python Heuristic Mirrors

Every SPL detection has a Python equivalent in `scripts/detection_validator.py`. These run offline against sample NDJSON without Splunk and provide fast feedback during detection development. They also load the same lookup CSVs as the SPL queries, so suppression logic is tested identically in both layers.

### Schedule / Lookback Design

Critical detections (CDET-003, CDET-006, CDET-014) run every 10 minutes with a 10-minute lookback — no gap, no overlap, fast response. Non-critical detections run every 15 minutes with a 30-minute lookback — intentional 2× overlap provides resilience against Splunk scheduling delays. CDET-008 uses a 2-hour lookback to capture slow-and-low enumeration patterns.

---

## Getting Started

### Prerequisites

- Python 3.11+
- AWS CLI configured: `aws configure` (read-only Security Auditor role is sufficient)
- Splunk Enterprise 9.x (optional — offline validation runs without it)

```bash
git clone https://github.com/UmerJidda/CloudThreatDetectionLab.git
cd CloudThreatDetectionLab
pip install -r requirements.txt
```

### Collect Live AWS Telemetry

```bash
# All sources, default 24h lookback
python -m scripts.aws_collectors.collect_cli --all --region us-east-1

# CloudTrail only, extended window
python -m scripts.aws_collectors.collect_cli --collector cloudtrail \
    --region us-east-1 --lookback-hours 72

# Output: data/collected/{collector}_{account_id}_{timestamp}.ndjson
```

### Run Offline Detection Validation (No Splunk Required)

```bash
# Validate all 14 detections against sample NDJSON
python scripts/detection_validator.py

# Run unit tests
pytest tests/unit/ -v

# Full CI validation suite
ruff check .
mypy scripts/ --ignore-missing-imports
python scripts/validation/validate_detection_schema.py --dir detections/
python scripts/validation/validate_mitre_mappings.py
python scripts/validation/check_detection_ids.py
python scripts/validation/validate_spl_syntax.py --dir detections/
```

### Deploy to Splunk

```bash
# Deploy Splunk app configuration
cp splunk/integration/props.conf      $SPLUNK_HOME/etc/apps/cdet/local/
cp splunk/integration/transforms.conf $SPLUNK_HOME/etc/apps/cdet/local/
cp splunk/integration/inputs.conf     $SPLUNK_HOME/etc/apps/cdet/local/
cp splunk/lookups/*.csv               $SPLUNK_HOME/etc/apps/cdet/lookups/
cp splunk/dashboards/*.xml            $SPLUNK_HOME/etc/apps/cdet/default/data/ui/views/

# Required macros — define in Splunk Settings > Advanced Search > Search macros
# aws_cloudtrail_index → index=aws_cloudtrail sourcetype="aws:cloudtrail:json"
# root_activity        → userIdentity.type=Root
# timeframe_10m        → earliest=-10m latest=now
# timeframe_30m        → earliest=-30m latest=now
# timeframe_1h         → earliest=-1h latest=now
# timeframe_2h         → earliest=-2h latest=now

/opt/splunk/bin/splunk restart
```

### Load Sample Telemetry into Splunk

```bash
# Load all malicious samples to test detection firing
for f in sample_logs/cloudtrail/malicious/*.ndjson; do
    /opt/splunk/bin/splunk add oneshot "$f" \
        -index aws_cloudtrail -sourcetype aws:cloudtrail:json
done

# Verify CDET-001 fires
| savedsearch CDET-Integration-SampleData-Validate
```

---

## Minimum IAM Permissions

All collectors use read-only API calls. The following policy grants full platform capability:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrailStatus",
      "guardduty:ListDetectors",
      "guardduty:ListFindings",
      "guardduty:GetFindings",
      "securityhub:GetFindings",
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:ListMFADevices",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies",
      "iam:ListGroupsForUser",
      "iam:GetUser",
      "iam:GetLoginProfile",
      "ec2:DescribeSecurityGroups",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

---

## CI/CD Pipeline

Five-job GitHub Actions pipeline runs on every push and pull request:

| Job | What It Validates | Gate |
|---|---|---|
| **lint** | `ruff` style + `mypy` type checking (`--ignore-missing-imports`) | Blocks unit tests |
| **unit-tests** | `pytest tests/unit/` — collector `_normalize()` methods with mocked boto3 | Blocks detection validation |
| **detection-schema** | YAML required fields, severity/status values, MITRE ID format, ID uniqueness | Blocks merge |
| **spl-syntax** | Every `detection.spl` exists and references a data source | Blocks merge |
| **secret-scan** | `gitleaks` scans full git history for committed credentials | Blocks merge |

```yaml
# .github/workflows/detection_ci.yml
on: [push, pull_request]
jobs:
  lint → unit-tests → detection-schema
                    → spl-syntax
                    → secret-scan
```

The pipeline enforces detection quality gates before any change reaches the detection library. Status is reflected in the CI badge at the top of this document.

---

## Alert Enrichment Pipeline

`AlertEnricher` runs five sequential enrichment layers against every fired detection:

```python
from scripts.alert_enrichment import AlertEnricher
from scripts.incident_report_generator import IncidentReportGenerator

enricher = AlertEnricher()        # loads lookup CSVs at init, uses aws configure
enriched = enricher.enrich(alert) # five layers: ATT&CK → severity → lookups → IAM API → queries

gen = IncidentReportGenerator()
report = gen.generate(enriched)
gen.write_reports(report, output_dir=Path("reports/generated"))
# Produces:
#   INC-CDET-001-20240115_executive.md   — business-language summary
#   INC-CDET-001-20240115_analyst.md     — full timeline, IOCs, SPL pivots
#   INC-CDET-001-20240115_summary.json   — structured data for SOAR/ticketing
```

Layer 4 (`_apply_iam_context`) makes live IAM API calls to retrieve current principal state — whether the account still exists, MFA status, attached policies, active key count. All IAM exceptions are caught; `EnrichedAlert` is always returned regardless of API availability.

---

## Detection Validation Framework

Three test tiers per detection, each backed by a real NDJSON file:

| Tier | Sample Location | Purpose |
|---|---|---|
| **Positive** | `sample_logs/cloudtrail/malicious/` | Must fire — confirms detection logic triggers on attack data |
| **Negative** | `sample_logs/cloudtrail/benign/` | Must not fire — confirms suppression lookups work correctly |
| **Edge case** | `sample_logs/cloudtrail/edge_cases/` | Documents boundary behavior (partial suppression, ambiguous signals) |

All sample IPs use RFC 5737 TEST-NET ranges (`198.51.100.x`, `203.0.113.x`). All account IDs are fictional (`123456789012`).

Each detection also ships a `validation/test_cases/CDET-NNN_*/expected_alert.json` defining the exact fields and values the detection must produce to pass the promotion checklist.

---

## Incident Response

56 playbook files — four phases per detection:

| Phase | File | Audience | Objective |
|---|---|---|---|
| Triage | `triage.md` | On-call analyst | Scope and severity in ≤15 minutes |
| Investigation | `investigation.md` | Tier-2 analyst | Timeline, blast radius, root cause |
| Containment | `containment.md` | Senior analyst + approval | Prevent further compromise |
| Recovery | `recovery.md` | Security engineer | Restore normal operations, harden |

Playbooks reference the exact SPL field names output by each detection (`principal_arn`, `session_issuer_arn`, `created_user_name`) so pivot queries work directly from alert data without manual field mapping.

---

## Repository Structure

```
CloudThreatDetectionLab/
│
├── .github/workflows/detection_ci.yml     # 5-job CI pipeline
│
├── scripts/
│   ├── aws_collectors/
│   │   ├── base_collector.py              # Abstract base: Session, collect(), run(), NDJSON output
│   │   ├── cloudtrail_collector.py        # LookupEvents, 64 high-value event names, 1000-event cap
│   │   ├── iam_collector.py               # Users + roles + access keys + MFA + policies
│   │   ├── guardduty_collector.py         # Findings batched in groups of 50, severity threshold
│   │   ├── securityhub_collector.py       # ASFF findings, ISO-8601 millisecond timestamps
│   │   ├── security_group_collector.py    # One record per IP permission, publicly_exposed flag
│   │   ├── schema.py                      # Typed dataclasses: CloudTrailEvent, IAMUser, IAMRole, ...
│   │   └── collect_cli.py                 # Click CLI, COLLECTORS registry, type-narrowed dispatch
│   ├── cloudtrail_parser.py               # ParsedEvent (22 fields), multi-format parser, filter_events()
│   ├── detection_validator.py             # _detect_001–_detect_014, lookup CSV loading, ValidationResult
│   ├── alert_enrichment.py                # AlertEnricher, _ATTACK_CONTEXT, _SEVERITY_ESCALATION
│   ├── ioc_extractor.py                   # IoC deduplication, RFC 1918 + TEST-NET exclusion
│   └── incident_report_generator.py       # Three output formats, _TACTIC_BUSINESS_IMPACT translation
│
├── detections/
│   ├── persistence/                       # CDET-001, CDET-002
│   ├── privilege_escalation/              # CDET-004, CDET-005
│   ├── defense_evasion/                   # CDET-003, CDET-013, CDET-014
│   ├── credential_access/                 # CDET-007
│   ├── discovery/                         # CDET-008
│   ├── lateral_movement/                  # CDET-012
│   ├── exfiltration/                      # CDET-009
│   ├── impact/                            # CDET-010, CDET-011
│   └── initial_access/                    # CDET-006
│   # Each CDET-NNN_name/ contains: detection.yaml + detection.spl + README.md
│
├── sample_logs/
│   ├── cloudtrail/malicious/              # 14 known-positive NDJSON files
│   ├── cloudtrail/benign/                 # 14 known-negative NDJSON files
│   ├── cloudtrail/edge_cases/             # 14 boundary-condition NDJSON files
│   ├── guardduty/                         # GuardDuty finding samples
│   └── securityhub/                       # Security Hub ASFF samples
│
├── validation/
│   ├── validator.py                       # run_validation() runner
│   ├── results/                           # 14 CDET_validation.md result documents
│   └── test_cases/CDET-NNN_*/            # positive + negative + edge + checklist + expected_alert.json
│
├── attack_simulations/CDET-NNN_*/
│   ├── simulate.py                        # Dry-run safe, cleanup after execution, timestamp-namespaced
│   ├── attack_description.md              # Adversary TTP context
│   ├── expected_events.md                 # CloudTrail events the simulation generates
│   └── simulation_steps.md               # Manual step-by-step procedure
│
├── playbooks/CDET-NNN_*/
│   ├── triage.md / investigation.md / containment.md / recovery.md
│
├── splunk/
│   ├── dashboards/                        # soc_dashboard.xml, cloud_security_dashboard.xml,
│   │                                      # detection_engineering_dashboard.xml, executive_dashboard.xml
│   ├── lookups/                           # 10 suppression CSV tables
│   │   ├── approved_iam_principals.csv    # Principal ARN → approved flag
│   │   ├── automation_role_arns.csv       # IaC role ARNs (Terraform, CDK)
│   │   ├── admin_policy_arns.csv          # AdministratorAccess + custom admin policies
│   │   ├── approved_aws_accounts.csv      # Trusted cross-account targets
│   │   ├── approved_cidr_ranges.csv       # Internal CIDR allowlist
│   │   ├── suspicious_instance_types.csv  # GPU/HPC instance types for CDET-011
│   │   ├── approved_regions.csv           # Expected AWS regions
│   │   └── cloudtrail_log_buckets.csv     # Known CloudTrail S3 buckets for CDET-014
│   ├── integration/
│   │   ├── props.conf                     # SHOULD_LINEMERGE=false, KV_MODE=json, CIM FIELDALIAS
│   │   ├── transforms.conf                # Lookup registration, identity_type extraction regex
│   │   ├── inputs.conf                    # File monitors with per-sourcetype whitelist filters
│   │   └── savedsearches.conf             # Integration smoke tests (enableSched=0)
│   └── savedsearches/                     # detection_health.conf, coverage_reporting.conf
│
├── tests/unit/
│   └── test_aws_collectors.py             # _normalize() tests with mocked boto3.Session
│
├── scripts/validation/                    # CI static validators (no AWS, no Splunk)
│   ├── validate_detection_schema.py       # YAML required fields + allowed values
│   ├── validate_mitre_mappings.py         # T\d{4}(\.\d{3})? format enforcement
│   ├── check_detection_ids.py             # CDET-\d{3} format + uniqueness
│   └── validate_spl_syntax.py            # Data source reference presence
│
├── docs/                                  # Architecture, detection standards, SOC runbooks
├── config/                                # lab_config.example.yaml, mitre_mappings.yaml
├── pyproject.toml                         # pytest pythonpath=["."]; ruff target-version=py311
├── requirements.txt                       # Production: boto3, structlog, click, PyYAML, rich
└── requirements-dev.txt                   # Adds pytest, ruff, mypy, boto3-stubs, types-PyYAML, moto
```

---

## Platform Metrics

| Component | Count |
|---|---|
| ATT&CK tactics covered | 9 |
| ATT&CK techniques (sub-technique level) | 14 |
| SPL detections with full metadata | 14 |
| Python heuristic detection mirrors | 14 |
| Suppression lookup tables | 10 |
| Sample NDJSON test files | 42 (14 × positive / negative / edge) |
| Validation test cases with expected outputs | 42 |
| Attack simulation packages | 14 |
| Incident response playbook files | 56 (14 × 4 phases) |
| Splunk dashboards | 4 |
| CI pipeline jobs | 5 |
| Python modules (typed, tested) | 14 |

---

## Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Cloud platform | AWS (CloudTrail, GuardDuty, SecurityHub, IAM, EC2, S3, STS) | — |
| Telemetry collection | Python + boto3 | 3.11 / 1.34.69 |
| SIEM | Splunk Enterprise | 9.x |
| Detection query language | SPL (tstats, lookups, macros, rex) | — |
| Structured logging | structlog | 24.1.0 |
| CLI framework | click | 8.1.7 |
| Type checking | mypy | 1.9.0 |
| Linter / formatter | ruff | 0.3.4 |
| Test framework | pytest | 8.1.1 |
| AWS mocking | moto | 5.0.3 |
| Threat framework | MITRE ATT&CK | v15 |

---

## Disclaimer

All attack simulations are designed for authorized use only and default to dry-run mode. Simulation scripts must only be executed in environments you own, with explicit written authorization. All sample data uses RFC 5737 TEST-NET IP ranges and fictional AWS account IDs.

*MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*
