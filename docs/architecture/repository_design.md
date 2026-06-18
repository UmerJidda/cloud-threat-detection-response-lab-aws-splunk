# Repository Design

## Purpose

This document describes the repository structure, naming conventions, file organization standards, and the reasoning behind key design decisions. It serves as the reference for contributors when deciding where to place new content.

---

## Directory Structure

```
CloudThreatDetectionLab/
│
├── .github/                            # GitHub-native automation
│   ├── ISSUE_TEMPLATE/
│   │   ├── detection_request.md        # New detection intake form
│   │   ├── false_positive_report.md    # FP reporting workflow
│   │   └── bug_report.md
│   ├── PULL_REQUEST_TEMPLATE.md        # Detection peer-review checklist
│   └── workflows/
│       └── detection_ci.yml            # CI: validate detections on PR
│
├── config/
│   ├── lab_config.example.yaml         # Annotated configuration template (committed)
│   ├── lab_config.yaml                 # Local configuration (gitignored)
│   └── mitre_mappings.yaml             # ATT&CK technique → detection ID index
│
├── data/
│   ├── collected/                      # Live collector output — GITIGNORED
│   └── samples/                        # Static test datasets — COMMITTED
│
├── detections/                         # Detection content by ATT&CK tactic
│   ├── initial_access/
│   ├── persistence/
│   ├── privilege_escalation/
│   ├── defense_evasion/
│   ├── credential_access/
│   ├── discovery/
│   ├── lateral_movement/
│   ├── exfiltration/
│   └── impact/
│
├── docs/                               # All project documentation
│   ├── architecture/                   # System architecture documents
│   ├── detection_engineering/          # DE standards and methodology
│   ├── detection_coverage/             # Coverage matrix and gap analysis
│   ├── mitre_mapping/                  # ATT&CK coverage planning
│   ├── splunk/                         # Splunk design documentation
│   ├── threat_intelligence/            # TI reports and context
│   └── walkthrough/                    # Onboarding and how-to guides
│
├── incident_response/
│   ├── playbooks/                      # Per-detection IR playbooks
│   ├── reports/                        # Closed incident reports (gitignored)
│   └── templates/                      # IR document templates
│
├── attack_simulation/
│   ├── scenarios/                      # Attack scenario procedures
│   └── atomic_mappings/                # Atomic Red Team test references
│
├── automation/
│   ├── lambda/                         # AWS Lambda response functions
│   ├── response_actions/               # Splunk Adaptive Response scripts
│   └── enrichment/                     # IOC and context enrichment
│
├── splunk/
│   ├── dashboards/                     # Dashboard XML definitions
│   ├── lookups/                        # Reference lookup CSV/YAML files
│   └── macros/                         # SPL macro definitions
│
├── scripts/
│   ├── aws_collectors/                 # AWS telemetry collection (read-only)
│   │   ├── __init__.py
│   │   ├── schema.py                   # Normalized output dataclasses
│   │   ├── base_collector.py           # Abstract base + output writer
│   │   ├── cloudtrail_collector.py
│   │   ├── iam_collector.py
│   │   ├── security_group_collector.py
│   │   ├── securityhub_collector.py
│   │   ├── guardduty_collector.py
│   │   └── collect_cli.py              # CLI entrypoint
│   ├── splunk_ops/                     # Splunk management utilities
│   ├── validation/                     # Detection validation framework
│   └── utils/                          # Shared Python utilities
│
├── templates/                          # Reusable document templates
│   ├── detection_template.md
│   ├── playbook_template.md
│   ├── attack_simulation_template.md
│   ├── incident_report_template.md
│   └── validation_report_template.md
│
└── tests/
    ├── unit/                           # Unit tests (no AWS calls)
    └── integration/                    # Integration tests (moto or real AWS)
```

---

## Naming Conventions

### Detection IDs

Format: `CDET-{NNN}` where NNN is a zero-padded three-digit number.

- Start at `CDET-001`
- IDs are never reused after a detection is deprecated
- Deprecated detections retain their ID in the directory name

### Detection Directories

Format: `{detection_id}_{snake_case_name}`

Examples:
- `CDET-001_iam_user_created_outside_pipeline`
- `CDET-005_cloudtrail_logging_disabled`
- `CDET-012_cross_account_role_assumption_chain`

### Playbook Files

Format: `{detection_id}_{snake_case_name}.md`

Mirrors the detection directory name for unambiguous cross-referencing.

### Collector Output Files

Format: `{collector_name}_{aws_account_id}_{YYYYMMDDTHHMMSSZ}.ndjson`

Generated by `BaseCollector._write_output()` — not hand-authored.

### Sample Dataset Files

Format: `{collector_name}_{scenario_description}.ndjson`

Examples:
- `cloudtrail_iam_createuser_unknown_principal.ndjson`
- `cloudtrail_cloudtrail_stopLogging.ndjson`
- `guardduty_instance_credential_exfiltration.ndjson`

### Incident Report Files

Format: `{YYYY-MM-DD}_{incident_id}_{short_description}.md`

Example: `2024-01-15_INC-2024-001_iam_credential_compromise.md`

---

## Git Workflow

### Branch Naming

| Branch Type | Format | Example |
|-------------|--------|---------|
| New detection | `detection/{id}-{short-name}` | `detection/CDET-001-iam-user-creation` |
| Detection update | `update/{id}-{change-description}` | `update/CDET-001-add-pipeline-exclusion` |
| Documentation | `docs/{topic}` | `docs/architecture-update` |
| Bug fix | `fix/{description}` | `fix/cloudtrail-parser-assumed-role` |
| Phase work | `phase/{number}-{title}` | `phase/2-log-ingestion` |

### Pull Request Requirements

All PRs that add or modify detections must:
- Reference the detection ID in the PR title
- Include the MITRE ATT&CK technique ID
- Attach test case results or CI badge
- Have detection.yaml and detection.spl reviewed by at least one peer
- Pass all CI validation checks

See `.github/PULL_REQUEST_TEMPLATE.md` for the full checklist.

### Commit Message Convention

```
{type}({scope}): {short description}

{optional body — what and why, not how}

Refs: {detection ID or issue number}
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

Examples:
```
feat(CDET-001): add IAM user creation detection

Detects CreateUser events from principals not in the approved pipeline lookup.
Maps to T1136.003 (Create Account: Cloud Account).

Refs: CDET-001
```

```
fix(cloudtrail-collector): handle missing sessionContext for root activity

Root account events omit the sessionContext block. Added null-safe access
for assumed_role_arn field.
```

---

## What Belongs Where

| Content Type | Location | Notes |
|-------------|----------|-------|
| SPL detection logic | `detections/{tactic}/{id}/detection.spl` | One file per detection |
| Detection metadata + test cases | `detections/{tactic}/{id}/detection.yaml` | Authoritative source of truth |
| SPL macros | `splunk/macros/` | Shared across all detections |
| Lookup tables | `splunk/lookups/` | CSV or YAML reference data |
| AWS API collection | `scripts/aws_collectors/` | Read-only boto3 code |
| Detection validation | `scripts/validation/` | Framework code, not test data |
| Sample test data | `data/samples/` | NDJSON, committed to repo |
| Live collection output | `data/collected/` | NDJSON, gitignored |
| Architecture docs | `docs/architecture/` | Stable reference documents |
| DE standards | `docs/detection_engineering/` | Living standards documents |
| Reusable templates | `templates/` | Blank templates, no content |
| IR playbooks | `incident_response/playbooks/` | One per detection |
| Lambda functions | `automation/lambda/` | Response automation only |
| Unit tests | `tests/unit/` | No real AWS calls (mock with moto) |
| Integration tests | `tests/integration/` | May call real AWS (read-only) |

---

## Files That Must Never Be Committed

The `.gitignore` enforces these exclusions:

| Pattern | Reason |
|---------|--------|
| `config/lab_config.yaml` | Contains Splunk credentials and AWS account IDs |
| `data/collected/` | Contains real AWS telemetry |
| `.aws/` | AWS credential files |
| `*.pem`, `*.key` | Private keys |
| `secrets.yaml`, `*_credentials.yaml` | Any credential file |
| `incident_response/reports/` | May contain sensitive incident details |

Use `config/lab_config.example.yaml` as the committed reference with placeholder values.
