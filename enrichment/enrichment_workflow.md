# Alert Enrichment Workflow

This document describes the end-to-end alert enrichment pipeline for the Cloud Threat Detection Lab.
Enrichment adds ATT&CK context, severity classification, lookup cross-referencing, live IAM data, and
investigation pivot queries to every raw CDET alert before it reaches an analyst or report generator.

---

## 1. When Enrichment Runs

Enrichment runs in two modes:

**Splunk Adaptive Response action**

When a Splunk correlation search fires a CDET alert, it can invoke an Adaptive Response action that
calls `AlertEnricher.enrich()` with the alert fields Splunk passes as a Python dict. The enriched
result is then logged, forwarded to a ticketing system, or passed directly to
`IncidentReportGenerator`.

**Standalone CLI / investigation script**

Any analyst script or notebook can import `AlertEnricher` directly and pass an alert dict assembled
from CloudTrail fields, a Splunk notable event export, or a manual investigation starting point.

---

## 2. The Five-Stage Pipeline

`AlertEnricher.enrich(alert)` runs five enrichment stages in order. Each stage is independent and
best-effort: a failure in one stage does not abort the others.

```
Input alert dict
       |
       v
 Stage 1 — ATT&CK context
       |
       v
 Stage 2 — Severity classification
       |
       v
 Stage 3 — Lookup cross-reference
       |
       v
 Stage 4 — Live IAM context (boto3)
       |
       v
 Stage 5 — Investigation pivot queries
       |
       v
 EnrichedAlert dataclass
```

### Stage 1: ATT&CK Context

Source: the `_ATTACK_CONTEXT` dict compiled into `alert_enrichment.py`. No network call is made.

For every detection ID CDET-001 through CDET-014 the stage writes:

| Field | Example (CDET-001) |
|---|---|
| `attack_tactic` | `Persistence` |
| `attack_technique` | `T1136.003` |
| `attack_technique_name` | `Create Account: Cloud Account` |
| `attack_url` | `https://attack.mitre.org/techniques/T1136/003/` |

If `detection_id` is not found in the table all four fields are set to empty strings; enrichment
continues.

### Stage 2: Severity Classification

Source: the `_SEVERITY_ESCALATION` dict in `alert_enrichment.py`. No network call is made.

Each CDET has a `base` severity and an optional list of `escalate_if` conditions. The stage:

1. Sets `base_severity` from the table (falls back to `alert.get("severity", "medium")` if the
   detection ID is unknown).
2. Evaluates escalation conditions against the alert fields currently available. Currently implemented
   condition: `no_mfa` — if `alert["mfa_used"]` is `"no"`, `"false"`, or `"0"` and the detection
   table lists `no_mfa` in `escalate_if`, severity is promoted to `escalated` and
   `severity_escalation_reason` is set to `"MFA not used by actor"`.
3. Writes `enriched_severity` (may equal `base_severity` if no condition triggered).

CDET severity reference:

| Detection | Base | Escalates to | Escalation trigger |
|---|---|---|---|
| CDET-001 | high | critical | no\_mfa, admin\_policy\_attached |
| CDET-002 | high | critical | second\_key\_created |
| CDET-003 | critical | critical | (always critical) |
| CDET-004 | critical | critical | (always critical) |
| CDET-005 | high | critical | external\_account |
| CDET-006 | critical | critical | (always critical) |
| CDET-007 | high | critical | external\_ip |
| CDET-008 | medium | high | rapid\_enumeration |
| CDET-009 | high | critical | unapproved\_account |
| CDET-010 | critical | critical | (always critical) |
| CDET-011 | high | critical | unapproved\_region, gpu\_instance |
| CDET-012 | high | critical | three\_hop\_chain |
| CDET-013 | high | critical | port\_22\_or\_3389 |
| CDET-014 | critical | critical | (always critical) |

### Stage 3: Lookup Cross-Reference

Source: CSV files under `splunk/lookups/`. Loaded once at `AlertEnricher.__init__()` time from three
files:

| File | Set populated | Key column |
|---|---|---|
| `approved_iam_principals.csv` | `_approved_principals` | `principal_arn` |
| `automation_role_arns.csv` | `_automation_roles` | `role_arn` |
| `admin_policy_arns.csv` | `_admin_policies` | `policy_arn` |

The stage resolves the actor ARN from `alert["creator_arn"]` or `alert["actor_arn"]` and writes:

- `principal_in_approved_list` — `True` if the ARN appears in `approved_iam_principals.csv`
- `principal_in_automation_roles` — `True` if the ARN appears in `automation_role_arns.csv`

A match on either flag is a strong signal that the alert may be a false positive from a legitimate
automation actor; it does not suppress the alert automatically.

### Stage 4: Live IAM Context

Source: AWS IAM API via `boto3`. Credentials come exclusively from the boto3 default credential
chain (`aws configure`, environment variables, or instance profile). No credentials are passed as
arguments.

The stage resolves a username from the alert fields in this priority order:
`new_user_name` → `target_user` → trailing segment of `creator_arn` / `actor_arn`.

If a username is resolved, the stage calls:

| AWS API | Field written |
|---|---|
| `iam.get_user()` | `principal_exists`, `principal_create_date`, `principal_console_access` |
| `iam.list_access_keys()` | `principal_access_key_count` |
| `iam.list_mfa_devices()` | `principal_mfa_active` |
| `iam.list_attached_user_policies()` | `principal_attached_policies` |
| `iam.get_login_profile()` | `principal_console_access` |

If `iam.get_user()` returns `NoSuchEntity` then `principal_exists` is set to `False` and no further
IAM calls are made. Any other `ClientError` appends a message to `enrichment_errors` and the stage
exits without blocking subsequent stages.

If no username can be resolved all IAM fields remain at their default values (`None` or empty list).

### Stage 5: Investigation Pivot Queries

Source: computed locally from alert fields. No network call is made.

The stage builds a list of ready-to-run Splunk SPL strings stored in `recommended_queries`:

1. **Actor history** — 7-day lookback for all events by the actor ARN.
2. **Detection replay** — 24-hour lookback filtered to the specific detection ID.
3. **Target user pivot** (CDET-001, CDET-002, CDET-004 only) — 30-day lookback for all events
   touching the newly created or modified username.

---

## 3. How to Invoke

### Minimal invocation (uses `aws configure` credentials)

```python
from scripts.alert_enrichment import AlertEnricher

enricher = AlertEnricher()
enriched = enricher.enrich(alert_dict)
```

### With an explicit boto3 session

```python
import boto3
from scripts.alert_enrichment import AlertEnricher

session = boto3.Session(profile_name="threat-detection-lab")
enricher = AlertEnricher(session=session)
enriched = enricher.enrich(alert_dict)
```

### With a custom lookups directory

```python
from pathlib import Path
from scripts.alert_enrichment import AlertEnricher

enricher = AlertEnricher(lookups_dir=Path("/opt/lab/splunk/lookups"))
enriched = enricher.enrich(alert_dict)
```

`AlertEnricher` is safe to instantiate once and reuse across multiple alerts in the same process.
Lookups are loaded only during `__init__`; re-instantiate if CSV files are updated at runtime.

---

## 4. Prerequisites

| Requirement | Detail |
|---|---|
| AWS credentials configured | Run `aws configure` before use. The IAM user or role needs `iam:GetUser`, `iam:ListAccessKeys`, `iam:ListMFADevices`, `iam:ListAttachedUserPolicies`, `iam:GetLoginProfile`. |
| `splunk/lookups/` CSVs populated | The three files loaded in Stage 3 must exist and have at least a header row. Missing files are silently skipped; enrichment continues with empty sets. |
| Python dependencies | `boto3`, `botocore`, `structlog` (see `requirements.txt`). |

Enrichment degrades gracefully when AWS credentials are absent or the lookup CSVs are empty: ATT&CK
context, severity, and pivot queries are all fully local and will still be populated.

---

## 5. Error Handling

Enrichment never raises an exception that would abort the pipeline. The contract is:

- Every stage is wrapped in a try/except (or checks for missing data before proceeding).
- Recoverable errors append a human-readable string to `enriched.enrichment_errors`.
- Non-recoverable AWS permission errors (`AccessDenied`, unexpected `ClientError` codes) are logged
  via `structlog` and recorded in `enrichment_errors` but do not stop subsequent stages.
- `principal_exists = False` is a valid, non-error outcome when the IAM user does not exist.

Checking for errors after enrichment:

```python
enriched = enricher.enrich(alert_dict)

if enriched.enrichment_errors:
    for err in enriched.enrichment_errors:
        print(f"[WARN] {err}")
```

The `IncidentReportGenerator` surfaces `enrichment_errors` in both the analyst Markdown report and
the JSON summary output.

---

## 6. Integration with Splunk Adaptive Response

A Splunk Adaptive Response action wraps the enrichment call in a Python script that Splunk invokes
when a correlation search fires. The typical pattern:

```python
import sys
import json
import splunk.Intersplunk as si
from scripts.alert_enrichment import AlertEnricher

enricher = AlertEnricher()

results, dummyresults, settings = si.getOrganizedResults()

for result in results:
    alert_dict = {
        "detection_id": result.get("detection_id", ""),
        "creator_arn":  result.get("creator_arn", ""),
        "actor_arn":    result.get("actor_arn", ""),
        "new_user_name": result.get("new_user_name", ""),
        "event_source_ip": result.get("src_ip", ""),
        "mfa_used":     result.get("mfa_used", "yes"),
        "region":       result.get("region", ""),
        "severity":     result.get("severity", "medium"),
    }
    enriched = enricher.enrich(alert_dict)
    enriched_dict = enriched.to_dict()

    # Write enrichment fields back into the Splunk result row
    for k, v in enriched_dict.items():
        if not isinstance(v, dict):
            result[f"enrich_{k}"] = str(v)

si.outputResults(results)
```

Key points:

- Map Splunk field names to the alert dict keys expected by `AlertEnricher` (see Stage 4 for the
  username resolution order).
- `enriched.to_dict()` merges the original alert fields with all enrichment fields into a single
  flat dict safe for Splunk field output.
- The action script should be placed under `$SPLUNK_HOME/etc/apps/<app>/bin/` and referenced from a
  `alert_actions.conf` stanza.

---

## 7. Integration with IncidentReportGenerator

An enriched alert flows directly into `IncidentReportGenerator.generate()`. No field mapping is
required — the generator reads the `EnrichedAlert` dataclass fields directly.

```python
from pathlib import Path
from scripts.alert_enrichment import AlertEnricher
from scripts.incident_report_generator import IncidentReportGenerator

enricher = AlertEnricher()
enriched = enricher.enrich(alert_dict)

gen = IncidentReportGenerator()
report = gen.generate(enriched)                          # without CloudTrail events
# or:
report = gen.generate(enriched, events=parsed_events)   # with ParsedEvent list for timeline

paths = gen.write_reports(report, output_dir=Path("reports/generated"))
# paths["executive"] → <stem>_executive.md
# paths["analyst"]   → <stem>_analyst.md
# paths["json"]      → <stem>_summary.json
```

The report generator uses these enrichment fields:

| EnrichedAlert field | Used in report |
|---|---|
| `enriched_severity` / `base_severity` | Report severity; executive impact statement |
| `attack_tactic`, `attack_technique`, `attack_technique_name`, `attack_url` | ATT&CK section |
| `principal_exists`, `principal_mfa_active`, `principal_attached_policies` | Principal Context table |
| `severity_escalation_reason` | Escalation note in executive summary |
| `recommended_queries` | Pivot Queries section in analyst report |
| `enrichment_errors` | Enrichment Errors section in analyst report |
| `original` (pass-through dict) | Actor ARN, source IP, region, affected resource |

---

## 8. Worked Example

### Input alert

```python
alert = {
    "detection_id":    "CDET-001",
    "creator_arn":     "arn:aws:iam::123456789012:user/attacker",
    "event_source_ip": "203.0.113.45",
    "new_user_name":   "backdoor-user",
    "mfa_used":        "no",
    "severity":        "high",
    "region":          "us-east-1",
}
```

### Stage 1 output — ATT&CK context

```
attack_tactic          = "Persistence"
attack_technique       = "T1136.003"
attack_technique_name  = "Create Account: Cloud Account"
attack_url             = "https://attack.mitre.org/techniques/T1136/003/"
```

### Stage 2 output — Severity classification

```
base_severity              = "high"       # from _SEVERITY_ESCALATION["CDET-001"]["base"]
enriched_severity          = "critical"   # escalated because mfa_used = "no"
severity_escalation_reason = "MFA not used by actor"
```

### Stage 3 output — Lookup cross-reference

```
principal_in_approved_list   = False   # ARN not in approved_iam_principals.csv
principal_in_automation_roles = False  # ARN not in automation_role_arns.csv
```

(If the ARN were `arn:aws:iam::123456789012:role/TerraformExecutionRole`, the second flag would be
`True`.)

### Stage 4 output — Live IAM context

Assumes the IAM user `attacker` was just created and exists in the account:

```
principal_exists           = True
principal_create_date      = "2024-01-15T14:02:11+00:00"
principal_console_access   = True
principal_access_key_count = 1
principal_mfa_active       = False
principal_attached_policies = []
```

If IAM access is unavailable:

```
principal_exists = None          # field left at default
enrichment_errors = ["IAM enrichment failed: AccessDenied"]
```

### Stage 5 output — Investigation pivot queries

```python
recommended_queries = [
    'index=aws_cloudtrail "userIdentity.arn"="arn:aws:iam::123456789012:user/attacker" earliest=-7d | head 50',
    'index=aws_cloudtrail detection_id="CDET-001" earliest=-24h',
    'index=aws_cloudtrail "requestParameters.userName"="backdoor-user" earliest=-30d',
]
```

### Final EnrichedAlert (abbreviated)

```python
EnrichedAlert(
    original={
        "detection_id": "CDET-001",
        "creator_arn": "arn:aws:iam::123456789012:user/attacker",
        "event_source_ip": "203.0.113.45",
        "new_user_name": "backdoor-user",
        "mfa_used": "no",
        "severity": "high",
        "region": "us-east-1",
    },
    attack_tactic="Persistence",
    attack_technique="T1136.003",
    attack_technique_name="Create Account: Cloud Account",
    attack_url="https://attack.mitre.org/techniques/T1136/003/",
    base_severity="high",
    enriched_severity="critical",
    severity_escalation_reason="MFA not used by actor",
    principal_in_approved_list=False,
    principal_in_automation_roles=False,
    principal_exists=True,
    principal_mfa_active=False,
    principal_access_key_count=1,
    principal_console_access=True,
    principal_attached_policies=[],
    recommended_queries=[
        'index=aws_cloudtrail "userIdentity.arn"="arn:aws:iam::123456789012:user/attacker" earliest=-7d | head 50',
        'index=aws_cloudtrail detection_id="CDET-001" earliest=-24h',
        'index=aws_cloudtrail "requestParameters.userName"="backdoor-user" earliest=-30d',
    ],
    enrichment_errors=[],
)
```

---

## 9. Lookup Maintenance

The CSV files under `splunk/lookups/` act as the ground-truth allowlists for approved actors.
Keeping them accurate reduces false positives and makes `principal_in_approved_list` /
`principal_in_automation_roles` meaningful.

### approved_iam_principals.csv

Tracks human users and roles that are known-good and approved for the actions monitored by CDET
detections. Schema:

```
arn,approved,description,environment,date_added,expiry_date,added_by,reason
```

To add a new entry:

1. Open `splunk/lookups/approved_iam_principals.csv` in any text editor or spreadsheet tool.
2. Append a row with the full principal ARN in the `arn` column, `true` in `approved`, a short
   `description`, and the `date_added` (YYYY-MM-DD).
3. Set `expiry_date` if the approval is time-limited (e.g., a temporary break-glass account);
   leave blank for permanent entries.
4. Commit the change with a message that references the change request or ticket number.

Example row:

```
arn:aws:iam::123456789012:user/cicd-deployer,true,CircleCI deployment user,production,2024-06-01,,platform-team,Authorized for stack deployments via approved pipeline
```

### automation_role_arns.csv

Tracks IAM roles used by automation systems (Terraform, CloudFormation, Auto Scaling). Schema is
identical to `approved_iam_principals.csv` with `role_arn` as the key column. Follow the same
append procedure.

### admin_policy_arns.csv

Tracks policy ARNs that are considered high-risk when attached to a principal. Schema:

```
policy_arn,policy_name,risk_level,date_added,added_by,reason
```

`risk_level` values are `critical`, `high`, `medium`, or `low`. Entries here are used by Stage 2
to evaluate the `admin_policy_attached` escalation condition for CDET-001 and CDET-004.

### General guidance

- After updating any CSV, re-instantiate `AlertEnricher` in any long-running process (or restart
  the Splunk Adaptive Response action worker) so the new entries are loaded into memory.
- Treat the CSV files as code: review additions in pull requests, especially for
  `approved_iam_principals.csv`, as an erroneous entry can permanently suppress alerts for a
  compromised principal.
- Periodically audit entries with non-empty `expiry_date` values and remove or update rows that
  have passed their expiry.

---

*Part of the Cloud Threat Detection & Response Lab — Phase 2 alert enrichment.*
