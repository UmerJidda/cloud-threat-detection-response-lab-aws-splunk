# EnrichedAlert Schema

Reference for the `EnrichedAlert` dataclass produced by `scripts/alert_enrichment.py`.

---

## Overview

`AlertEnricher.enrich(alert)` accepts a raw alert `dict` and returns an `EnrichedAlert`
dataclass instance. Enrichment is applied in five sequential layers:

| # | Layer | Data source | Requires AWS? |
|---|-------|-------------|---------------|
| 1 | ATT&CK context | `_ATTACK_CONTEXT` dict (in-process) | No |
| 2 | Severity context | `_SEVERITY_ESCALATION` dict + alert fields | No |
| 3 | Lookup context | `splunk/lookups/` CSV files | No |
| 4 | IAM context | boto3 IAM API (`get_user`, `list_*`) | Yes — best-effort |
| 5 | Investigation queries | Template strings built from alert fields | No |

All errors during IAM calls are appended to `enrichment_errors`; the pipeline
never raises — a partially enriched alert is always returned.

---

## Credential Security

All AWS calls use `boto3.Session()` with no explicit credentials. The session resolves
credentials through the boto3 default chain in order:

1. Environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`)
2. AWS shared credentials file (populated by `aws configure`)
3. IAM instance profile (EC2 / ECS / Lambda execution role)

**Credentials are never accepted as constructor arguments and must never be
hardcoded.** Run `aws configure` on the host before invoking the enricher.

---

## Input Alert Dict Contract

The enricher reads the following keys from the raw alert dict passed to `enrich()`.
All keys are optional — missing keys degrade gracefully.

| Field | Type | Description | Used by layer |
|-------|------|-------------|---------------|
| `detection_id` | `str` | CDET identifier, e.g. `"CDET-001"` | ATT&CK, Severity, Queries |
| `creator_arn` | `str` | ARN of the IAM principal who triggered the event | Lookup, IAM, Queries |
| `actor_arn` | `str` | Fallback ARN when `creator_arn` is absent | Lookup, IAM, Queries |
| `new_user_name` | `str` | Username of a newly created IAM user | IAM (username extraction), Queries |
| `target_user` | `str` | Fallback username for IAM lookup | IAM (username extraction), Queries |
| `mfa_used` | `str` | Whether MFA was used: `"yes"` / `"no"` / `"true"` / `"false"` / `"1"` / `"0"` | Severity escalation |
| `severity` | `str` | Base severity from the detection rule (fallback if CDET not in escalation dict) | Severity |
| `event_source_ip` | `str` | Source IP of the triggering API call (pass-through, not directly enriched) | Queries (future) |

Username extraction priority (IAM layer): `new_user_name` > `target_user` >
last path segment of `creator_arn` > last path segment of `actor_arn`.

---

## EnrichedAlert Fields

### Pass-through

| Field | Type | Layer | Description | Example |
|-------|------|-------|-------------|---------|
| `original` | `dict[str, Any]` | — | The unmodified input alert dict | `{"detection_id": "CDET-001", ...}` |

`to_dict()` merges `original` into the returned dict so all raw alert fields are
present at the top level alongside enrichment fields.

---

### Layer 1 — ATT&CK Context

Populated from the module-level `_ATTACK_CONTEXT` dict keyed on `detection_id`.
No network call is made. If `detection_id` is absent or unknown all four fields
are set to `""`.

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `attack_tactic` | `str` | MITRE ATT&CK tactic name | `"Persistence"` |
| `attack_technique` | `str` | ATT&CK technique ID | `"T1136.003"` |
| `attack_technique_name` | `str` | Human-readable technique name | `"Create Account: Cloud Account"` |
| `attack_url` | `str` | Direct URL to the ATT&CK technique page | `"https://attack.mitre.org/techniques/T1136/003/"` |

Mapping for all 14 CDETs:

| CDET | Tactic | Technique |
|------|--------|-----------|
| CDET-001 | Persistence | T1136.003 — Create Account: Cloud Account |
| CDET-002 | Persistence | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| CDET-003 | Defense Evasion | T1562.008 — Impair Defenses: Disable Cloud Logs |
| CDET-004 | Privilege Escalation | T1078.004 — Valid Accounts: Cloud Accounts |
| CDET-005 | Privilege Escalation | T1484.002 — Domain Policy Modification: Trust Modification |
| CDET-006 | Initial Access | T1078.004 — Valid Accounts: Cloud Accounts |
| CDET-007 | Credential Access | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| CDET-008 | Discovery | T1580 — Cloud Infrastructure Discovery |
| CDET-009 | Exfiltration | T1537 — Transfer Data to Cloud Account |
| CDET-010 | Impact | T1485 — Data Destruction |
| CDET-011 | Impact | T1496 — Resource Hijacking |
| CDET-012 | Lateral Movement | T1550.001 — Use Alternate Authentication Material |
| CDET-013 | Defense Evasion | T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall |
| CDET-014 | Defense Evasion | T1070.004 — Indicator Removal: File Deletion |

---

### Layer 2 — Severity Context

Populated from `_SEVERITY_ESCALATION` keyed on `detection_id`, combined with
alert field `mfa_used`. If `detection_id` is unknown, `base_severity` falls back
to `alert.get("severity", "medium")`.

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `base_severity` | `str` | Severity from the static escalation config for this CDET | `"high"` |
| `enriched_severity` | `str` | Final severity after applying any escalation rules | `"critical"` |
| `severity_escalation_reason` | `str` | Human-readable explanation for an escalation, or `""` if none | `"MFA not used by actor"` |

Escalation logic currently implemented:

- `no_mfa` condition: if `mfa_used` parses as falsy (`"no"`, `"false"`, `"0"`)
  and `"no_mfa"` appears in the CDET's `escalate_if` list, severity is escalated
  and `severity_escalation_reason` is set to `"MFA not used by actor"`.
- Other conditions (`second_key_created`, `external_account`, `external_ip`,
  `rapid_enumeration`, `unapproved_account`, `unapproved_region`, `gpu_instance`,
  `three_hop_chain`, `port_22_or_3389`) are defined in the config dict and
  reserved for future alert-field-driven escalation logic.

Base severities by CDET:

| Severity | CDETs |
|----------|-------|
| `critical` | CDET-003, CDET-004, CDET-006, CDET-010, CDET-014 |
| `high` | CDET-001, CDET-002, CDET-005, CDET-007, CDET-009, CDET-011, CDET-012, CDET-013 |
| `medium` | CDET-008 |

---

### Layer 3 — Lookup Context

Populated by matching the principal ARN (from `creator_arn` or `actor_arn`)
against sets loaded at `AlertEnricher.__init__` time from CSV files under
`splunk/lookups/`. Missing CSV files are silently skipped (debug-logged).

| Field | Type | Description | Source CSV | Key column |
|-------|------|-------------|------------|------------|
| `principal_in_approved_list` | `bool` | ARN appears in the approved principals list | `approved_iam_principals.csv` | `principal_arn` (falls back to `arn`) |
| `principal_in_automation_roles` | `bool` | ARN matches a known automation/CI role | `automation_role_arns.csv` | `role_arn` (falls back to `arn`) |

CSV column resolution: the loader reads `row.get("principal_arn") or row.get("role_arn") or row.get("policy_arn", "")`, so both generic `arn` header names and the purpose-specific column names above work.

`admin_policy_arns.csv` is also loaded into an internal `_admin_policies` set
(column `policy_arn`) for future use in severity escalation — it does not
currently produce an `EnrichedAlert` field.

CSV schemas:

**`approved_iam_principals.csv`**

| Column | Description |
|--------|-------------|
| `arn` | IAM principal ARN (user or role) |
| `approved` | `true` / `false` |
| `description` | Free-text label |
| `environment` | `production` / `all` / etc. |
| `date_added` | ISO date |
| `expiry_date` | ISO date or blank |
| `added_by` | Team or person who approved |
| `reason` | Justification |

**`automation_role_arns.csv`** — same columns as above (`arn` key).

**`admin_policy_arns.csv`**

| Column | Description |
|--------|-------------|
| `policy_arn` | IAM managed policy ARN |
| `policy_name` | Short display name |
| `risk_level` | `critical` / `high` / `low` |
| `date_added` | ISO date |
| `added_by` | Team or person |
| `reason` | Justification |

---

### Layer 4 — IAM Context

Populated via boto3 IAM API calls. Username extraction: `new_user_name` >
`target_user` > last `/`-delimited segment of `creator_arn` > last segment of
`actor_arn`. If no username can be derived the entire layer is skipped and all
fields remain at their dataclass defaults (`None` / `[]`).

All fields are `None` (not `False` / `0`) when the layer was skipped or a
non-fatal error was encountered; distinguish "unknown" from "false".

| Field | Type | boto3 call | Description | Example |
|-------|------|-----------|-------------|---------|
| `principal_exists` | `bool \| None` | `iam.get_user(UserName=...)` | `True` if the IAM user was found; `False` on `NoSuchEntity`; `None` if lookup failed with another error | `True` |
| `principal_create_date` | `str \| None` | `iam.get_user` → `User.CreateDate` | ISO-8601 string of the user's creation timestamp | `"2024-03-15T14:22:10+00:00"` |
| `principal_mfa_active` | `bool \| None` | `iam.list_mfa_devices(UserName=...)` | `True` if at least one MFA device is registered | `False` |
| `principal_attached_policies` | `list[str]` | `iam.list_attached_user_policies(UserName=...)` | List of managed policy ARNs attached directly to the user | `["arn:aws:iam::aws:policy/ReadOnlyAccess"]` |
| `principal_access_key_count` | `int \| None` | `iam.list_access_keys(UserName=...)` | Number of access keys (active or inactive) on the user | `2` |
| `principal_console_access` | `bool \| None` | `iam.get_login_profile(UserName=...)` | `True` if a console password login profile exists; `False` on `NoSuchEntity` | `True` |

Error handling for IAM layer:

- `NoSuchEntity` on `get_user` sets `principal_exists = False` and returns
  without calling the remaining IAM APIs.
- `NoSuchEntity` on `get_login_profile` returns `False` for
  `principal_console_access` without recording an error.
- Any other `ClientError` (permissions denied, throttling, etc.) appends a
  message to `enrichment_errors` and leaves the field at its default; remaining
  IAM sub-calls are not attempted.

---

### Layer 5 — Investigation Queries

Always populated from templates; no network call required.

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `recommended_queries` | `list[str]` | Splunk SPL strings for follow-on investigation | See below |

Every alert receives at least two queries:

1. All CloudTrail events by actor ARN over the last 7 days:
   ```
   index=aws_cloudtrail "userIdentity.arn"="<actor_arn>" earliest=-7d | head 50
   ```
2. All events matching this detection ID over the last 24 hours:
   ```
   index=aws_cloudtrail detection_id="<detection_id>" earliest=-24h
   ```

For detections involving a target user (`CDET-001`, `CDET-002`, `CDET-004`)
a third query is appended:

3. All CloudTrail events touching the target username over the last 30 days:
   ```
   index=aws_cloudtrail "requestParameters.userName"="<new_user_name>" earliest=-30d
   ```

Placeholder values (`ACTOR_ARN`, `TARGET_USER`) are substituted when the
corresponding alert fields are absent.

---

### Error Tracking

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `enrichment_errors` | `list[str]` | Accumulated non-fatal error messages from any layer | `["IAM enrichment failed: AccessDenied", "login profile check failed: ..."]` |

The pipeline never raises an exception. Every caught error appends a descriptive
string to this list. Consumers should surface any non-empty `enrichment_errors`
to the analyst.

---

## Example

Input alert:

```python
{
    "detection_id": "CDET-001",
    "creator_arn": "arn:aws:iam::123456789012:user/attacker",
    "event_source_ip": "203.0.113.45",
    "new_user_name": "backdoor-user",
    "mfa_used": "no",
    "severity": "high",
}
```

Resulting `EnrichedAlert` (AWS fields shown with hypothetical IAM response):

```python
EnrichedAlert(
    original={...},                          # pass-through of input dict

    # Layer 1 — ATT&CK
    attack_tactic="Persistence",
    attack_technique="T1136.003",
    attack_technique_name="Create Account: Cloud Account",
    attack_url="https://attack.mitre.org/techniques/T1136/003/",

    # Layer 2 — Severity (escalated because mfa_used="no")
    base_severity="high",
    enriched_severity="critical",
    severity_escalation_reason="MFA not used by actor",

    # Layer 3 — Lookups
    principal_in_approved_list=False,
    principal_in_automation_roles=False,

    # Layer 4 — IAM (requires live AWS session)
    principal_exists=True,
    principal_create_date="2024-12-01T09:00:00+00:00",
    principal_mfa_active=False,
    principal_attached_policies=["arn:aws:iam::aws:policy/AdministratorAccess"],
    principal_access_key_count=1,
    principal_console_access=True,

    # Layer 5 — Queries
    recommended_queries=[
        'index=aws_cloudtrail "userIdentity.arn"="arn:aws:iam::123456789012:user/attacker" earliest=-7d | head 50',
        'index=aws_cloudtrail detection_id="CDET-001" earliest=-24h',
        'index=aws_cloudtrail "requestParameters.userName"="backdoor-user" earliest=-30d',
    ],

    enrichment_errors=[],
)
```
