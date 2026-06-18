# Detection Catalog

This directory contains all MITRE ATT&CK-mapped detections for the Cloud Threat Detection Lab. Each detection is a self-contained YAML document that defines the threat hypothesis, SPL logic, data requirements, and response actions.

---

## Detection ID Schema

Detection IDs follow the format: `DETECT-XXXX`

IDs are assigned sequentially and never reused. A retired detection is marked `status: retired` — its file and ID are preserved for auditability.

---

## Detection File Structure

Every detection YAML file follows this schema:

```yaml
# ─────────────────────────────────────────────
# Detection Metadata
# ─────────────────────────────────────────────
id: "DETECT-XXXX"
name: "Human-readable detection name"
version: "1.0.0"
status: "active"              # active | testing | tuning | retired
created: "YYYY-MM-DD"
last_modified: "YYYY-MM-DD"
author: "Author Name"
severity: "critical"          # critical | high | medium | low | informational
confidence: "high"            # high | medium | low

# ─────────────────────────────────────────────
# MITRE ATT&CK Mapping
# ─────────────────────────────────────────────
mitre:
  tactic_id: "TA0005"
  tactic_name: "Defense Evasion"
  technique_id: "T1562.008"
  technique_name: "Impair Defenses: Disable Cloud Logs"
  technique_url: "https://attack.mitre.org/techniques/T1562/008/"

# ─────────────────────────────────────────────
# Detection Hypothesis
# ─────────────────────────────────────────────
hypothesis: |
  An adversary who has obtained sufficient IAM permissions may disable CloudTrail
  logging to blind the SOC before conducting further malicious operations.
  This is a high-confidence indicator of adversary activity as legitimate
  workloads have no business reason to stop CloudTrail.

# ─────────────────────────────────────────────
# Data Requirements
# ─────────────────────────────────────────────
data_sources:
  - source: "AWS CloudTrail"
    index: "aws_cloudtrail"
    sourcetype: "aws:cloudtrail"
    required_fields:
      - "eventName"
      - "userIdentity.arn"
      - "userIdentity.type"
      - "sourceIPAddress"
      - "eventTime"
      - "errorCode"

# ─────────────────────────────────────────────
# Detection Logic (SPL)
# ─────────────────────────────────────────────
spl: |
  index=aws_cloudtrail sourcetype="aws:cloudtrail"
      eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail")
  | eval actor = coalesce('userIdentity.arn', 'userIdentity.userName', 'userIdentity.principalId')
  | eval is_assumed_role = if('userIdentity.type'=="AssumedRole", "true", "false")
  | table _time, actor, is_assumed_role, eventName, sourceIPAddress, awsRegion, requestParameters.*
  | sort -_time

# ─────────────────────────────────────────────
# Tuning / False Positive Guidance
# ─────────────────────────────────────────────
false_positives:
  - scenario: "Authorized CloudTrail reconfiguration during maintenance windows"
    suppression: "Add exclusion for specific IAM role ARNs performing planned changes"
  - scenario: "Infrastructure-as-code pipeline modifying trail configuration"
    suppression: "Exclude the CI/CD IAM role ARN used for trail management"

tuning_notes: |
  This detection has a very low expected false positive rate. Any fire should be
  treated as high-priority. Tune by excluding known-good automation roles rather
  than broadening the event filter.

# ─────────────────────────────────────────────
# Response Actions
# ─────────────────────────────────────────────
response_actions:
  automated:
    - action: "send_sns_alert"
      description: "Immediately notify security team via SNS"
      playbook_ref: "incident_response/playbooks/PB-0005_cloudtrail_disabled.md"
  manual:
    - step: 1
      action: "Verify the change was unauthorized — check change management records"
    - step: 2
      action: "Re-enable CloudTrail logging immediately"
    - step: 3
      action: "Determine what activity occurred in the logging gap"
    - step: 4
      action: "Revoke credentials of the actor if unauthorized"
    - step: 5
      action: "Open P1 incident and follow playbook"

# ─────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────
test_cases:
  true_positive:
    description: "StopLogging API call by non-admin IAM user"
    simulation_script: "attack_simulation/scenarios/SCENARIO-0005_disable_cloudtrail.py"
    expected_result: "Alert fires within 5 minutes"
  true_negative:
    description: "Authorized UpdateTrail call by IaC role"
    expected_result: "Alert suppressed by tuning exclusion"
```

---

## Detection Directories

| Directory | MITRE Tactic |
|-----------|--------------|
| `initial_access/` | TA0001 – Initial Access |
| `persistence/` | TA0003 – Persistence |
| `privilege_escalation/` | TA0004 – Privilege Escalation |
| `defense_evasion/` | TA0005 – Defense Evasion |
| `credential_access/` | TA0006 – Credential Access |
| `discovery/` | TA0007 – Discovery |
| `lateral_movement/` | TA0008 – Lateral Movement |
| `exfiltration/` | TA0010 – Exfiltration |
| `impact/` | TA0040 – Impact |

---

## Detection Lifecycle States

| Status | Meaning |
|--------|---------|
| `testing` | In development, not deployed to Splunk |
| `tuning` | Deployed but FP rate being reduced |
| `active` | Production-ready, alerting enabled |
| `retired` | No longer active; preserved for history |

---

## Coverage Metrics

See `config/mitre_mappings.yaml` for the authoritative technique-to-detection mapping.

Run the coverage report script to generate an up-to-date summary:

```bash
python scripts/utils/coverage_report.py
```
