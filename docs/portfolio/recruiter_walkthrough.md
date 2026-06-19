# Recruiter Walkthrough: Cloud Threat Detection Lab

## What This Project Is

This repository is a fully self-contained detection engineering portfolio built to the same standards used in production SOC environments. It covers the complete lifecycle of a cloud detection: threat modeling a real attacker technique, writing a Splunk detection rule in SPL with lookup-based suppression, generating realistic test telemetry in NDJSON format, validating that logic independently in Python before touching Splunk, writing structured incident response playbooks, and producing audience-specific incident reports. Every component — 14 detection rules, 5 Python automation scripts, 56 playbook files, 53 sample log files, 11 Splunk lookup CSVs, and 9 AWS collector modules — was built from scratch and committed to version control.

---

## Why This Matters

Security teams lose an average of hours per alert because detection rules fire on noise, analysts lack the context to triage quickly, and there is no documented process for what to do once something fires. This project directly addresses all three problems. The lookup-mediated suppression system means known-good activity (IaC pipelines, automation roles) never reaches analysts. The Python enrichment layer attaches ATT&CK mapping, IAM context, and severity reasoning to every alert automatically. The four-phase playbooks (triage → investigate → contain → recover) tell the analyst exactly what to do. Taken together, this demonstrates not just the ability to write detection rules but an understanding of the full operational chain from telemetry to resolution.

---

## 5-Minute Tour

1. **Start here — the detection definition:**
   Open `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.yaml`. This YAML file is the single source of truth for one detection: ATT&CK mapping, severity, required data sources, suppression lookups, test cases, and the path to the playbook. Every one of the 14 CDETs has this structure.

   ```yaml
   id: CDET-001
   name: "IAM User Created Outside Approved Pipeline"
   tactic: "Persistence"
   technique: "T1136"
   sub_technique: "T1136.003"
   severity: high
   lookups:
     - name: approved_iam_principals
       file: splunk/lookups/approved_iam_principals.csv
     - name: automation_role_arns
       file: splunk/lookups/automation_role_arns.csv
   ```

2. **Then look at the SPL rule:**
   Open `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.spl`. Notice the double lookup join that suppresses approved IaC pipelines, the `coalesce` for normalizing AssumedRole vs. IAMUser identity fields, and the confidence scoring that distinguishes interactive logins from automated ones.

   ```spl
   | lookup approved_iam_principals arn AS principal_arn OUTPUT approved, suppression_reason
   | lookup automation_role_arns arn AS principal_arn OUTPUT approved AS auto_approved
   | eval suppressed=if(approved="true" OR auto_approved="true", "true", "false")
   | where suppressed!="true"
   ```

3. **Then notice the Python validator:**
   Open `scripts/detection_validator.py`. The `_detect_001()` function mirrors the SPL logic in Python. The `ValidationResult.passed` property is `should_fire == fired` — a boolean equality check, not a status field. This means the same test data that feeds Splunk can be validated offline, with no Splunk instance required.

   ```python
   @property
   def passed(self) -> bool:
       return self.should_fire == self.fired
   ```

4. **Then try the sample data:**
   Browse `sample_logs/cloudtrail/`. There are three subdirectories: `malicious/` (positive test cases that should fire), `benign/` (suppressed activity that should not fire), and `edge_cases/` (boundary conditions like approved roles in unusual regions). Each file is NDJSON — one event per line — so individual records can be appended, removed, or piped without parsing a JSON array.

5. **Finally see the playbooks:**
   Open `playbooks/CDET-001_iam_user_created_outside_pipeline/`. Four files: `triage.md`, `investigation.md`, `containment.md`, `recovery.md`. Every CDET has the same four-phase structure. An analyst receiving a CDET-001 alert has an exact, tested procedure to follow.

---

## Key Proof Points

- **14 detection rules covering 9 MITRE ATT&CK tactics** — shows breadth across Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Exfiltration, Lateral Movement, Impact, and Initial Access.
- **Python heuristic validator (`detection_validator.py`) mirrors SPL logic** — demonstrates understanding of detection-as-code: the same logic lives in two forms, one for Splunk production use and one for offline pre-ingestion testing.
- **Three-tier test model (malicious / benign / edge_case)** — goes beyond "does it fire" to prove it does not fire on known-good activity, which is the harder and more operationally important property.
- **Lookup-based suppression (`approved_iam_principals.csv`, `automation_role_arns.csv`)** — suppression is data, not logic. New approved principals can be added by updating a CSV without touching any detection code.
- **Structured YAML detection definitions** — each detection is a machine-readable specification with test cases, data source requirements, and playbook references embedded, not a loose SPL file.
- **Alert enrichment pipeline (`alert_enrichment.py`)** with severity escalation rules — CDET-001 escalates from high to critical when no MFA is present; CDET-007 escalates when the source IP is routable. Shows understanding of alert triage economics.
- **Audience-specific incident reports (`incident_report_generator.py`)** — produces executive summary (business impact), analyst report (technical timeline + IOCs), and JSON output (SIEM-ingestible) from the same data.
- **AWS collector modules using boto3 default credential chain** — zero hardcoded credentials anywhere. The pattern `boto3.Session()` resolves via `aws configure`, matching production security posture.
- **56 incident response playbooks (4 per CDET × 14 CDETs)** — each rule has an operationalized response procedure, not just a detection alert that drops into a queue with no guidance.
- **IOC extraction with RFC 5737 TEST-NET exclusions** — `ioc_extractor.py` correctly skips `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` so documentation example ranges never contaminate indicator lists.

---

## Technologies Used

| Technology | How Used | File Reference |
|---|---|---|
| Splunk SPL | Detection rules, lookup joins, spath JSON parsing, scheduled searches | `detections/*/detection.spl`, `splunk/savedsearches/` |
| Python 3 + dataclasses | CloudTrail normalization, detection validation, alert enrichment, IOC extraction, report generation | `scripts/*.py` |
| MITRE ATT&CK v15 | Tactic/technique mapping for all 14 CDETs | `scripts/alert_enrichment.py`, all `detection.yaml` files |
| AWS CloudTrail | Primary telemetry source; NDJSON test data format matches real CloudTrail records | `sample_logs/cloudtrail/`, `scripts/aws_collectors/cloudtrail_collector.py` |
| AWS IAM | Enrichment target (GetUser, ListAttachedUserPolicies), suppression lookup population | `scripts/aws_collectors/iam_collector.py` |
| AWS boto3 | Credential chain, all collector modules | `scripts/aws_collectors/*.py` |
| NDJSON | Sample test data format — one event per line for stream-compatible processing | `sample_logs/cloudtrail/**/*.ndjson` |
| YAML | Detection specification format — machine-readable single source of truth | `detections/**/detection.yaml` |
| structlog | Structured logging throughout Python scripts | All `scripts/*.py` |

---

## Project Scale

| Metric | Count |
|---|---|
| Detection rules (CDETs) | 14 |
| MITRE ATT&CK tactics covered | 9 |
| Python source files | 32 |
| Python lines of code (5 core scripts) | ~1,940 |
| Incident response playbook files | 56 |
| Sample test log files (NDJSON) | 53+ |
| Splunk lookup CSVs | 11 |
| Splunk savedsearch conf files | 3 |
| AWS collector modules | 9 |
| Total repository files (non-git) | ~437 |
| Development phases | 2 (architecture + detection engineering with Splunk integration) |
