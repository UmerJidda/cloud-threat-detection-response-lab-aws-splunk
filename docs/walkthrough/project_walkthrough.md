# Project Walkthrough

## Welcome

This walkthrough is written for a security engineer who is new to this project. It explains how the system works from end to end: how AWS telemetry enters the system, how detections operate, how validation confirms detection correctness, how investigations proceed, and how the program generates reports.

After reading this document, you should be able to:

1. Run the AWS collectors and understand what they produce
2. Understand how a detection is structured and how it fires
3. Run the validation framework and interpret the results
4. Follow a detection alert through an investigation
5. Understand how coverage is measured and reported

---

## Prerequisites

Before anything works, you need:

```bash
# 1. Configure AWS credentials (read-only Security Auditor role is sufficient)
aws configure

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Copy and fill in the lab configuration
cp config/lab_config.example.yaml config/lab_config.yaml
# Edit config/lab_config.yaml with your Splunk host, port, and AWS account ID
```

**Credential note:** This project never asks you to put AWS credentials in environment variables, `.env` files, or configuration files. `aws configure` writes to `~/.aws/credentials`, which boto3 reads automatically. Every Python script in this project calls `boto3.Session()` with no credential arguments — credentials are resolved behind the scenes from your local AWS configuration.

---

## 1. How AWS Telemetry Enters the System

### The Collection Layer

All AWS data collection lives in `scripts/aws_collectors/`. There are five collectors, each targeting a different AWS service:

| Collector | What It Collects | Why It Matters |
|-----------|-----------------|----------------|
| `cloudtrail_collector.py` | Management-plane API activity | Primary signal for most detections |
| `iam_collector.py` | Users, roles, access keys, policies | Security posture and drift detection |
| `security_group_collector.py` | Network rules, public exposure flags | Misconfiguration detection |
| `securityhub_collector.py` | Cross-service compliance findings | Compliance posture and enrichment |
| `guardduty_collector.py` | ML-detected threat findings | High-confidence corroborating signal |

### Running the Collectors

```bash
# Collect everything (last 24 hours of CloudTrail + current state of IAM/SG/GD/SH)
python -m scripts.aws_collectors.collect_cli \
  --all \
  --region us-east-1 \
  --output-dir data/collected

# Collect only CloudTrail with a longer lookback
python -m scripts.aws_collectors.collect_cli \
  --collector cloudtrail \
  --region us-east-1 \
  --lookback-hours 72 \
  --output-dir data/collected
```

### What Gets Produced

Each collector run creates one or more `.ndjson` files in `data/collected/`:

```
data/collected/
├── cloudtrail_123456789012_20240115T103000Z.ndjson
├── iam_123456789012_20240115T103005Z.ndjson
├── security_groups_123456789012_20240115T103010Z.ndjson
├── securityhub_123456789012_20240115T103015Z.ndjson
└── guardduty_123456789012_20240115T103020Z.ndjson
```

NDJSON (newline-delimited JSON) means one complete JSON object per line. Each object is a normalized record conforming to the schema in `scripts/aws_collectors/schema.py`.

### The Normalization Contract

Raw AWS API responses vary significantly across services. For example, the CloudTrail `LookupEvents` response embeds the actual event as a JSON string inside the `CloudTrailEvent` field. The IAM API returns dates as Python datetime objects. GuardDuty finding severity is a float on a 1–10 scale.

The collectors parse all of this and output a consistent structure:

```python
# schema.py — every CloudTrail event looks like this after normalization
@dataclass
class CloudTrailEvent:
    event_id: str
    event_time: datetime
    event_name: str               # e.g., "CreateUser"
    event_source: str             # e.g., "iam.amazonaws.com"
    aws_region: str
    source_ip_address: str
    user_agent: str
    user_identity_type: str       # IAMUser / AssumedRole / Root
    user_identity_arn: str | None # full ARN
    assumed_role_arn: str | None  # for AssumedRole sessions
    error_code: str | None        # e.g., "AccessDenied"
    request_parameters: dict
    response_elements: dict
    raw: dict                     # original API response preserved
```

Downstream detection logic and the validation framework depend on this contract. If AWS changes its API response format, only the collector needs to change — everything else keeps working.

### Getting Data into Splunk

The NDJSON files are ingested into Splunk using file monitoring inputs. In `config/lab_config.yaml`, configure the Splunk host and credentials. Then:

```bash
# Configure Splunk to watch the output directory
# (Add to Splunk inputs.conf on the Splunk server or Universal Forwarder)
[monitor:///path/to/data/collected/cloudtrail_*.ndjson]
sourcetype = aws:cloudtrail:normalized
index = aws_cloudtrail
```

See `docs/splunk/index_strategy.md` for the complete ingestion configuration.

---

## 2. How Detections Operate

### What a Detection Is

A detection is a Splunk correlation search that runs on a schedule and fires an alert when specific conditions are met in the CloudTrail data. Each detection lives in its own directory under `detections/{tactic}/`:

```
detections/defense_evasion/CDET-003_cloudtrail_logging_disabled/
├── detection.yaml   ← metadata, configuration, test cases
├── detection.spl    ← the SPL search logic
└── README.md        ← human-readable summary
```

### Reading a Detection

`detection.yaml` is the authoritative record for a detection:

```yaml
id: CDET-003
name: "CloudTrail Logging Disabled"
status: active
severity: critical
tactic: Defense Evasion
technique: "T1562.008"

data_sources:
  - cloudtrail

spl_file: detection.spl
splunk_index: aws_cloudtrail
schedule: "*/5 * * * *"    # every 5 minutes — critical severity

false_positive_notes: |
  Legitimate CloudTrail updates (UpdateTrail for configuration changes) may
  trigger if the filter is too broad. Verify the eventName is StopLogging
  or DeleteTrail specifically.

test_cases:
  - name: "StopLogging called from unknown principal"
    input_file: "data/samples/cloudtrail_stopLogging.ndjson"
    expected_alert: true
```

`detection.spl` is the actual search:

```spl
`aws_cloudtrail_index`
eventName IN (StopLogging, DeleteTrail, UpdateTrail)
eventSource="cloudtrail.amazonaws.com"
| eval principal_arn=coalesce('userIdentity.arn', "unknown")
| eval severity="critical", tactic="Defense Evasion", technique="T1562.008",
       technique_name="Impair Defenses: Disable Cloud Logs",
       detection_id="CDET-003"
| table _time, detection_id, severity, tactic, technique, technique_name,
         eventName, principal_arn, sourceIPAddress, awsRegion
```

Notice that:
- The index is referenced via the `` `aws_cloudtrail_index` `` macro, not hardcoded
- Severity, tactic, and technique are `eval`'d in — they don't come from the raw event
- Output fields follow the standard detection schema defined in `docs/detection_engineering/spl_guidelines.md`

### How Detection Searches Are Deployed

Detections are deployed to Splunk using the management script:

```bash
python scripts/splunk_ops/deploy_detections.py --env lab --validate
```

This reads all `detection.yaml` files, creates the corresponding Splunk saved searches, and schedules them per the cron expression in the YAML.

---

## 3. How Validation Works

### The Problem Validation Solves

Writing a detection and deploying it is not enough — you need to know it actually fires when it should. The validation framework addresses this without requiring live attack execution.

The framework runs each detection's SPL logic against a sample dataset and compares the output to the expected results defined in the test cases.

### Sample Datasets

Static NDJSON files in `data/samples/` represent real attack scenarios. They look exactly like collector output but contain synthesized or anonymized events that represent the adversary behavior the detection targets.

For example, `data/samples/cloudtrail_stopLogging.ndjson` might contain:

```json
{"event_id": "abc-001", "event_time": "2024-01-15T10:30:00Z", "event_name": "StopLogging", "event_source": "cloudtrail.amazonaws.com", "user_identity_type": "IAMUser", "user_identity_arn": "arn:aws:iam::123456789012:user/attacker", "source_ip_address": "203.0.113.5", "aws_region": "us-east-1", ...}
```

This event would trigger CDET-003. A corresponding benign dataset (`cloudtrail_update_trail_config_change.ndjson`) would contain a `UpdateTrail` event from a known automation role — the detection should NOT fire on this.

### Running Validation

```bash
# Run all detections
python scripts/validation/run_validation.py --all

# Run a specific detection
python scripts/validation/run_validation.py --detection CDET-003

# Run against live CloudTrail data instead of samples
python scripts/validation/run_validation.py --all --source historical --lookback-hours 24
```

### Interpreting Results

The validation run produces a report in `data/validation_results/`. The key output is:

```
Detection Validation Report — 2024-01-15
========================================
Total detections tested: 14
PASS: 11
FAIL:  2
ERROR: 1

FAILED:
  CDET-006 — Console Login from Unexpected Geolocation
    Test case: "Login from unknown country"
    Expected: alert=True, Actual: alert=False
    Cause: IP geolocation lookup table not populated

  CDET-009 — S3 Bucket Replication to External Account
    Test case: "Replication to unknown account"
    Expected: alert=True, Actual: alert=False
    Cause: approved_aws_accounts lookup missing
```

A FAIL means either the detection logic is wrong, the test data is wrong, or a dependency (like a lookup table) is missing. The validation report tells you which.

### Validation Against Live Data

When you have historical CloudTrail data available, you can validate that detections fire on real events:

```bash
# Collect 72 hours of CloudTrail history
python -m scripts.aws_collectors.collect_cli \
  --collector cloudtrail \
  --lookback-hours 72 \
  --output-dir data/collected

# Run validation against it
python scripts/validation/run_validation.py \
  --all \
  --source data/collected/cloudtrail_*.ndjson
```

This does not require any attacks to have occurred — it validates that detections process real events correctly and do not produce spurious errors.

---

## 4. How Investigations Occur

### Starting from an Alert

When a detection fires in Splunk, it creates a Notable Event. The Notable Event contains:
- The detection ID (e.g., `CDET-003`)
- The severity
- The relevant fields (principal ARN, source IP, region)
- A link to the playbook

### Finding the Playbook

Every active detection has a corresponding playbook in `incident_response/playbooks/`. The playbook file name mirrors the detection directory name:

```
incident_response/playbooks/CDET-003_cloudtrail_logging_disabled.md
```

The playbook provides:
1. What the detection means and why it matters
2. A triage checklist to confirm or dismiss as false positive in under 5 minutes
3. Ready-to-run Splunk SPL queries and AWS CLI commands for the investigation
4. Evidence preservation steps
5. Containment actions (ordered from least to most disruptive)
6. Recovery steps
7. Escalation criteria

### Evidence Collection

The key investigation query for any CloudTrail-sourced detection is the timeline for the affected principal:

```spl
index=aws_cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/alice"
| sort _time
| table _time, eventName, eventSource, sourceIPAddress, awsRegion, errorCode
```

You can also collect fresh AWS state data during an investigation without affecting the environment:

```bash
python -m scripts.aws_collectors.collect_cli \
  --all \
  --region us-east-1 \
  --output-dir data/investigation/
```

This read-only collection captures a snapshot of the current IAM state, active GuardDuty findings, and security group configuration that can be compared to the pre-incident baseline.

### Containment

Containment actions (disabling access keys, revoking sessions, isolating instances) require write permissions beyond the read-only collection role. These are documented in each playbook but executed manually by an analyst with the appropriate credentials, or automatically by Lambda functions configured in `automation/lambda/`.

The `dry_run: true` setting in `lab_config.yaml` must be explicitly set to `false` before automated containment actions will execute.

---

## 5. How Reports Are Generated

### Incident Reports

After an incident is closed, the analyst fills out the incident report template:

```bash
cp templates/incident_report_template.md \
   incident_response/reports/2024-01-15_INC-2024-001_cloudtrail_disabled.md
```

Incident reports are gitignored by default (they may contain sensitive details). They are stored locally and shared through internal channels.

### Validation Reports

The validation framework generates coverage reports automatically:

```bash
python scripts/validation/run_validation.py --all --report
# Outputs: data/validation_results/2024-01-15_validation_report.md
#          docs/detection_coverage/coverage_matrix.md (updated)
```

The coverage matrix in `docs/detection_coverage/coverage_matrix.md` is the living record of what is tested, what passes, and what is still planned.

### ATT&CK Coverage Report

The MITRE ATT&CK mapping documents in `docs/mitre_mapping/` are updated after each detection phase:

- `attack_matrix.md` — technique-level coverage map
- `coverage_plan.md` — priority and rationale for technique selection
- `detection_to_attack_mapping.md` — detection ID → technique cross-reference

These documents are manually maintained as detections are authored and reach Active status. The detection ID column in `detection_to_attack_mapping.md` is updated to reflect the current status.

---

## Repository Quick Reference

| Task | Command |
|------|---------|
| Configure AWS credentials | `aws configure` |
| Run all collectors | `python -m scripts.aws_collectors.collect_cli --all --region us-east-1` |
| Run CloudTrail only | `python -m scripts.aws_collectors.collect_cli --collector cloudtrail --lookback-hours 24` |
| Deploy detections to Splunk | `python scripts/splunk_ops/deploy_detections.py --env lab --validate` |
| Run validation suite | `python scripts/validation/run_validation.py --all` |
| Run single detection validation | `python scripts/validation/run_validation.py --detection CDET-003` |
| Run unit tests | `pytest tests/unit/ -v` |
| Run all tests | `pytest tests/ -v` |

---

## Where to Go Next

- **Architecture:** Read `docs/architecture/solution_architecture.md` for the full system design
- **Detection standards:** Read `docs/detection_engineering/detection_standards.md` before authoring detections
- **Writing a detection:** Start with `templates/detection_template.md`
- **Coverage gaps:** Check `docs/detection_coverage/coverage_matrix.md` for unaddressed techniques
- **ATT&CK mapping:** See `docs/mitre_mapping/coverage_plan.md` for prioritized technique list
