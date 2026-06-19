# Telemetry Pipeline: AWS to Splunk

This document describes how telemetry flows from AWS services into Splunk, covering the full path from event generation to indexed and searchable data. It also describes how the `sample_logs/` corpus substitutes for a live Splunk instance during offline development and validation.

---

## 1. Primary Telemetry Sequence

```mermaid
sequenceDiagram
    participant CT as AWS CloudTrail
    participant S3 as S3 Bucket
    participant Op as SOC Operator
    participant CLI as collect_cli.py
    participant CC as cloudtrail_collector.py
    participant API as boto3 / CloudTrail API
    participant FS as data/collected/
    participant HEC as Splunk HEC
    participant IDX as aws_cloudtrail index
    participant DET as Detection Search
    participant ALT as cdet_alerts index

    CT ->> S3: Write log archive (5-min delivery, gzip JSON)
    Op ->> CLI: python scripts/aws_collectors/collect_cli.py --service cloudtrail
    CLI ->> CC: CloudTrailCollector.collect()
    CC ->> API: LookupEvents (paginated, boto3 default credential chain)
    API -->> CC: CloudTrail records (JSON)
    CC ->> FS: Write NDJSON output (data/collected/cloudtrail_<timestamp>.ndjson)
    Op ->> HEC: curl/Splunk forwarder ingest NDJSON from data/collected/
    HEC ->> IDX: Index events (sourcetype=aws:cloudtrail, index=aws_cloudtrail)
    DET ->> IDX: SPL query every 5 min (cdet_alerts.conf saved searches)
    DET ->> ALT: Write alert event on detection match
```

---

## 2. Parallel Telemetry Paths

The lab collects from four AWS telemetry sources, each with a dedicated collector module. All collectors share the `BaseCollector` interface defined in `scripts/aws_collectors/base_collector.py` and all use `boto3.Session()` with the default credential chain.

| Service | Collector Module | Output Index | Primary Use |
|---|---|---|---|
| CloudTrail (management events) | `scripts/aws_collectors/cloudtrail_collector.py` — `CloudTrailCollector` | `aws_cloudtrail` | Primary detection data source for all 14 CDETs |
| GuardDuty findings | `scripts/aws_collectors/guardduty_collector.py` — `GuardDutyCollector` | `aws_security` | Threat intelligence correlation; GuardDuty-native findings |
| Security Hub findings | `scripts/aws_collectors/securityhub_collector.py` — `SecurityHubCollector` | `aws_security` | Aggregated compliance and partner findings |
| IAM configuration snapshots | `scripts/aws_collectors/iam_collector.py` — `IAMCollector` | `aws_security` | Identity baseline for enrichment and anomaly detection |

The `scripts/aws_collectors/security_group_collector.py` (`SecurityGroupCollector`) collects EC2 security group configurations and feeds the `aws_security` index with network exposure snapshots used by CDET-013.

All collected data is written as NDJSON to `data/collected/` before Splunk ingestion.

---

## 3. NDJSON Field Mapping: CloudTrail to Splunk

When CloudTrail NDJSON is indexed by Splunk with `sourcetype=aws:cloudtrail`, the following field mappings apply. Fields marked with an asterisk are extracted by Splunk's built-in `aws:cloudtrail` props/transforms; the others are extracted via the lab's custom field extractions.

| CloudTrail JSON Field | Splunk Field Name | Notes |
|---|---|---|
| `eventName` | `eventName` | Primary detection pivot field |
| `eventSource` | `eventSource` | e.g. `iam.amazonaws.com`, `s3.amazonaws.com` |
| `eventTime` | `_time` | Indexed as the event timestamp |
| `awsRegion` | `awsRegion` | Used by region-based detections (CDET-011) |
| `sourceIPAddress` | `sourceIPAddress` | Used for CIDR lookup suppression |
| `userAgent` | `userAgent` | Automation tool fingerprinting |
| `userIdentity.type` | `userIdentity_type` | `IAMUser`, `AssumedRole`, `Root`, `AWSService` |
| `userIdentity.arn` | `userIdentity_arn` | Full principal ARN; primary enrichment key |
| `userIdentity.accountId` | `userIdentity_accountId` | Account boundary checks (CDET-005, CDET-009, CDET-012) |
| `userIdentity.userName` | `userIdentity_userName` | Populated for `IAMUser` type only |
| `userIdentity.sessionContext.sessionIssuer.arn` | `session_issuer_arn` | Role ARN for assumed-role sessions |
| `userIdentity.sessionContext.sessionIssuer.type` | `session_issuer_type` | `Role` or `FederatedUser` |
| `userIdentity.sessionContext.attributes.mfaAuthenticated` | `mfaAuthenticated` | Boolean string `"true"` / `"false"` |
| `errorCode` | `errorCode` | Present only on failed API calls |
| `errorMessage` | `errorMessage` | Human-readable error text |
| `requestParameters` | `requestParameters` | JSON string; KV-extracted per eventName |
| `responseElements` | `responseElements` | JSON string; KV-extracted per eventName |
| `recipientAccountId` | `recipientAccountId` | Destination account for cross-account events |

### Detection-specific derived fields

Several CDETs rely on fields derived from `requestParameters` by Splunk field extractions:

| Derived Splunk Field | Source | Used by |
|---|---|---|
| `new_user_name` | `requestParameters.userName` on `CreateUser` | CDET-001 |
| `creator_arn` | `userIdentity_arn` on `CreateUser` / `CreateAccessKey` | CDET-001, CDET-002 |
| `policy_arn` | `requestParameters.policyArn` on `AttachUserPolicy` / `AttachRolePolicy` | CDET-004 |
| `trust_policy_document` | `requestParameters.policyDocument` on `UpdateAssumeRolePolicy` | CDET-005 |
| `instance_type` | `requestParameters.instanceType` on `RunInstances` | CDET-011 |
| `destination_account` | `requestParameters.ReplicationConfiguration.Role` or trust policy ARN | CDET-005, CDET-009 |
| `bucket_name` | `requestParameters.bucketName` | CDET-009, CDET-010, CDET-014 |
| `assumed_role_arn` | `requestParameters.RoleArn` on `AssumeRole` | CDET-012 |

---

## 4. Collector Execution Commands

Use `python` (not `python3`) for all collector invocations. The `collect_cli.py` script is the single entry point for all collector modules.

**Collect CloudTrail management events (primary detection source):**
```bash
python scripts/aws_collectors/collect_cli.py --service cloudtrail
```

**Collect GuardDuty findings:**
```bash
python scripts/aws_collectors/collect_cli.py --service guardduty
```

**Collect Security Hub findings:**
```bash
python scripts/aws_collectors/collect_cli.py --service securityhub
```

**Collect IAM configuration snapshot:**
```bash
python scripts/aws_collectors/collect_cli.py --service iam
```

**Collect all services in sequence:**
```bash
python scripts/aws_collectors/collect_cli.py --service cloudtrail
python scripts/aws_collectors/collect_cli.py --service guardduty
python scripts/aws_collectors/collect_cli.py --service securityhub
python scripts/aws_collectors/collect_cli.py --service iam
```

All commands require valid AWS credentials configured via `aws configure`. The collectors call `boto3.Session()` with no arguments and resolve credentials from the standard chain (environment variables, shared credentials file, IAM instance profile). No credentials are accepted as command-line arguments or hardcoded in any module.

Output files are written to `data/collected/` with the naming convention `<service>_<ISO8601_timestamp>.ndjson`.

---

## 5. Offline Validation Using sample_logs/ as a Splunk Substitute

During lab development and portfolio demonstration, the `sample_logs/cloudtrail/` corpus replaces a live Splunk environment. The substitution works at two levels.

### Level 1 — Python heuristic validation (fully offline)

`scripts/detection_validator.py` mirrors each SPL detection rule in Python. It consumes NDJSON files directly via `CloudTrailParser.parse_file()` and returns a `ValidationResult` without any network dependency.

```
sample_logs/cloudtrail/malicious/CDET-00X_*.ndjson
         |
         v
CloudTrailParser.parse_file()
         |
         v
list[ParsedEvent]
         |
         v
DetectionValidator.run_validation("CDET-00X", events)
         |
         v
ValidationResult(passed=True, summary="[PASS] ...")
```

The 42 validation test cases in `validation/` each contain an `expected_alert.json` that specifies the precise fields a detection must produce. The Python validator checks `matched_events` and `field_checks` against these expected values.

### Level 2 — Enrichment and report generation (offline)

Because `AlertEnricher` is designed for best-effort enrichment, it functions with degraded (lookup-only) output when AWS credentials are unavailable:

- ATT&CK context is resolved entirely from the local `_ATTACK_CONTEXT` dictionary in `alert_enrichment.py` — no API call needed.
- Severity escalation is resolved from the local `_SEVERITY_ESCALATION` dictionary — no API call needed.
- Lookup cross-references are resolved from `splunk/lookups/` CSVs — no API call needed.
- IAM live enrichment (principal existence, MFA status, attached policies) is skipped and `enrichment_errors` is populated — requires live AWS credentials.

This means `IoCExtractor` and `IncidentReportGenerator` can produce complete reports from `sample_logs/` data with no AWS or Splunk dependency, demonstrating the full pipeline in a portfolio context.

### Directory structure of the offline corpus

```
sample_logs/cloudtrail/
├── malicious/          # 14 positive test cases — one per CDET
│   ├── CDET-001_iam_user_created_outside_pipeline.ndjson
│   ├── CDET-002_iam_access_key_created_for_existing_user.ndjson
│   └── ... (CDET-003 through CDET-014)
├── benign/             # 14 negative test cases + 4 normal-activity baselines
│   ├── CDET-001_pipeline_createuser.ndjson
│   ├── CDET-002_self_key_creation.ndjson
│   ├── ... (CDET-003 through CDET-014)
│   ├── normal_ec2_activity.ndjson
│   ├── normal_iam_activity.ndjson
│   ├── normal_s3_activity.ndjson
│   └── normal_sts_activity.ndjson
└── edge_cases/         # 14 boundary-condition test cases — one per CDET
    ├── CDET-001_edge_approved_role_unusual_region.ndjson
    ├── CDET-002_edge_key_rotation_same_day.ndjson
    └── ... (CDET-003 through CDET-014)
```

Each NDJSON file contains one or more CloudTrail event records, one per line, in the exact format produced by `CloudTrailCollector`. This ensures that the same `CloudTrailParser` code path is exercised in both offline validation and live collection.
