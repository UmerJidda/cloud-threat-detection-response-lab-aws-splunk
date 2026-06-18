# Splunk Index Strategy

## Overview

This document defines the Splunk index architecture for the Cloud Threat Detection Lab. Index design directly affects search performance, data retention, access control, and the maintainability of detection searches. All indexes are referenced via SPL macros, never hardcoded in detection files.

---

## Index Architecture

### Indexes

| Index Name | Purpose | Primary Data Sources | Retention |
|-----------|---------|---------------------|----------|
| `aws_cloudtrail` | AWS management-plane events | CloudTrail LookupEvents (normalized NDJSON) | 90 days |
| `aws_security` | IAM posture and network configuration | IAM collector, security group collector | 90 days |
| `aws_alerts` | Security service findings | GuardDuty, Security Hub | 365 days |
| `aws_vpc_flow` | Network traffic metadata | VPC Flow Logs | 30 days |

### Rationale for Separate Indexes

**`aws_cloudtrail`** is kept separate from other sources because:
- It is the primary data source for 13 of 14 planned detections
- It generates high event volume and benefits from dedicated retention settings
- Access control can be enforced at the index level for audit log separation

**`aws_security`** is used for posture data (IAM state, security group configuration) rather than event data:
- Records represent current state snapshots, not time-series events
- Lower event volume — IAM and SG data changes infrequently
- Detections on this index typically compare current state to a baseline

**`aws_alerts`** aggregates pre-scored findings from AWS security services:
- GuardDuty and Security Hub findings are already triaged with severity scores
- Keeping them separate allows correlation with raw CloudTrail without polluting the primary event index
- Longer retention (365 days) supports trend analysis and compliance reporting

**`aws_vpc_flow`** is high-volume and typically only useful for network-level investigations:
- Short retention (30 days) balances investigation utility with storage cost
- Not yet in scope for Phase 1 detections

---

## Sourcetype Definitions

Each data type has a defined sourcetype that governs field extraction and CIM mapping.

| Sourcetype | Index | Format | CIM Data Model |
|-----------|-------|--------|---------------|
| `aws:cloudtrail:normalized` | `aws_cloudtrail` | NDJSON (from collector) | Authentication, Change Analysis |
| `aws:iam:normalized` | `aws_security` | NDJSON (from collector) | Identity Management |
| `aws:ec2:securitygroup:normalized` | `aws_security` | NDJSON (from collector) | Network Traffic |
| `aws:guardduty:finding` | `aws_alerts` | NDJSON (from collector) | Alerts |
| `aws:securityhub:finding` | `aws_alerts` | NDJSON (from collector) | Alerts |
| `aws:vpc:flow` | `aws_vpc_flow` | Standard VPC flow format | Network Traffic |

---

## SPL Macro Definitions

Detection files must reference indexes and sourcetypes exclusively through macros. The macro definitions are maintained in `splunk/macros/`.

### Index Macros

```spl
[aws_cloudtrail_index]
definition = index=aws_cloudtrail

[aws_security_index]
definition = index=aws_security

[aws_alerts_index]
definition = index=aws_alerts

[aws_vpc_flow_index]
definition = index=aws_vpc_flow
```

### Sourcetype Macros

```spl
[cloudtrail_events]
definition = sourcetype="aws:cloudtrail:normalized"

[guardduty_findings]
definition = sourcetype="aws:guardduty:finding"

[securityhub_findings]
definition = sourcetype="aws:securityhub:finding"
```

### Combined Convenience Macros

```spl
[iam_event]
definition = index=aws_cloudtrail sourcetype="aws:cloudtrail:normalized" eventSource="iam.amazonaws.com"

[cloudtrail_event(1)]
args = event_name
definition = index=aws_cloudtrail sourcetype="aws:cloudtrail:normalized" eventName="$event_name$"

[root_activity]
definition = index=aws_cloudtrail sourcetype="aws:cloudtrail:normalized" userIdentity.type=Root

[timeframe_15m]
definition = earliest=-15m latest=now

[timeframe_1h]
definition = earliest=-1h latest=now

[timeframe_24h]
definition = earliest=-24h latest=now
```

---

## Data Ingestion Pipeline

```
Collector Output (NDJSON)
        │
        ▼
data/collected/*.ndjson
        │
        ├─── Method A: Universal Forwarder file monitor input
        │         → monitors data/collected/
        │         → sourcetype assigned via transforms.conf
        │
        └─── Method B: Splunk HTTP Event Collector (HEC)
                  → POST to HEC endpoint
                  → sourcetype set in request header
```

### File Monitor Configuration (inputs.conf)

```ini
[monitor:///path/to/CloudThreatDetectionLab/data/collected/cloudtrail_*.ndjson]
sourcetype = aws:cloudtrail:normalized
index = aws_cloudtrail

[monitor:///path/to/CloudThreatDetectionLab/data/collected/iam_*.ndjson]
sourcetype = aws:iam:normalized
index = aws_security

[monitor:///path/to/CloudThreatDetectionLab/data/collected/security_groups_*.ndjson]
sourcetype = aws:ec2:securitygroup:normalized
index = aws_security

[monitor:///path/to/CloudThreatDetectionLab/data/collected/guardduty_*.ndjson]
sourcetype = aws:guardduty:finding
index = aws_alerts

[monitor:///path/to/CloudThreatDetectionLab/data/collected/securityhub_*.ndjson]
sourcetype = aws:securityhub:finding
index = aws_alerts
```

---

## Retention and Lifecycle

| Index | Hot/Warm | Frozen | Notes |
|-------|----------|--------|-------|
| `aws_cloudtrail` | 90 days | Archive to S3 | Standard compliance window |
| `aws_security` | 90 days | Delete | IAM/SG state data |
| `aws_alerts` | 365 days | Archive to S3 | Findings have regulatory value |
| `aws_vpc_flow` | 30 days | Delete | High volume; limited long-term value |

---

## Access Controls

| Index | Read Access | Write Access |
|-------|-------------|-------------|
| `aws_cloudtrail` | security_analyst, detection_engineer | indexer_service_account |
| `aws_security` | security_analyst, detection_engineer | indexer_service_account |
| `aws_alerts` | security_analyst, detection_engineer, management | indexer_service_account |
| `aws_vpc_flow` | security_analyst, detection_engineer | indexer_service_account |
