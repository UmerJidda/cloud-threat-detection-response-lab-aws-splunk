# End-to-End Architecture

This diagram shows the complete data flow and component relationships across all layers of the Cloud Threat Detection Lab — from raw AWS telemetry through collection, normalization, SIEM ingestion, detection, and incident response.

```mermaid
flowchart TD
    subgraph AWS["AWS Layer"]
        CT[CloudTrail]
        GD[GuardDuty]
        SH[SecurityHub]
        IAM[IAM]
    end

    subgraph Collection["Collection Layer"]
        CLI[collect_cli.py]
        CTC[cloudtrail_collector.py]
        GDC[guardduty_collector.py]
        SHC[securityhub_collector.py]
        IAMC[iam_collector.py]
        NDJSON[data/collected/*.ndjson]
        PARSER[CloudTrailParser]
    end

    subgraph SIEM["SIEM Layer"]
        HEC[Splunk HEC / UF Monitor]
        IDX1[Index: aws_cloudtrail]
        IDX2[Index: aws_security]
        IDX3[Index: cdet_alerts]
        LOOKUPS[Lookup Suppression\n11 CSV files]
    end

    subgraph Detection["Detection Layer"]
        D01[CDET-001: RootAccountUsage]
        D02[CDET-002: ConsoleLoginFailures]
        D03[CDET-003: IAMPrivilegeEscalation]
        D04[CDET-004: UnusualRegionActivity]
        D05[CDET-005: S3BucketPublicExposure]
        D06[CDET-006: AccessKeyCreation]
        D07[CDET-007: SecurityGroupModification]
        D08[CDET-008: CloudTrailDisabled]
        D09[CDET-009: MassiveDataExfiltration]
        D10[CDET-010: CredentialStuffing]
        D11[CDET-011: IMDSv1Abuse]
        D12[CDET-012: LambdaBackdoor]
        D13[CDET-013: AssumeRoleChain]
        D14[CDET-014: GuardDutyFinding]
        DETGRP[14 SPL Saved Searches]
    end

    subgraph Response["Response Layer"]
        ENRICH[alert_enrichment.py\nATT&CK + IAM + Severity]
        IOC[ioc_extractor.py]
        REPORT[incident_report_generator.py]
        PB[playbooks/]
        RPTS[reports/\nexecutive + analyst + JSON]
    end

    CT -->|API / S3 events| CLI
    GD -->|Findings| CLI
    SH -->|Findings| CLI
    IAM -->|Credentials & Context| CLI

    CLI --> CTC
    CLI --> GDC
    CLI --> SHC
    CLI --> IAMC

    CTC --> NDJSON
    GDC --> NDJSON
    SHC --> NDJSON
    IAMC --> NDJSON

    NDJSON --> PARSER
    PARSER -->|Normalized events| HEC

    HEC --> IDX1
    HEC --> IDX2

    IDX1 --> DETGRP
    IDX2 --> DETGRP

    DETGRP --> D01
    DETGRP --> D02
    DETGRP --> D03
    DETGRP --> D04
    DETGRP --> D05
    DETGRP --> D06
    DETGRP --> D07
    DETGRP --> D08
    DETGRP --> D09
    DETGRP --> D10
    DETGRP --> D11
    DETGRP --> D12
    DETGRP --> D13
    DETGRP --> D14

    LOOKUPS -->|Suppress known-good| DETGRP

    D01 --> IDX3
    D02 --> IDX3
    D03 --> IDX3
    D04 --> IDX3
    D05 --> IDX3
    D06 --> IDX3
    D07 --> IDX3
    D08 --> IDX3
    D09 --> IDX3
    D10 --> IDX3
    D11 --> IDX3
    D12 --> IDX3
    D13 --> IDX3
    D14 --> IDX3

    IDX3 --> ENRICH
    ENRICH --> IOC
    ENRICH --> REPORT
    IOC --> REPORT
    REPORT --> RPTS
    REPORT --> PB

    classDef aws fill:#FF9900,stroke:#CC7700,color:#000
    classDef python fill:#3776AB,stroke:#2B5F8A,color:#fff
    classDef splunk fill:#2ECC71,stroke:#229954,color:#000
    classDef response fill:#8E44AD,stroke:#6C3483,color:#fff

    class CT,GD,SH,IAM aws
    class CLI,CTC,GDC,SHC,IAMC,PARSER,ENRICH,IOC,REPORT python
    class HEC,IDX1,IDX2,IDX3,LOOKUPS,DETGRP,D01,D02,D03,D04,D05,D06,D07,D08,D09,D10,D11,D12,D13,D14 splunk
    class PB,RPTS response
```

## Component File Path Reference

| Node | File Path in Repository |
|------|------------------------|
| CloudTrail | AWS managed service |
| GuardDuty | AWS managed service |
| SecurityHub | AWS managed service |
| IAM | AWS managed service |
| collect_cli.py | `scripts/aws_collectors/collect_cli.py` |
| cloudtrail_collector.py | `scripts/aws_collectors/cloudtrail_collector.py` |
| guardduty_collector.py | `scripts/aws_collectors/guardduty_collector.py` |
| securityhub_collector.py | `scripts/aws_collectors/securityhub_collector.py` |
| iam_collector.py | `scripts/aws_collectors/iam_collector.py` |
| data/collected/*.ndjson | `data/collected/` |
| CloudTrailParser | `scripts/aws_collectors/cloudtrail_parser.py` |
| Splunk HEC / UF Monitor | `ingestion/` |
| Index: aws_cloudtrail | Splunk index (configured in `splunk/indexes.conf`) |
| Index: aws_security | Splunk index (configured in `splunk/indexes.conf`) |
| Index: cdet_alerts | Splunk index (configured in `splunk/indexes.conf`) |
| Lookup Suppression (11 CSVs) | `splunk/lookups/*.csv` |
| 14 SPL Saved Searches | `detections/splunk/` |
| CDET-001 through CDET-014 | `detections/splunk/CDET-00X/` |
| alert_enrichment.py | `enrichment/alert_enrichment.py` |
| ioc_extractor.py | `enrichment/ioc_extractor.py` |
| incident_report_generator.py | `incident_response/incident_report_generator.py` |
| playbooks/ | `playbooks/` |
| reports/ | `reports/` |
