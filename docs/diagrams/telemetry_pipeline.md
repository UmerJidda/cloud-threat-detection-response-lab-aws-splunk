# Telemetry Pipeline

This sequence diagram traces the exact data flow from an adversary's malicious AWS API call all the way through collection, normalization, SIEM ingestion, detection, enrichment, and report generation. A parallel offline validation path is also shown for detection engineering work done outside of Splunk.

```mermaid
sequenceDiagram
    actor Attacker
    actor SOC_Operator
    participant AWS_API
    participant CloudTrail_API
    participant collect_cli as collect_cli.py
    participant cloudtrail_collector as cloudtrail_collector.py
    participant NDJSON_file as data/collected/*.ndjson
    participant CloudTrailParser as CloudTrailParser
    participant Splunk_HEC as Splunk HEC / UF Monitor
    participant aws_cloudtrail_index as Index: aws_cloudtrail
    participant Detection_Search as SPL Detection Search
    participant cdet_alerts_index as Index: cdet_alerts
    participant AlertEnricher as alert_enrichment.py
    participant IncidentReportGenerator as incident_report_generator.py
    participant reports as reports/

    Attacker->>AWS_API: Malicious API call (e.g., CreateUser)
    AWS_API->>CloudTrail_API: Write event to S3 log archive

    SOC_Operator->>collect_cli: python collect_cli.py --service cloudtrail
    collect_cli->>cloudtrail_collector: CloudTrailCollector().collect()
    cloudtrail_collector->>CloudTrail_API: LookupEvents (paginated)
    CloudTrail_API-->>cloudtrail_collector: CloudTrail records (JSON)
    cloudtrail_collector->>NDJSON_file: Write data/collected/cloudtrail_YYYYMMDD.ndjson

    SOC_Operator->>Splunk_HEC: POST NDJSON (or Splunk UF monitor stanza)
    Splunk_HEC->>aws_cloudtrail_index: Index normalized events

    Note over Detection_Search,aws_cloudtrail_index: Detection searches run on 5-minute scheduled intervals
    Detection_Search->>aws_cloudtrail_index: SPL query (e.g., CDET-001 root account usage)
    Detection_Search->>cdet_alerts_index: Write alert record on match

    AlertEnricher->>cdet_alerts_index: Read alert, enrich with MITRE ATT&CK + IAM context + severity
    AlertEnricher->>cdet_alerts_index: Write enriched alert back to index

    IncidentReportGenerator->>cdet_alerts_index: Fetch enriched alert
    IncidentReportGenerator->>reports: Write executive report, analyst report, and JSON bundle

    rect rgb(40, 60, 100)
        Note over NDJSON_file,CloudTrailParser: Offline / CI Validation Path (parallel)
        NDJSON_file->>CloudTrailParser: Parse raw NDJSON into structured events
        CloudTrailParser->>CloudTrailParser: Normalize fields (eventName, userIdentity, sourceIPAddress, etc.)
        CloudTrailParser->>Detection_Search: Feed ParsedEvent list to detection_validator.py
        Detection_Search->>Detection_Search: Assert should_fire == fired for each test case
        Detection_Search->>SOC_Operator: Return ValidationResult (PASS / FAIL per CDET)
    end
```

## Pipeline Stage Reference

| Stage | Key File(s) |
|-------|------------|
| AWS API event generation | AWS managed (CloudTrail S3 bucket) |
| Collection CLI entrypoint | `scripts/aws_collectors/collect_cli.py` |
| CloudTrail collector | `scripts/aws_collectors/cloudtrail_collector.py` |
| NDJSON output directory | `data/collected/` |
| Normalization / parsing | `scripts/aws_collectors/cloudtrail_parser.py` |
| Splunk ingestion config | `ingestion/` |
| Detection SPL searches | `detections/splunk/CDET-00X/` |
| Alert enrichment | `enrichment/alert_enrichment.py` |
| Incident report generator | `incident_response/incident_report_generator.py` |
| Report output | `reports/` |
| Offline validation | `validation/detection_validator.py` |
