# SPL Guidelines

## Overview

This document defines SPL (Search Processing Language) standards for detection searches. Following these guidelines ensures detections are efficient, maintainable, and produce consistent output fields for downstream processing.

---

## Index and Sourcetype References

**Always use macros for index references.** Never hardcode index names in detection files.

```spl
`aws_cloudtrail_index`           ← correct
index=aws_cloudtrail             ← do not use in detection files
```

This allows the index strategy to change (e.g., environment suffix for dev/prod) without modifying detection files.

### Available Macros

| Macro | Purpose |
|-------|---------|
| `` `aws_cloudtrail_index` `` | CloudTrail management events |
| `` `aws_security_index` `` | IAM and security group data |
| `` `aws_alerts_index` `` | GuardDuty and Security Hub findings |
| `` `aws_vpc_flow_index` `` | VPC Flow Log data |
| `` `iam_event` `` | Shorthand filter for IAM API source |
| `` `cloudtrail_event(X)` `` | Filter to a specific event name |
| `` `root_activity` `` | Filter to root account events |
| `` `timeframe_15m` `` | Standard 15-minute window (`earliest=-15m`) |
| `` `timeframe_1h` `` | Standard 1-hour window (`earliest=-1h`) |
| `` `timeframe_24h` `` | Standard 24-hour window (`earliest=-24h`) |

---

## Search Structure

### Standard Detection Template

```spl
`aws_cloudtrail_index`
[ optional: timerange macro ]
[ primary event filter — indexed fields first ]
[ secondary filters — eval/where ]
| eval
    principal_arn=coalesce('userIdentity.arn', "unknown"),
    event_source_ip='sourceIPAddress',
    region='awsRegion'
[ optional: lookup for enrichment or suppression ]
[ optional: stats for threshold-based detections ]
| where [ final filter condition ]
| eval
    severity="high",
    tactic="Persistence",
    technique="T1136.003",
    technique_name="Create Account: Cloud Account",
    detection_id="CDET-001"
| table _time, detection_id, severity, tactic, technique,
         eventName, principal_arn, event_source_ip, region
```

### Search Efficiency Rules

1. **Index fields first.** The following fields are indexed in Splunk and should be used as early filters:
   - `index`, `sourcetype`, `source`, `host`
   - `eventName` (extracted as indexed field via transforms)
   - `userIdentity.type`

2. **Avoid leading wildcards.** `eventName=*User*` triggers a full scan. Use `eventName=CreateUser OR eventName=DeleteUser` instead.

3. **`where` before `eval`.** Apply filtering conditions before computing new fields.

4. **`stats` scope.** When using `stats`, ensure the `by` clause fields are present in all events — use `coalesce()` on nullable fields.

5. **Avoid `search` within subsearches.** Use `lookup` or `inputlookup` for set membership tests.

---

## Lookups in Detection Logic

Use lookup tables for suppression and enrichment. Lookups are defined in `splunk/lookups/`.

### Suppression Pattern

```spl
`aws_cloudtrail_index`
eventName=CreateUser
| eval principal_arn=coalesce('userIdentity.arn', "unknown")
| lookup approved_iam_principals arn AS principal_arn OUTPUT approved
| where isnull(approved) OR approved!="true"
```

### Enrichment Pattern

```spl
`aws_cloudtrail_index`
eventName=AssumeRole
| eval source_ip='sourceIPAddress'
| lookup ip_geolocation ip AS source_ip OUTPUT country_code, country_name, is_vpn
| where country_code!="US" OR is_vpn="true"
```

---

## Threshold-Based Detections

For detections that trigger on volume (e.g., API enumeration), use a `stats` + `where` pattern:

```spl
`aws_cloudtrail_index`
earliest=-1h
eventName IN ("ListUsers", "ListRoles", "ListPolicies", "GetUser",
              "DescribeInstances", "ListBuckets", "ListFunctions")
| eval principal_arn=coalesce('userIdentity.arn', "unknown")
| stats
    count AS total_calls,
    dc(eventName) AS unique_api_calls,
    values(eventName) AS api_calls
    BY principal_arn, awsRegion
| where total_calls >= 50 AND unique_api_calls >= 5
| eval severity="medium", tactic="Discovery", technique="T1580"
| table principal_arn, awsRegion, total_calls, unique_api_calls, api_calls, severity, tactic, technique
```

### Threshold Tuning

Document threshold rationale in `detection.yaml` under `false_positive_notes`. Thresholds should be reviewed after 30 days of production data.

---

## Multi-Event Correlation

For detections that require sequencing across multiple events, use a transaction or subsearch pattern:

### Transaction Pattern (sequence detection)

```spl
`aws_cloudtrail_index`
earliest=-1h
eventName IN ("ConsoleLogin", "CreateUser", "AttachUserPolicy", "CreateAccessKey")
| eval principal_arn=coalesce('userIdentity.arn', "unknown")
| transaction principal_arn maxspan=30m
| where eventcount >= 3
    AND match(eventName, "AttachUserPolicy")
    AND match(eventName, "CreateAccessKey")
| eval severity="critical", tactic="Persistence", technique="T1098.001"
```

### Subsearch Pattern (cross-source correlation)

```spl
`aws_cloudtrail_index`
eventName=AssumeRole
[ search `aws_alerts_index`
  sourcetype="aws:guardduty:finding"
  | eval src_ip='service.action.networkConnectionAction.remoteIpDetails.ipAddressV4'
  | return 100 src_ip ]
| eval severity="high"
```

---

## Output Field Standards

Every detection search must produce these fields in the final `| table` command:

| Field | Type | Description |
|-------|------|-------------|
| `_time` | timestamp | Event time |
| `detection_id` | string | CDET-NNN |
| `severity` | string | critical / high / medium / low |
| `tactic` | string | MITRE ATT&CK tactic name |
| `technique` | string | MITRE ATT&CK technique ID |
| `technique_name` | string | MITRE ATT&CK technique name |
| `eventName` | string | CloudTrail API call |
| `principal_arn` | string | Full ARN of acting principal |
| `event_source_ip` | string | Source IP address |
| `region` | string | AWS region |

Additional fields relevant to the specific detection should be appended after these required fields.

---

## Search Scheduling

Detection searches run on a schedule defined in `detection.yaml`. Guidelines:

| Severity | Recommended Schedule | Maximum Lookback |
|----------|---------------------|-----------------|
| Critical | `*/5 * * * *` (every 5 min) | `-10m` |
| High | `*/15 * * * *` (every 15 min) | `-30m` |
| Medium | `0 * * * *` (hourly) | `-2h` |
| Low | `0 */4 * * *` (every 4 hours) | `-8h` |

Overlapping search windows by 2x the schedule interval prevents missed events during delayed ingestion.

---

## SPL Anti-Patterns

Avoid these patterns in detection files:

| Anti-Pattern | Problem | Preferred Alternative |
|-------------|---------|----------------------|
| `index=* eventName=CreateUser` | Searches all indexes | Use `` `aws_cloudtrail_index` `` macro |
| Hardcoded ARNs in SPL | Breaks across environments | Use lookup table |
| `| head 1000` | Silently truncates results | Use time-bounded searches |
| `| eval ip=src_ip` without `coalesce` | Null values cause silent failures | `coalesce('src_ip', "unknown")` |
| Chained `| search` commands | Inefficient | Apply filters via `where` early |
| `NOT` with wildcards | Expensive scan | Use `lookup` with NOT IN logic |
