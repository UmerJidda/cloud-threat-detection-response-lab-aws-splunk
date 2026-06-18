# Splunk Field Mapping

## Overview

This document defines how fields from the normalized collector output map to Splunk fields, CIM (Common Information Model) fields, and the detection output schema. Consistent field naming is essential for lookups, cross-source correlation, and dashboard construction.

---

## CloudTrail Field Mapping

The `CloudTrailEvent` dataclass fields map to Splunk fields as follows. The normalized NDJSON output from the collector is ingested directly — Splunk field names match the dataclass field names.

| Collector Field (schema.py) | Splunk Field Name | CIM Field | Description |
|----------------------------|-------------------|-----------|-------------|
| `event_id` | `event_id` | — | CloudTrail event UUID |
| `event_time` | `_time` (primary) / `event_time` | — | ISO 8601 event timestamp |
| `event_name` | `eventName` | `action` | API operation name |
| `event_source` | `eventSource` | — | AWS service endpoint |
| `aws_region` | `awsRegion` | — | AWS region |
| `source_ip_address` | `sourceIPAddress` | `src` / `src_ip` | Requesting IP address |
| `user_agent` | `userAgent` | — | AWS SDK / CLI identifier |
| `user_identity_type` | `userIdentity.type` | `user_type` | IAMUser / AssumedRole / Root / etc. |
| `user_identity_arn` | `userIdentity.arn` | `user` | Full ARN of acting principal |
| `user_identity_account_id` | `userIdentity.accountId` | — | Account ID of acting principal |
| `assumed_role_arn` | `userIdentity.sessionContext.sessionIssuer.arn` | — | Source role for AssumedRole sessions |
| `error_code` | `errorCode` | — | AWS error code (AccessDenied, etc.) |
| `error_message` | `errorMessage` | — | Human-readable error detail |
| `request_parameters` | `requestParameters.*` | — | API call input parameters (expanded) |
| `response_elements` | `responseElements.*` | — | API call output elements (expanded) |

### CIM: Authentication Data Model

For `ConsoleLogin` events, the following CIM Authentication fields apply:

| Splunk Field | CIM Field | Example Value |
|-------------|-----------|--------------|
| `userIdentity.arn` | `user` | `arn:aws:iam::123456789012:user/alice` |
| `sourceIPAddress` | `src` | `203.0.113.5` |
| `awsRegion` | `dest` | `us-east-1` |
| `additionalEventData.MFAUsed` | `app` | `Yes` / `No` |
| `eventName` | `action` | `ConsoleLogin` |

### CIM: Change Analysis Data Model

For IAM-mutating events, the following CIM Change fields apply:

| Splunk Field | CIM Field | Example Value |
|-------------|-----------|--------------|
| `eventName` | `action` | `CreateUser` |
| `userIdentity.arn` | `user` | `arn:aws:iam::123456789012:role/AdminRole` |
| `requestParameters.userName` | `object` | `mallory` |
| `eventSource` | `app` | `iam.amazonaws.com` |
| `awsRegion` | `dest` | `us-east-1` |

---

## IAM Field Mapping

| Collector Field | Splunk Field Name | Description |
|----------------|-------------------|-------------|
| `user_id` | `user_id` | IAM UserId (AIDAXXXXXXXX format) |
| `user_name` | `user_name` | IAM username |
| `arn` | `arn` | Full user ARN |
| `created` | `created` | User creation timestamp |
| `password_last_used` | `password_last_used` | Last console login |
| `mfa_active` | `mfa_active` | true / false |
| `access_keys[].access_key_id` | `access_key_id` | AKIA* key ID |
| `access_keys[].status` | `key_status` | Active / Inactive |
| `access_keys[].created` | `key_created` | Key creation timestamp |
| `access_keys[].last_used` | `key_last_used` | Last API call timestamp |
| `access_keys[].last_used_region` | `key_last_used_region` | Region of last use |
| `attached_policies` | `attached_policies` | List of managed policy ARNs |
| `inline_policy_names` | `inline_policy_names` | List of inline policy names |

---

## GuardDuty Field Mapping

| Collector Field | Splunk Field Name | Description |
|----------------|-------------------|-------------|
| `finding_id` | `finding_id` | GuardDuty finding UUID |
| `title` | `title` | Human-readable finding title |
| `severity` | `severity_score` | Numeric severity (1–10) |
| `severity_label` | `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `finding_type` | `finding_type` | GuardDuty finding type string |
| `region` | `awsRegion` | AWS region where finding was generated |
| `aws_account_id` | `aws_account_id` | Account ID |
| `created` | `_time` (primary) / `finding_created` | First observed timestamp |
| `resource_type` | `resource_type` | Instance / AccessKey / S3Bucket |
| `resource_id` | `resource_id` | Instance ID, access key ID, bucket name |
| `action_type` | `action_type` | NETWORK_CONNECTION / PORT_PROBE / etc. |
| `remote_ip_address` | `src_ip` | Attacker source IP |
| `remote_country_code` | `src_country` | Two-letter country code |

---

## Security Hub Field Mapping

| Collector Field | Splunk Field Name | Description |
|----------------|-------------------|-------------|
| `finding_id` | `finding_id` | Security Hub finding ARN |
| `title` | `title` | Finding title |
| `severity` | `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `severity_score` | `severity_score` | Normalized 0–100 score |
| `compliance_status` | `compliance_status` | PASSED / FAILED / NOT_AVAILABLE |
| `workflow_status` | `workflow_status` | NEW / NOTIFIED / RESOLVED / SUPPRESSED |
| `product_name` | `product_name` | Inspector / Config / SecurityHub / etc. |
| `resource_type` | `resource_type` | AwsIamUser / AwsEc2Instance / etc. |
| `resource_id` | `resource_id` | ARN or ID of affected resource |
| `aws_account_id` | `aws_account_id` | Account ID |
| `region` | `awsRegion` | Region where finding was generated |

---

## Security Group Field Mapping

| Collector Field | Splunk Field Name | Description |
|----------------|-------------------|-------------|
| `group_id` | `group_id` | Security group ID (sg-XXXXXXXX) |
| `group_name` | `group_name` | Security group name |
| `vpc_id` | `vpc_id` | VPC ID |
| `direction` | `direction` | ingress / egress |
| `protocol` | `protocol` | tcp / udp / icmp / -1 (all) |
| `from_port` | `from_port` | Start of port range |
| `to_port` | `to_port` | End of port range |
| `cidr_ranges` | `cidr_ranges` | List of IPv4 CIDR ranges |
| `publicly_exposed` | `publicly_exposed` | true if 0.0.0.0/0 present |

---

## Detection Output Field Standards

All detection SPL searches must produce these fields in their final `| table` output. This enables the Splunk Enterprise Security Notable Event framework and downstream dashboards to work without custom field extraction.

| Field | Type | Source | Example |
|-------|------|--------|---------|
| `_time` | timestamp | CloudTrail `event_time` | `2024-01-15T10:30:00Z` |
| `detection_id` | string | `eval` in SPL | `CDET-003` |
| `severity` | string | `eval` in SPL | `critical` |
| `tactic` | string | `eval` in SPL | `Defense Evasion` |
| `technique` | string | `eval` in SPL | `T1562.008` |
| `technique_name` | string | `eval` in SPL | `Impair Defenses: Disable Cloud Logs` |
| `eventName` | string | CloudTrail | `StopLogging` |
| `principal_arn` | string | `eval coalesce(...)` | `arn:aws:iam::123456789012:user/alice` |
| `event_source_ip` | string | CloudTrail `sourceIPAddress` | `203.0.113.5` |
| `region` | string | CloudTrail `awsRegion` | `us-east-1` |

---

## Field Aliasing in props.conf

Splunk field aliasing maps the collector's snake_case output fields to the CIM-standard field names expected by ES data models:

```ini
[aws:cloudtrail:normalized]
FIELDALIAS-src = sourceIPAddress AS src
FIELDALIAS-user = userIdentity.arn AS user
FIELDALIAS-action = eventName AS action
FIELDALIAS-dest = awsRegion AS dest

[aws:guardduty:finding]
FIELDALIAS-src = remote_ip_address AS src_ip
FIELDALIAS-severity_label = severity_label AS severity
```
