# Validation Schema Reference

**Version:** 1.0.0
**Date:** 2026-06-18
**Project:** Cloud Threat Detection & Response Lab
**Scope:** All validation artifacts produced or consumed by the detection engineering program

---

## Table of Contents

1. [Test Case Schema](#1-test-case-schema)
   - 1.1 [expected_alert.json Field Definitions](#11-expected_alertjson-field-definitions)
   - 1.2 [JSON Schema for expected_alert.json](#12-json-schema-for-expected_alertjson)
   - 1.3 [positive_case.md Required Sections](#13-positive_casemd-required-sections)
   - 1.4 [negative_case.md Required Sections](#14-negative_casemd-required-sections)
   - 1.5 [edge_case.md Required Sections](#15-edge_casemd-required-sections)
   - 1.6 [checklist.md Required Sections](#16-checklistmd-required-sections)
2. [Validation Result Schema](#2-validation-result-schema)
   - 2.1 [Top-Level Run Output](#21-top-level-run-output)
   - 2.2 [Per-Detection Result Fields](#22-per-detection-result-fields)
   - 2.3 [Per-Test-Case Result Fields](#23-per-test-case-result-fields)
   - 2.4 [Field Assertion Result Structure](#24-field-assertion-result-structure)
3. [Sample Data Schema](#3-sample-data-schema)
   - 3.1 [Mandatory CloudTrail Fields](#31-mandatory-cloudtrail-fields)
   - 3.2 [_test_label Convention](#32-_test_label-convention)
   - 3.3 [Directory and Naming Conventions](#33-directory-and-naming-conventions)
4. [Alert Schema](#4-alert-schema)
   - 4.1 [Universal Alert Fields](#41-universal-alert-fields)
   - 4.2 [Detection-Specific Event Fields](#42-detection-specific-event-fields)
   - 4.3 [Field Nullability Rules](#43-field-nullability-rules)

---

## 1. Test Case Schema

Each detection MUST have a corresponding directory under `validation/test_cases/` named using the pattern:

```
CDET-NNN_<snake_case_detection_name>/
```

Example: `CDET-001_iam_user_created_outside_pipeline/`

Every test case directory MUST contain exactly these five files:

| File | Required | Purpose |
|---|---|---|
| `expected_alert.json` | Yes | Machine-readable alert field specification consumed by `validator.py` |
| `positive_case.md` | Yes | Human-readable description of the true-positive test scenario |
| `negative_case.md` | Yes | Human-readable description of the suppression/benign test scenario |
| `edge_case.md` | Yes | Human-readable description of boundary and known-gap scenarios |
| `checklist.md` | Yes | Pre-deployment and sign-off gate checklist |

---

### 1.1 expected_alert.json Field Definitions

`expected_alert.json` is a flat JSON object. It represents the exact field set that must appear in the alert row produced by the Splunk `| table` clause for the detection. The validator reads this file and constructs `FieldAssertion` objects for every key.

#### Universal Fields (required in every expected_alert.json)

| Field | Type | Allowed Values / Pattern | Notes |
|---|---|---|---|
| `detection_id` | string | `CDET-[0-9]{3}` | Must match the directory prefix exactly |
| `alert_title` | string | `[CDET-NNN] <Human Title>` | Displayed in Splunk Notable Events |
| `severity` | string | `critical`, `high`, `medium`, `low`, `informational` | Maps to Splunk ES urgency |
| `urgency` | integer | `1` (critical), `2` (high), `3` (medium), `4` (low), `5` (informational) | Numeric companion to severity; used for SLA routing |
| `confidence` | string | `high`, `medium`, `low` | Analyst confidence level in the detection logic |
| `tactic` | string | Any MITRE ATT&CK tactic name (e.g., `Persistence`, `Defense Evasion`) | Full tactic name, not ID |
| `technique` | string | MITRE technique ID (e.g., `T1136.003`, `T1562.008`) | Include sub-technique dot notation when applicable |
| `technique_name` | string | Full MITRE technique name (e.g., `Create Account: Cloud Account`) | Colon-separated for sub-techniques |
| `eventName` | string | AWS API call name (e.g., `CreateUser`, `StopLogging`) | Must match the raw CloudTrail `eventName` value |
| `event_source_ip` | string | IPv4 address or AWS service token | Derived from CloudTrail `sourceIPAddress` |
| `region` | string | AWS region code (e.g., `us-east-1`) | Derived from CloudTrail `awsRegion` |
| `_time` | string | ISO 8601 UTC timestamp (e.g., `2024-01-15T14:32:15Z`) | Splunk internal time field; used for sample event timestamp reference only |

#### Severity-to-Urgency Mapping

| severity value | urgency value | SLA target |
|---|---|---|
| `critical` | `1` | 15 minutes |
| `high` | `2` | 1 hour |
| `medium` | `3` | 4 hours |
| `low` | `4` | 24 hours |
| `informational` | `5` | Best effort |

#### Identity and Session Fields (required for most detections)

| Field | Type | Nullable | Notes |
|---|---|---|---|
| `principal_type` | string | No | CloudTrail `userIdentity.type`: `IAMUser`, `AssumedRole`, `Root`, `AWSService`, `AWSAccount`, `FederatedUser` |
| `mfa_used` | string | No | `Yes` or `No`; derived from `additionalEventData.MFAUsed` or session context |
| `session_issuer_arn` | string | Yes | Null when `principal_type` is `IAMUser` or `Root`; populated for `AssumedRole` from `userIdentity.sessionContext.sessionIssuer.arn` |

#### Field Value Semantics

- Fields with a non-null, non-empty value in `expected_alert.json` cause the validator to assert both existence and value equality.
- Fields with a `null` value in `expected_alert.json` cause the validator to assert existence only (the field must be present; its value may be null or empty).
- Fields absent from `expected_alert.json` are not validated by the automated runner but may be checked in manual Splunk verification.

---

### 1.2 JSON Schema for expected_alert.json

The following JSON Schema (Draft 2020-12) governs every `expected_alert.json` file. Additional detection-specific properties are permitted via `additionalProperties: true`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://cloudthreatdetectionlab/schemas/expected_alert/v1.0.0",
  "title": "ExpectedAlert",
  "description": "Defines the alert fields that a detection must produce. Consumed by validation/validator.py.",
  "type": "object",
  "required": [
    "detection_id",
    "alert_title",
    "severity",
    "urgency",
    "confidence",
    "tactic",
    "technique",
    "technique_name",
    "eventName",
    "event_source_ip",
    "region",
    "_time"
  ],
  "additionalProperties": true,
  "properties": {
    "detection_id": {
      "type": "string",
      "pattern": "^CDET-[0-9]{3}$",
      "description": "Unique detection identifier. Must match the test case directory prefix."
    },
    "alert_title": {
      "type": "string",
      "pattern": "^\\[CDET-[0-9]{3}\\] .+$",
      "description": "Human-readable alert title displayed in Splunk ES."
    },
    "severity": {
      "type": "string",
      "enum": ["critical", "high", "medium", "low", "informational"],
      "description": "Analyst-assigned severity level."
    },
    "urgency": {
      "type": "integer",
      "enum": [1, 2, 3, 4, 5],
      "description": "Numeric urgency: 1=critical, 2=high, 3=medium, 4=low, 5=informational."
    },
    "confidence": {
      "type": "string",
      "enum": ["high", "medium", "low"],
      "description": "Confidence in the detection logic producing true positives."
    },
    "tactic": {
      "type": "string",
      "minLength": 1,
      "description": "MITRE ATT&CK tactic name (full name, not ID)."
    },
    "technique": {
      "type": "string",
      "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$",
      "description": "MITRE ATT&CK technique ID, optionally including sub-technique."
    },
    "technique_name": {
      "type": "string",
      "minLength": 1,
      "description": "Full MITRE technique name; use colon-separated form for sub-techniques."
    },
    "eventName": {
      "type": "string",
      "minLength": 1,
      "description": "AWS API call name that triggers or is associated with this detection."
    },
    "event_source_ip": {
      "type": ["string", "null"],
      "description": "Source IP address from CloudTrail sourceIPAddress. Null when called by an AWS service."
    },
    "region": {
      "type": "string",
      "pattern": "^[a-z]{2}-[a-z]+-[0-9]$",
      "description": "AWS region code (e.g., us-east-1, eu-west-2)."
    },
    "_time": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
      "description": "ISO 8601 UTC reference timestamp. Taken from eventTime of the triggering event."
    },
    "principal_type": {
      "type": "string",
      "enum": ["IAMUser", "AssumedRole", "Root", "AWSService", "AWSAccount", "FederatedUser"],
      "description": "CloudTrail userIdentity.type of the acting principal."
    },
    "mfa_used": {
      "type": ["string", "null"],
      "enum": ["Yes", "No", null],
      "description": "Whether MFA was used in the session."
    },
    "session_issuer_arn": {
      "type": ["string", "null"],
      "description": "ARN of the role that issued the session. Null for IAMUser and Root principal types."
    }
  }
}
```

---

### 1.3 positive_case.md Required Sections

`positive_case.md` documents the scenario under which the detection MUST fire. The automated runner references the `expected_alert.json` for field assertions; this file provides the human-readable rationale.

#### Required Sections and Content Rules

**Header line:** `# CDET-NNN — Positive Test Case`

**`## Test Input`**
- Path to the sample NDJSON file (relative to project root).
- Target Splunk index (always `aws_cloudtrail` unless the detection uses GuardDuty data).
- Sourcetype (always `aws:cloudtrail` or `aws:guardduty`).

**`## Trigger Conditions`**
- Bulleted list of every field condition that causes the detection to fire.
- Must include `eventName` value(s).
- Must include any lookup exclusion logic that is NOT applied (i.e., why this event bypasses suppression).
- Use raw CloudTrail field names (e.g., `userIdentity.arn`, `requestParameters.userName`).

**`## Sample Event Fields`**
- Fenced JSON block containing the minimum viable triggering event fields.
- Must be a valid JSON object.
- Must include at minimum: `eventName`, `userIdentity` (with `type` and `arn`), `sourceIPAddress`, `awsRegion`, `eventTime`.

**`## Expected Result`**
- `Detection fires: YES`
- `Expected severity:` matching `expected_alert.json`.
- `Expected urgency:` matching `expected_alert.json`.
- `Expected ATT&CK fields populated:` listing tactic and technique.

**`## Pass Criteria`**
- Bulleted list of individually verifiable assertions.
- Each criterion must be binary (pass or fail, no ambiguity).
- Must include: alert generation within one schedule period, `alert_title` value, each identity field derivation, each detection-specific field, and all fields listed in `expected_alert.json`.
- Null fields must be explicitly called out with their expected null/empty condition.

---

### 1.4 negative_case.md Required Sections

`negative_case.md` documents every suppression scenario under which the detection MUST NOT fire.

#### Required Sections and Content Rules

**Header line:** `# CDET-NNN — Negative Test Case`

**`## Test Input`**
- Path to the benign/suppressed sample NDJSON file.
- Target Splunk index and sourcetype.

**`## Suppression Conditions`**
- One subsection (`### Scenario A`, `### Scenario B`, ...) per distinct suppression path.
- Each subsection must identify:
  - Which lookup table provides suppression (`approved_iam_principals`, `automation_role_arns`, etc.).
  - The field used as the join key (e.g., `creator_arn`, `session_issuer_arn`).
  - The specific value present in the lookup that causes suppression.

**`## Expected Result`**
- `Detection fires: NO`
- `Splunk search returns 0 results for the suppressed events`

**`## Pass Criteria`**
- Bulleted list of individually verifiable steps.
- Must include: loading all scenario events, running the SPL manually, confirming zero alerts, verifying the lookup join field, and confirming all suppression lookup tables are evaluated.

---

### 1.5 edge_case.md Required Sections

`edge_case.md` documents boundary conditions, known detection gaps, and scenarios where the detection behavior may be surprising or incomplete.

#### Required Sections and Content Rules

**Header line:** `# CDET-NNN — Edge Case`

**Opening paragraph (`**Purpose:**`)**
- One sentence describing what boundary condition this file covers.

**One or more named scenarios (`## Scenario: <Name>`)**
Each scenario must contain:

- `### Background` (or equivalent prose): explanation of why this scenario is at the boundary.
- Event detail block or bulleted field list showing the specific field values that define the edge.
- `### Expected Result`:
  - `Detection fires: YES` or `Detection fires: NO`.
  - If the detection does NOT fire on a potentially malicious event, label it explicitly: `This is a documented detection gap`.
  - If a gap exists, include a recommendation for a complementary detection or lookup enhancement.

**`## Pass Criteria`**
- Bulleted list of binary assertions.
- Must include: loading each scenario's events, confirming detection fires or does not fire, and documenting any gap in `data/validation_results/`.

---

### 1.6 checklist.md Required Sections

`checklist.md` is the gate that an engineer must complete before a detection is promoted from Testing to Active. All items use GitHub-flavored Markdown task list syntax (`- [ ]`).

#### Required Sections and Items

**`## Pre-Deployment Checks`**
Must include at minimum:
- `detection.yaml` completeness and required field presence.
- SPL syntax verification (no parse errors in Splunk Search).
- All referenced macros exist in `macros.conf`.
- All referenced lookup tables exist with correct column names.
- Schedule and lookback window set appropriately.

**`## Positive Test (must fire)`**
Must include at minimum:
- Positive case sample data loaded into Splunk test index.
- Detection fires within one schedule period.
- All `expected_alert.json` fields present in alert output.
- Each detection-specific field (identity fields, requestParameters-derived fields) individually verified.
- Severity and urgency values match `expected_alert.json`.
- ATT&CK fields populated (tactic and technique).

**`## Negative Test (must NOT fire)`**
Must include at minimum:
- Negative case sample data loaded.
- One checkbox per suppression scenario from `negative_case.md`.
- Confirmation that the lookup join field matched correctly.
- All suppression lookup tables evaluated.

**`## Edge Case Test`**
Must include at minimum:
- Edge case sample data loaded.
- One checkbox per scenario from `edge_case.md`.
- Any documented detection gap explicitly noted.
- Cross-reference to any complementary detection recommended in `edge_case.md`.

**`## False Positive Baseline`**
Must include at minimum:
- Detection run against a minimum of 14 days of production CloudTrail data.
- FP count and rate documented (target: less than 5% FP rate).
- Suppression lookups updated based on FP analysis.
- Positive test re-run after lookup updates to confirm detection is not broken.

**`## Sign-off`**
Must include at minimum:
- Detection reviewed by a second engineer.
- All test cases documented in `data/validation_results/`.
- `coverage_matrix.md` updated to Testing status.
- `detection_catalog.md` updated.

---

## 2. Validation Result Schema

The output of `python -m validation.validator` is a JSON file written to `data/validation_results/validation_run_<YYYYMMDDTHHMMSS>.json`. The schema below describes every field in that file.

---

### 2.1 Top-Level Run Output

```json
{
  "run_id": "a1b2c3d4",
  "run_timestamp": "2026-06-18T14:00:00.000000",
  "detections_tested": 14,
  "detections_passed": 12,
  "detections_failed": 2,
  "detections_skipped": 0,
  "coverage_percent": 85.7,
  "results": [ ... ]
}
```

| Field | Type | Description |
|---|---|---|
| `run_id` | string | First 8 characters of a UUID v4 generated at run start. Unique per invocation. |
| `run_timestamp` | string | UTC ISO 8601 datetime at which the run started. Produced by `datetime.utcnow().isoformat()`. |
| `detections_tested` | integer | Count of distinct detection IDs evaluated in this run. |
| `detections_passed` | integer | Count of detections where all executed test cases passed. |
| `detections_failed` | integer | Count of detections where one or more test cases failed. |
| `detections_skipped` | integer | Count of detections skipped due to missing sample files or other non-error conditions. Always 0 in the current runner; reserved for future use. |
| `coverage_percent` | float | `detections_passed / detections_tested * 100`, rounded to one decimal place. |
| `results` | array | Array of `DetectionValidationSummary` objects, one per detection ID. See Section 2.2. |

---

### 2.2 Per-Detection Result Fields

Each entry in the `results` array is a `DetectionValidationSummary`:

```json
{
  "detection_id": "CDET-001",
  "positive_result": { ... },
  "negative_result": { ... },
  "edge_result": null
}
```

| Field | Type | Nullable | Description |
|---|---|---|---|
| `detection_id` | string | No | Detection identifier (e.g., `CDET-001`). |
| `positive_result` | object | Yes | `ValidationResult` for the positive test case. Null if no positive test case was defined or run. |
| `negative_result` | object | Yes | `ValidationResult` for the negative (suppression) test case. Null if not defined or run. |
| `edge_result` | object | Yes | `ValidationResult` for the edge case. Null if not defined or run. Frequently null in the automated runner because edge cases are evaluated manually in Splunk. |

**Derived promotion readiness** (computed, not stored in JSON):
A detection is considered ready for promotion when `positive_result.result == "PASS"` AND `negative_result.result == "PASS"`. Edge result does not block promotion but is noted in the report.

---

### 2.3 Per-Test-Case Result Fields

Each `ValidationResult` object (the value of `positive_result`, `negative_result`, or `edge_result`):

```json
{
  "detection_id": "CDET-001",
  "test_case_type": "positive",
  "test_name": "CDET-001 — positive case",
  "result": "PASS",
  "alert_count": 3,
  "field_results": [ ... ],
  "errors": [],
  "notes": ""
}
```

| Field | Type | Allowed Values | Description |
|---|---|---|---|
| `detection_id` | string | `CDET-[0-9]{3}` | Detection identifier for this result row. |
| `test_case_type` | string | `positive`, `negative`, `edge` | Which category of test case this result belongs to. |
| `test_name` | string | Free text | Human-readable test name, typically `<detection_id> — <type> case`. |
| `result` | string | `PASS`, `FAIL`, `SKIP`, `ERROR` | Overall outcome of this test case. See result semantics below. |
| `alert_count` | integer | >= 0 | Number of mock alerts returned by the heuristic detection runner for the loaded sample events. |
| `field_results` | array | | Array of `FieldResult` objects. Populated only for positive test cases where `should_fire=true`. See Section 2.4. |
| `errors` | array | | Array of strings describing each failure reason. Empty array on PASS. |
| `notes` | string | Free text | Optional human-added annotation. Defaults to empty string. |

#### Result Semantics

| Value | Meaning |
|---|---|
| `PASS` | All assertions passed. For positive cases: detection fired and all field assertions succeeded. For negative cases: no alerts were generated. |
| `FAIL` | One or more assertions failed. `errors` array will be non-empty with specific failure reasons. |
| `SKIP` | Sample file not found and test case type is `positive`. The test could not be evaluated. This is a data-gap condition, not a detection failure. |
| `ERROR` | An unexpected exception occurred during evaluation. `errors` array contains the traceback summary. Should be treated as a pipeline problem, not a detection failure. |

---

### 2.4 Field Assertion Result Structure

Each entry in `field_results` is a `FieldResult`:

```json
{
  "field_name": "severity",
  "passed": true,
  "reason": "ok"
}
```

| Field | Type | Description |
|---|---|---|
| `field_name` | string | The name of the alert output field that was asserted (e.g., `severity`, `creator_arn`). |
| `passed` | boolean | `true` if the assertion succeeded; `false` if it failed. |
| `reason` | string | `"ok"` on success. On failure, a human-readable explanation such as `"Field 'severity': expected='high', got='medium'"` or `"Missing required field: creator_arn"`. |

#### Assertion Logic Summary

The `FieldAssertion` object (defined in `validation/schema.py`) evaluates in this order:

1. If `must_exist=true` and the field is absent from the alert: FAIL with `"Missing required field: <name>"`.
2. If `must_be_nonempty=true` and the field value is falsy: FAIL with `"Field '<name>' is empty"`.
3. If `expected_value` is set and the field value does not equal it: FAIL with a value-mismatch message.
4. If `expected_type` is set and the value's Python type does not match: FAIL with a type-mismatch message.
5. Otherwise: PASS with reason `"ok"`.

---

## 3. Sample Data Schema

Sample data files are NDJSON (newline-delimited JSON). Each line is a single, self-contained CloudTrail event object. Files must be UTF-8 encoded with Unix line endings.

---

### 3.1 Mandatory CloudTrail Fields

Every event in a sample NDJSON file MUST include the following fields. The validator and Splunk parsing both depend on them.

| Field | Type | Example | Notes |
|---|---|---|---|
| `eventVersion` | string | `"1.08"` | Always `"1.08"` for modern CloudTrail. |
| `eventTime` | string | `"2024-01-15T14:32:15Z"` | ISO 8601 UTC. Used as `_time` in Splunk. |
| `eventSource` | string | `"iam.amazonaws.com"` | AWS service endpoint that generated the event. |
| `eventName` | string | `"CreateUser"` | The API action name. |
| `eventType` | string | `"AwsApiCall"` | Typically `AwsApiCall`; also `AwsConsoleSignIn`, `AwsServiceEvent`. |
| `awsRegion` | string | `"us-east-1"` | The region where the API call was made. |
| `sourceIPAddress` | string | `"198.51.100.77"` | Caller's IP or AWS service token (e.g., `"sts.amazonaws.com"`). |
| `userAgent` | string | `"aws-cli/2.13.0..."` | User agent string; used for behavioral profiling. |
| `requestID` | string | UUID format | Unique per API call. |
| `eventID` | string | UUID format | Unique event identifier for deduplication. |
| `readOnly` | boolean | `false` | Whether the API call is read-only. Used by CDET-008 enumeration logic. |
| `managementEvent` | boolean | `true` | Whether this is a management (control plane) event. |
| `recipientAccountId` | string | `"123456789012"` | The AWS account ID that received the event. |
| `userIdentity` | object | See below | Must always be present; sub-fields vary by principal type. |

#### userIdentity Sub-Fields

| Field | Type | Required When | Notes |
|---|---|---|---|
| `userIdentity.type` | string | Always | One of: `IAMUser`, `AssumedRole`, `Root`, `AWSService`, `AWSAccount`, `FederatedUser` |
| `userIdentity.arn` | string | Always except Root console logins | Full ARN of the acting principal. |
| `userIdentity.accountId` | string | Always | 12-digit AWS account number. |
| `userIdentity.principalId` | string | Always | Internal AWS principal identifier. |
| `userIdentity.accessKeyId` | string | When API call made with access key | `AKIA...` for long-term; `ASIA...` for temporary credentials. |
| `userIdentity.userName` | string | When `type=IAMUser` | IAM username. |
| `userIdentity.sessionContext` | object | When `type=AssumedRole` | Must contain `sessionIssuer` and optionally `attributes`. |
| `userIdentity.sessionContext.sessionIssuer.arn` | string | When `type=AssumedRole` | ARN of the role whose policy applies to the session. Used for suppression lookup matching. |
| `userIdentity.sessionContext.sessionIssuer.type` | string | When `type=AssumedRole` | `"Role"` or `"EC2Instance"` (the latter for instance profile sessions). |
| `userIdentity.sessionContext.attributes.mfaAuthenticated` | string | When console session | `"true"` or `"false"`. |

#### Optional But Recommended Fields

| Field | Notes |
|---|---|
| `requestParameters` | Required for detections that inspect API parameters (user creation, policy attachment, security group rules, S3 configuration). Include as a nested object matching the AWS API documentation. |
| `responseElements` | Required for detections that verify the created resource ARN (e.g., `new_user_arn` in CDET-001). |
| `additionalEventData` | Required for console login events (`MFAUsed` field). |
| `errorCode` | Include in negative case and edge case events where the API call failed (e.g., `"AccessDenied"`). Events with `errorCode` set are excluded from detection evaluation. |
| `errorMessage` | Companion to `errorCode`. |

---

### 3.2 _test_label Convention

Every event in a sample NDJSON file SHOULD include a `_test_label` field to identify its purpose. This field is stripped before Splunk ingestion but is used by test tooling and during manual review.

```json
{
  "_test_label": "CDET-001-positive-attacker-creates-user",
  ...other fields...
}
```

#### _test_label Format

```
<detection_id>-<scenario>-<brief_description>
```

| Component | Rules | Examples |
|---|---|---|
| `<detection_id>` | Lowercase with hyphen (e.g., `cdet-001`) | `cdet-001`, `cdet-013` |
| `<scenario>` | One of: `positive`, `negative`, `edge` | `positive`, `negative`, `edge` |
| `<brief_description>` | Lowercase hyphen-separated slug, max 40 chars | `attacker-creates-user`, `pipeline-suppressed`, `approved-role-unusual-region` |

#### _test_label Usage Rules

- Files in `malicious/` must use `positive` scenario in `_test_label`.
- Files in `benign/` must use `negative` scenario in `_test_label`.
- Files in `edge_cases/` must use `edge` scenario in `_test_label`.
- A single NDJSON file may contain multiple events with different `_test_label` values when a scenario requires a sequence of events (e.g., CDET-008 enumeration burst).

---

### 3.3 Directory and Naming Conventions

Sample log files live under `sample_logs/cloudtrail/` and `sample_logs/guardduty/`. The directory layout enforces scenario segregation.

```
sample_logs/
├── cloudtrail/
│   ├── malicious/          — True-positive events (must trigger detection)
│   ├── benign/             — True-negative events (must NOT trigger detection)
│   └── edge_cases/         — Boundary condition events
└── guardduty/
    ├── malicious/
    ├── benign/
    └── edge_cases/
```

#### File Naming Convention

**Malicious files** (one file per detection):
```
CDET-NNN_<snake_case_detection_name>.ndjson
```
Example: `CDET-001_iam_user_created_outside_pipeline.ndjson`

**Benign files** (shared or per-detection):
- Shared benign baselines follow: `normal_<service>_activity.ndjson`
  - `normal_iam_activity.ndjson`
  - `normal_ec2_activity.ndjson`
  - `normal_s3_activity.ndjson`
  - `normal_sts_activity.ndjson`
- Per-detection suppression files follow: `CDET-NNN_<scenario_description>.ndjson`
  - Example: `CDET-001_pipeline_createuser.ndjson`

**Edge case files** (one file per detection edge):
```
CDET-NNN_edge_<brief_description>.ndjson
```
Example: `CDET-001_edge_approved_role_unusual_region.ndjson`

#### File Content Rules

| Rule | Description |
|---|---|
| One event per line | Each line must be a complete, valid JSON object. Blank lines are ignored. |
| UTF-8 encoding | No BOM. Unix line endings (`\n`). |
| Realistic but non-production data | Use RFC 5737 IP addresses (`198.51.100.0/24`, `203.0.113.0/24`) for attacker IPs. Use `123456789012` as the victim account. Use `234567890123` as a secondary/external account. |
| No real credentials | All access key IDs must use the pattern `AKIAEXAMPLE...` or `ASIAEXAMPLE...`. |
| Temporal ordering | Events within a file should be in ascending `eventTime` order. |
| Minimum event count | Malicious files must contain at least one event that triggers the detection. Benign files must contain at least one event per suppression scenario defined in `negative_case.md`. |

---

## 4. Alert Schema

The alert schema describes the normalized output that every detection must produce. In Splunk ES, this corresponds to the fields produced by the `| table` clause in each detection's SPL search.

---

### 4.1 Universal Alert Fields

Every detection alert, regardless of the specific MITRE technique, must include all of the following fields.

| Field | Type | Nullable | Source | Description |
|---|---|---|---|---|
| `detection_id` | string | No | Static in SPL | Pattern: `CDET-NNN`. The unique identifier for this detection rule. |
| `alert_title` | string | No | Static in SPL | Pattern: `[CDET-NNN] <Human Title>`. Appears in Splunk Notable Events. |
| `severity` | string | No | Static in SPL | Enum: `critical`, `high`, `medium`, `low`, `informational`. |
| `urgency` | integer | No | Static in SPL | Enum: `1`, `2`, `3`, `4`, `5`. Numeric companion to severity. |
| `confidence` | string | No | Static in SPL | Enum: `high`, `medium`, `low`. |
| `tactic` | string | No | Static in SPL | Full MITRE ATT&CK tactic name. |
| `technique` | string | No | Static in SPL | MITRE technique ID including sub-technique if applicable. |
| `technique_name` | string | No | Static in SPL | Full MITRE technique name. |
| `principal_arn` | string | No | `userIdentity.arn` | ARN of the principal that performed the action. |
| `principal_type` | string | No | `userIdentity.type` | CloudTrail identity type of the acting principal. |
| `mfa_used` | string | No | Session context | `Yes` or `No`. |
| `session_issuer_arn` | string | Yes | `userIdentity.sessionContext.sessionIssuer.arn` | Null for `IAMUser` and `Root` types. |
| `event_source_ip` | string | Yes | `sourceIPAddress` | Source IP address. May be null or an AWS service token string for service-initiated calls. |
| `region` | string | No | `awsRegion` | AWS region of the event. |
| `eventName` | string | No | `eventName` | The AWS API action that triggered the detection. |
| `_time` | string | No | `eventTime` | Splunk event time, derived from CloudTrail `eventTime`. |

---

### 4.2 Detection-Specific Event Fields

In addition to the universal fields above, each detection produces fields specific to the underlying event. The following table enumerates all detection-specific fields across the current detection catalog.

| Detection | Field | Type | Nullable | Description |
|---|---|---|---|---|
| CDET-001 | `creator_arn` | string | No | ARN of the principal that created the IAM user. Alias for `principal_arn` in alert context. |
| CDET-001 | `new_user_name` | string | No | `requestParameters.userName` of the created IAM user. |
| CDET-001 | `new_user_arn` | string | Yes | `responseElements.user.arn` of the created IAM user. Null if responseElements are suppressed. |
| CDET-002 | `key_owner_name` | string | No | `requestParameters.userName` — the user for whom the access key was created. |
| CDET-002 | `creator_name` | string | No | `userIdentity.userName` of the principal that created the key. |
| CDET-002 | `is_cross_user` | string | No | `"true"` when the key was created for a user other than the creator; `"false"` otherwise. |
| CDET-003 | `trail_name` | string | Yes | Name of the affected CloudTrail trail. Derived from `requestParameters.name` or `requestParameters.trailName`. |
| CDET-003 | `disable_reason` | string | No | Human-readable description: `"Trail stopLogging"`, `"Trail deleteTrail"`, or `"Trail coverage degraded via UpdateTrail"`. |
| CDET-004 | `policy_arn` | string | Yes | `requestParameters.policyArn` for managed policy attachments. Null for inline policy events. |
| CDET-004 | `target_entity` | string | No | The user or role ARN to which the policy was attached or in which the inline policy was created. |
| CDET-004 | `is_wildcard_inline` | string | No | `"true"` if the policy document contains a wildcard (`"*"`) resource or action; `"false"` for managed policy attachments. |
| CDET-005 | `role_name` | string | No | Name of the role whose trust policy was created or modified. |
| CDET-005 | `external_account_id` | string | No | The first external (non-approved) AWS account ID found in the trust policy document. |
| CDET-005 | `trust_policy_document` | string | Yes | URL-encoded or stringified trust policy. May be truncated in Splunk output for large policies. |
| CDET-006 | `root_action_category` | string | No | `"console_login"` for `ConsoleLogin` events; `"api_call"` for all other root actions. |
| CDET-007 | `session_issuer_arn` | string | No | ARN of the EC2 instance profile role. Overrides the universal nullable definition for this detection — must be populated. |
| CDET-007 | `detection_source` | string | No | `"cloudtrail"` when detected via CloudTrail IP anomaly; `"guardduty"` when detected via GuardDuty finding. |
| CDET-008 | `total_calls` | integer | No | Total number of read-only API calls by the principal in the lookback window. |
| CDET-008 | `unique_api_calls` | integer | No | Count of distinct `eventName` values called by the principal. |
| CDET-009 | `source_bucket` | string | No | `requestParameters.bucketName` — the S3 bucket configured for replication. |
| CDET-009 | `destination_account_id` | string | No | The external AWS account ID extracted from the replication configuration's destination bucket ARN. |
| CDET-010 | `total_delete_events` | integer | No | Count of `DeleteObject`, `DeleteObjects`, and `DeleteBucket` events by the principal. |
| CDET-010 | `estimated_objects_deleted` | integer | No | Estimated total object count: `DeleteObjects` counts as 100, `DeleteBucket` as 1000, `DeleteObject` as 1. |
| CDET-010 | `buckets_targeted` | integer | No | Number of distinct S3 bucket names targeted in the deletion sequence. |
| CDET-010 | `bucket_names_str` | string | No | Comma-separated list of targeted bucket names. |
| CDET-011 | `instance_type` | string | No | EC2 instance type launched (e.g., `p4d.24xlarge`). |
| CDET-011 | `instance_count` | integer | No | Number of instances requested (`requestParameters.maxCount`). |
| CDET-012 | `target_account_id` | string | No | The AWS account ID of the role being assumed. |
| CDET-012 | `target_role_arn` | string | No | Full ARN of the role being assumed (`requestParameters.roleArn`). |
| CDET-012 | `is_chained_assumption` | string | No | `"true"` if the caller is already an `AssumedRole` session (chain assumption); `"false"` otherwise. |
| CDET-013 | `group_id` | string | No | `requestParameters.groupId` — the security group being modified. |
| CDET-013 | `cidr_range` | string | No | The offending CIDR block (e.g., `0.0.0.0/0` or `::/0`). |
| CDET-014 | `bucket_name` | string | No | Name of the S3 bucket from which CloudTrail logs were deleted. |
| CDET-014 | `deletion_type` | string | No | `"Batch or single CloudTrail log deletion"` for object-level deletes; `"CRITICAL: Entire CloudTrail log bucket deleted"` for bucket deletion. |

---

### 4.3 Field Nullability Rules

The following rules govern when fields may be null or absent in a produced alert:

1. **Fields marked `Nullable: No`** in the universal table must always be present and non-empty. A field assertion failure for these fields causes the test case to FAIL.

2. **`session_issuer_arn`** is nullable in the universal schema but is treated as non-nullable for CDET-007, where the session issuer ARN of the EC2 instance profile is the primary evidence field.

3. **`event_source_ip`** may contain an AWS service hostname (e.g., `"sts.amazonaws.com"`) rather than a routable IP address when the API call originates from another AWS service. This is valid and must not be treated as a missing value.

4. **`requestParameters`-derived fields** (e.g., `new_user_name`, `key_owner_name`, `bucket_name`) will be empty string rather than null when the raw CloudTrail event omits `requestParameters` (which occurs for some read-only events and for some service events). Detections should handle this gracefully with `coalesce` or `if(isnull(...), "", ...)` in SPL.

5. **`_time`** is always present in Splunk output. In `expected_alert.json` it serves as a reference timestamp for the sample event and is not asserted against during automated field validation (it is listed in the `skip_keys` set in `validator.py`).

6. **Detection-specific fields** not listed in `expected_alert.json` are not validated by the automated runner. If an analyst adds new output fields to a detection's SPL `| table` clause, `expected_alert.json` must be updated to include them before the validator can assert their correctness.

---

## Appendix A — Field Source Reference

| Alert Field | CloudTrail JSON Path |
|---|---|
| `principal_arn` | `userIdentity.arn` |
| `principal_type` | `userIdentity.type` |
| `mfa_used` | `userIdentity.sessionContext.attributes.mfaAuthenticated` or `additionalEventData.MFAUsed` |
| `session_issuer_arn` | `userIdentity.sessionContext.sessionIssuer.arn` |
| `event_source_ip` | `sourceIPAddress` |
| `region` | `awsRegion` |
| `eventName` | `eventName` |
| `_time` | `eventTime` |

---

## Appendix B — Validation Run Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | All tested detections passed all executed test cases. |
| `1` | One or more detections failed one or more test cases. |

The runner does not distinguish between a SKIP and a FAIL at the process exit code level. Skipped detections are surfaced only in the JSON report.

---

## Appendix C — Adding a New Detection to the Validation Program

1. Create `validation/test_cases/CDET-NNN_<name>/` with all five required files.
2. Write `expected_alert.json` with all fields produced by the detection's `| table` clause.
3. Write `positive_case.md`, `negative_case.md`, `edge_case.md`, and `checklist.md` following the section requirements in this document.
4. Add a malicious sample NDJSON to `sample_logs/cloudtrail/malicious/CDET-NNN_<name>.ndjson`.
5. Add suppression scenario events to `sample_logs/cloudtrail/benign/CDET-NNN_<scenario>.ndjson`.
6. Add edge case events to `sample_logs/cloudtrail/edge_cases/CDET-NNN_edge_<description>.ndjson`.
7. Add detection-specific heuristic logic to `validator.py` under `_run_heuristic_detection()`.
8. Run `python -m validation.validator --detection CDET-NNN` and confirm PASS.
9. Load sample data into Splunk and run the SPL detection manually.
10. Complete `checklist.md` and update `coverage_matrix.md` to Testing status.
