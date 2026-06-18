# CDET-003 — Expected CloudTrail Events

## Overview

This simulation can generate different events depending on which variant is executed. All events originate from `cloudtrail.amazonaws.com`. Critically, all events appear in CloudTrail **before** logging actually stops — the trail records its own disabling.

---

## Variant 1: StopLogging

### Primary Event: StopLogging

| Field | Value |
|-------|-------|
| `eventSource` | `cloudtrail.amazonaws.com` |
| `eventName` | `StopLogging` |
| `requestParameters.name` | Trail name (e.g., `management-events`) or trail ARN |
| `userIdentity.type` | `IAMUser` or `AssumedRole` |
| `userIdentity.arn` | ARN of the principal who stopped logging |
| `sourceIPAddress` | IP address of the attacker |
| `userAgent` | `aws-cli/2.x` or SDK user agent |
| `awsRegion` | Region where the trail's home region is |
| `errorCode` | *(absent on success)* |

**Critical note**: After this event is written, the trail stops recording. Any API calls made after this point will NOT appear in CloudTrail until `StartLogging` is called.

**SPL Detection Field Mapping:**
- Primary trigger: `eventName = "StopLogging"`
- Identity: `userIdentity.arn` — who disabled logging
- Target: `requestParameters.name` — which trail was stopped

---

## Variant 2: UpdateTrail Degradation

### Event 2A: PutEventSelectors

| Field | Value |
|-------|-------|
| `eventSource` | `cloudtrail.amazonaws.com` |
| `eventName` | `PutEventSelectors` |
| `requestParameters.trailName` | Trail name |
| `requestParameters.eventSelectors` | JSON array — look for `"IncludeManagementEvents": false` |
| `userIdentity.arn` | Attacker's ARN |

**SPL Detection Field Mapping:**
- Trigger: `eventName = "PutEventSelectors"` AND `requestParameters.eventSelectors` contains `IncludeManagementEvents: false`
- This is the stealthiest variant — many orgs alert on `StopLogging` but not `PutEventSelectors`

### Event 2B: UpdateTrail

| Field | Value |
|-------|-------|
| `eventSource` | `cloudtrail.amazonaws.com` |
| `eventName` | `UpdateTrail` |
| `requestParameters.name` | Trail name |
| `requestParameters.includeGlobalServiceEvents` | `false` (when disabling) |
| `requestParameters.isMultiRegionTrail` | May change to `false` if single-region downgrade |
| `requestParameters.s3BucketName` | May change if attacker redirects logs |
| `userIdentity.arn` | Attacker's ARN |

**SPL Detection Field Mapping:**
- Trigger: `eventName = "UpdateTrail"` with `requestParameters.includeGlobalServiceEvents = false`
- High false positive potential — legitimate UpdateTrail changes (CloudFormation, Terraform) look similar
- Enrich with: is the change from `true` → `false` (degradation) vs `false` → `true` (improvement)?

---

## Variant 3: DeleteTrail

### Primary Event: DeleteTrail

| Field | Value |
|-------|-------|
| `eventSource` | `cloudtrail.amazonaws.com` |
| `eventName` | `DeleteTrail` |
| `requestParameters.name` | Trail name being deleted |
| `userIdentity.arn` | Attacker's ARN |
| `sourceIPAddress` | Attacker's IP |

**This is the last CloudTrail event for this trail.** All subsequent events are unlogged until a new trail is created.

---

## Cleanup Events

| `eventName` | Triggered By |
|-------------|-------------|
| `StartLogging` | Variant 1 cleanup |
| `PutEventSelectors` | Variant 2 cleanup (restores management events) |
| `UpdateTrail` | Variant 2 cleanup (restores global service events) |
| `CreateTrail` + `StartLogging` | Variant 3 recovery |

---

## Event Correlation and Detection SPL

### High-Confidence: StopLogging / DeleteTrail
```spl
index=aws_cloudtrail eventSource="cloudtrail.amazonaws.com"
  eventName IN ("StopLogging", "DeleteTrail")
| table _time, eventName, userIdentity.arn, requestParameters.name, sourceIPAddress
| eval severity="CRITICAL"
```

### Medium-Confidence: UpdateTrail Degradation
```spl
index=aws_cloudtrail eventSource="cloudtrail.amazonaws.com"
  eventName IN ("UpdateTrail", "PutEventSelectors")
| spath input=requestParameters output=params
| where (eventName="UpdateTrail" AND (
    like(params, "%\"includeGlobalServiceEvents\":false%") OR
    like(params, "%\"isMultiRegionTrail\":false%")
  ))
  OR
  (eventName="PutEventSelectors" AND
    like(params, "%\"IncludeManagementEvents\":false%")
  )
| table _time, eventName, userIdentity.arn, params, sourceIPAddress
| eval severity="HIGH"
```

---

## Detection Window Analysis

| Variant | Time to Alert (CloudTrail→S3) | Time to Alert (CloudTrail→CloudWatch Logs) |
|---------|------------------------------|-------------------------------------------|
| `StopLogging` | 5-15 min | 1-2 min |
| `UpdateTrail` | 5-15 min | 1-2 min |
| `DeleteTrail` | 5-15 min | 1-2 min |

**Key insight**: After `StopLogging` or `DeleteTrail`, subsequent adversary actions are NOT logged. The response SLA must be within the detection window to catch the attack in progress.
