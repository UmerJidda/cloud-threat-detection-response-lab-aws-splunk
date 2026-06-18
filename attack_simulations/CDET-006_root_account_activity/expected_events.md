# CDET-006 — Expected CloudTrail Events

## Overview

Root account activity generates CloudTrail events with a distinctive `userIdentity.type = "Root"` marker. Unlike IAM user events where the `userId` is a unique AIDA-prefixed identifier, root events use the **account ID itself** as the userId.

---

## Event 1: ConsoleLogin (Root Console Access)

Generated when the root user logs into the AWS Management Console.

| Field | Value |
|-------|-------|
| `eventSource` | `signin.amazonaws.com` |
| `eventName` | `ConsoleLogin` |
| `userIdentity.type` | `Root` |
| `userIdentity.principalId` | `123456789012` (the Account ID — same as UserID for root) |
| `userIdentity.arn` | `arn:aws:iam::123456789012:root` |
| `userIdentity.accountId` | `123456789012` |
| `additionalEventData.MobileVersion` | `No` |
| `additionalEventData.MFAUsed` | `Yes` (if MFA is enrolled) or `No` |
| `responseElements.ConsoleLogin` | `Success` or `Failure` |
| `sourceIPAddress` | IP of the browser/computer used to log in |
| `userAgent` | Browser user agent string |

**Critical field**: `userIdentity.type = "Root"` — this is the primary detection trigger for ALL root events.

**MFA indicator**: `additionalEventData.MFAUsed = "No"` is an additional critical signal — a root login without MFA should trigger immediate lockout response.

---

## Event 2: GetCallerIdentity (Root API Call from CloudShell)

| Field | Value |
|-------|-------|
| `eventSource` | `sts.amazonaws.com` |
| `eventName` | `GetCallerIdentity` |
| `userIdentity.type` | `Root` |
| `userIdentity.principalId` | `123456789012` |
| `userIdentity.arn` | `arn:aws:iam::123456789012:root` |
| `sourceIPAddress` | IP of CloudShell session (AWS CloudShell IP range) |
| `userAgent` | `aws-cli/2.x` |

---

## Event 3: Any Root API Call

Any API call made while authenticated as root will have:

| Field | Value |
|-------|-------|
| `userIdentity.type` | `Root` |
| `userIdentity.arn` | `arn:aws:iam::ACCOUNT_ID:root` |
| `userIdentity.accountId` | Account ID (same as principalId) |
| `userIdentity.invokedBy` | *(absent)* — root never has an invoking service |

---

## How Root Differs from IAM User Events

| Field | Root Account | IAM User |
|-------|-------------|----------|
| `userIdentity.type` | `Root` | `IAMUser` |
| `userIdentity.userName` | *(absent)* | `alice` |
| `userIdentity.principalId` | Account ID (`123456789012`) | IAM User ID (`AIDAXXXXXXXXX`) |
| `userIdentity.arn` | `arn:aws:iam::123456789012:root` | `arn:aws:iam::123456789012:user/alice` |
| Restricted by SCPs | **No** | Yes |
| Has access keys by default | No | Optional |

---

## SPL Detection Query (CDET-006)

```spl
index=aws_cloudtrail userIdentity.type=Root
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S UTC")
| eval mfa_used=if(
    eventName="ConsoleLogin",
    coalesce(additionalEventData.MFAUsed, "Unknown"),
    "N/A (API call)"
  )
| table event_time, eventName, sourceIPAddress, awsRegion, mfa_used, userAgent
| sort -event_time
| eval severity="CRITICAL"
| eval alert_msg="Root account activity detected — requires immediate investigation"
```

### Additional query — root activity without MFA (Critical):
```spl
index=aws_cloudtrail eventName=ConsoleLogin userIdentity.type=Root
  additionalEventData.MFAUsed=No
| eval severity="CRITICAL — ROOT LOGIN WITHOUT MFA"
| table _time, sourceIPAddress, userAgent, severity
```

---

## GuardDuty Finding

If GuardDuty is enabled, root account activity may also trigger:

| Finding Type | Severity | Description |
|-------------|----------|-------------|
| `Policy:IAMUser/RootCredentialUsage` | Medium (7.0) | Root account credentials used to access AWS |

GuardDuty's `RootCredentialUsage` finding fires independently of CloudTrail delivery latency, providing faster alerting in some configurations.

---

## CloudWatch Alarm Integration

The recommended detection stack for root activity:

```
CloudTrail → CloudWatch Logs → Metric Filter (userIdentity.type=Root) → CloudWatch Alarm → SNS → PagerDuty/Slack
```

This path has a typical latency of **60-120 seconds** from API call to alert — significantly faster than waiting for S3-based CloudTrail delivery.

**Metric filter pattern** (exact match for root, excluding AWS service events):
```
{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
```
