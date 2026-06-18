# CDET-003 — CloudTrail Logging Disabled or Trail Deleted

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-003 |
| **Severity** | Critical |
| **Confidence** | High |
| **Tactic** | Defense Evasion |
| **Technique** | T1562.008 — Impair Defenses: Disable Cloud Logs |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 5 minutes |

## Detection Logic

CloudTrail is the primary audit source for all AWS management-plane activity. An adversary who disables or deletes CloudTrail eliminates visibility into all subsequent actions. This detection targets the narrow window between the disabling event and loss of logging — the disabling event itself is always logged.

Three event types are monitored:

- **`StopLogging`** — halts log delivery without deleting the trail configuration
- **`DeleteTrail`** — permanently removes the trail
- **`UpdateTrail`** — fires only when the update specifically reduces logging scope (disabling log file validation, reverting from multi-region to single-region, or excluding global service events)

This detection runs every 5 minutes with a 10-minute lookback. The schedule overlap is intentional: if a detection run is delayed, the event still falls within the lookback of the next run.

## Example Events

**Positive (should alert — critical):**
```json
{
  "event_name": "StopLogging",
  "event_source": "cloudtrail.amazonaws.com",
  "event_time": "2024-01-15T04:11:09Z",
  "user_identity_type": "IAMUser",
  "user_identity_arn": "arn:aws:iam::123456789012:user/attacker",
  "error_code": null,
  "request_parameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events"}
}
```

## Example Alert Output

```
detection_id  : CDET-003
alert_title   : [CDET-003] CloudTrail Logging Disabled or Trail Deleted
severity      : critical
urgency       : 1
eventName     : StopLogging
trail_name    : management-events
disable_reason: CloudTrail logging stopped — all API activity logging halted
principal_arn : arn:aws:iam::123456789012:user/attacker
region        : us-east-1
```

## Investigation Guidance

1. **Re-enable logging immediately** — before any other action, restore CloudTrail logging to prevent further blind spots.
2. **Check who called the API** — the `principal_arn` field. Cross-reference with recent login events (CDET-006) and access key usage.
3. **Identify the time window** — determine when logging was stopped and when it was re-enabled. All activity in that window is unobserved from a CloudTrail perspective.
4. **Query GuardDuty** — GuardDuty uses its own log source and may have findings covering the blind window.
5. **Check all regions** — adversaries often disable logging in each region sequentially. Run a cross-region query.

## Containment Guidance

1. Re-enable the trail: `aws cloudtrail start-logging --name <trail-name>`
2. Revoke credentials of the disabling principal
3. Review all IAM policies that grant `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail` and tighten them
