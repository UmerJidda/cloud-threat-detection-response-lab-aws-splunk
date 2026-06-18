# CDET-006 — Root Account API or Console Activity

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-006 |
| **Severity** | Critical |
| **Confidence** | High |
| **Tactic** | Initial Access |
| **Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 5 minutes |

## Detection Logic

The AWS root account has unrestricted access to all resources and services in the account and cannot be constrained by IAM policies. AWS security best practices require that the root account have MFA enabled, no active access keys, and that it is used only for specific root-only operations that cannot be performed by any IAM principal.

This detection alerts on **any** root account activity. There is no suppression — by design. Any root activity should be acknowledged by a security engineer within 15 minutes. The `root_action_category` field provides context to help the analyst quickly categorize whether the activity is likely legitimate (e.g., changing support plan once per year) or suspicious (e.g., creating access keys, disabling CloudTrail).

## Example Alert Output

```
detection_id        : CDET-006
alert_title         : [CDET-006] Root Account Activity Detected
severity            : critical
eventName           : ConsoleLogin
root_action_category: Root console login — interactive console access
login_result        : Success
mfa_used            : true
event_source_ip     : 203.0.113.5
region              : us-east-1
```

## Investigation Guidance

1. Verify with account owner: was there a legitimate reason for root usage?
2. Check the source IP — does it match a known admin location?
3. If `mfa_used=false`, treat as high-priority compromise
4. If `eventName=CreateAccessKey`, assume compromise — root keys should not exist
5. Review all subsequent actions in the same session (same source IP, within 30 minutes)

## Containment Guidance

If unauthorized root access is confirmed:
1. Immediately change the root account password
2. Delete any root account access keys created during the session
3. Review root account MFA device — if compromised, the MFA device itself must be replaced
4. Contact AWS Support if root account password cannot be changed (account lockout)
