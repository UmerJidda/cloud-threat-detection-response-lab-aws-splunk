---
detection_id: CDET-006
detection_name: Root Account Activity Detected
tactic: Initial Access
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-006 — Root Account Activity Detected: Triage

> **Target completion time:** 5–10 minutes from alert receipt.
> **Audience:** Tier-2 SOC analyst with AWS experience.

---

## 1. Acknowledge and Timestamp

1. Acknowledge the alert in your SIEM/ticketing system immediately.
2. Record the exact time you began triage (UTC).
3. Note the alert source (Splunk, GuardDuty, AWS Config, etc.) and correlation rule version.

---

## 2. Validate the Alert Is Real (Not Test Data or Pipeline Noise)

| Check | How | Expected for real alert |
|---|---|---|
| Account ID | Check `recipientAccountId` in CloudTrail | Matches a production account (not sandbox/test) |
| Event source | Check `userIdentity.type` | Must equal `Root` |
| Event time | Check `eventTime` | Falls outside of known maintenance windows |
| Source IP | Check `sourceIPAddress` | Not an AWS-internal service IP (e.g., not `AWS Internal`) |
| MFA used | Check `additionalEventData.MFAUsed` | `No` raises severity; `Yes` still warrants investigation |
| User agent | Check `userAgent` | Unusual agent (e.g., raw `aws-cli`, `curl`, `python-requests`) is more suspicious than AWS Console |

**Test-data indicators to rule out:**

- `recipientAccountId` is a known dev/test account listed in `splunk/lookups/aws_account_inventory.csv`.
- `sourceIPAddress` is a known automation or scanning IP in `splunk/lookups/trusted_ips.csv`.
- Event time aligns with a scheduled task in `splunk/lookups/maintenance_windows.csv`.

If any test-data indicator matches, document and close as **Benign FP**. Otherwise proceed.

---

## 3. Key Fields to Check in the Alert and CloudTrail

Pull the raw CloudTrail event. Focus on:

```
userIdentity.type          = "Root"
userIdentity.accountId     = <account ID>
eventName                  = <action taken — e.g., ConsoleLogin, CreateAccessKey, PutUserPolicy>
eventSource                = <iam.amazonaws.com | sts.amazonaws.com | signin.amazonaws.com>
sourceIPAddress            = <caller IP>
userAgent                  = <client string>
awsRegion                  = <region>
errorCode                  = (absent = success; present = failed attempt)
additionalEventData.MFAUsed
requestParameters          = <what was requested>
responseElements           = <what was returned — contains new key IDs, etc.>
```

Cross-reference the source IP against:
- `splunk/lookups/trusted_ips.csv` — known safe IPs (corporate egress, automation).
- `splunk/lookups/aws_account_inventory.csv` — account classification (prod/dev/sandbox).

---

## 4. Determine Urgency

| Condition | Urgency | Action |
|---|---|---|
| `ConsoleLogin` by Root with no MFA from unknown IP | **Critical** | Escalate immediately; page on-call |
| `CreateAccessKey` for Root | **Critical** | Escalate immediately; initiate containment |
| `PutUserPolicy` / `AttachUserPolicy` by Root | **High** | Escalate within 15 min |
| Root used for read-only describe/list calls from known IP | **Medium** | Investigate; likely operational error |
| Root API call from CI/CD pipeline IP (in trusted_ips.csv) | **Low** | Verify pipeline change; document |

---

## 5. Initial Splunk Query (Run Immediately)

```spl
index=aws_cloudtrail userIdentity.type=Root
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table event_time, recipientAccountId, eventSource, eventName, sourceIPAddress,
         userAgent, awsRegion, errorCode, additionalEventData.MFAUsed
| sort -_time
| head 20
```

Scope to the last 24 hours. If more than one event appears, note whether they share an IP and user agent (session) or differ (multiple access points — higher severity).

---

## 6. PASS / FAIL Criteria

### PASS — Treat as Benign FP

All of the following must be true:
- Source IP is in `splunk/lookups/trusted_ips.csv` **and** labeled as an automation/pipeline actor.
- Event falls within an approved maintenance window in `splunk/lookups/maintenance_windows.csv`.
- Event is a read-only action (e.g., `GetAccountSummary`, `ListBuckets`).
- MFA was used.
- No subsequent privilege-escalation or key-creation events follow.

Document findings, close ticket as FP, and file a tuning request to suppress known-good pipeline Root calls.

### FAIL — Treat as Real Alert

Any one of the following is sufficient:
- Root login from an IP not in `splunk/lookups/trusted_ips.csv`.
- No MFA on console login.
- `CreateAccessKey` or any credential-creation event.
- Policy attachment, role creation, or permission boundary removal.
- Multiple events across different regions in a short window.
- Source IP geolocates to an unexpected country.

Escalate immediately per the criteria in Section 4 and proceed to `investigation.md`.

---

## 7. Escalation Contacts

Populate these per your organization's runbook:

| Role | When to Page |
|---|---|
| Security Lead / IR Manager | Critical urgency (see table above) |
| AWS Account Owner | Any confirmed Root usage in production |
| CISO | Active breach suspected or credentials confirmed compromised |

---

## 8. Lookup CSVs Referenced (CDET-006)

| File | Purpose |
|---|---|
| `splunk/lookups/trusted_ips.csv` | Known-safe IPs; used to qualify source IP |
| `splunk/lookups/aws_account_inventory.csv` | Account classification (prod/dev/sandbox) |
| `splunk/lookups/maintenance_windows.csv` | Scheduled maintenance periods |
