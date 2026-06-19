---
detection_id: CDET-008
detection_name: API Enumeration Reconnaissance
tactic: Discovery
technique: T1580
last_updated: 2026-06-18
---

# CDET-008 — API Enumeration Reconnaissance: Triage

**Time budget: 5–10 minutes**
**Role: Tier-2 SOC First Responder**

---

## 1. Open the Alert and Confirm It Is Not Test Data

1. Verify the alert source index is `aws_cloudtrail` and NOT a test or staging index (e.g., `aws_cloudtrail_test`, `dev_*`).
2. Confirm the `recipientAccountId` is a production account. Cross-reference against `splunk/lookups/aws_accounts.csv`.
3. Confirm the event timestamp is within the last 24 hours. Stale replays are a common FP source.

---

## 2. Identify the Actor

Check the following CloudTrail fields in the triggering event:

| Field | What to Look For |
|---|---|
| `userIdentity.type` | `AssumedRole`, `IAMUser`, or `Root` — Root is highest urgency |
| `userIdentity.arn` | Full ARN of the caller |
| `userIdentity.principalId` | Session principal; compare against known automation |
| `userIdentity.sessionContext.sessionIssuer.arn` | Parent role if assumed; indicates human vs. CI/CD |
| `userIdentity.accessKeyId` | Key ID — look up in `splunk/lookups/known_service_accounts.csv` |
| `sourceIPAddress` | Compare against `splunk/lookups/trusted_cidr_ranges.csv` |
| `userAgent` | Automated tools (Terraform, Boto3, aws-cli) vs. recon tools (Pacu, ScoutSuite) |

---

## 3. Check for Known Pipeline Actors

1. Look up the `userIdentity.arn` in `splunk/lookups/known_service_accounts.csv`.
   - If the ARN is present AND the IP is in `splunk/lookups/trusted_cidr_ranges.csv`, this is likely a **pipeline FP**. Proceed to PASS criteria.
2. Check `userAgent` for CI/CD strings: `aws-sdk-java`, `Terraform`, `github-actions`, `codepipeline`.
   - Known pipeline agents performing Describe/List calls during deployments are expected behavior.

---

## 4. Assess Volume and Spread

Run this quick Splunk query to gauge burst scope:

```splunk
index=aws_cloudtrail eventName IN ("Describe*","List*","Get*")
    userIdentity.arn="<ARN_FROM_ALERT>"
| bucket _time span=5m
| stats count by _time, eventSource
| where count > 20
```

- **< 20 events / 5 min per service:** Low urgency — monitor.
- **20–100 events / 5 min across 1–2 services:** Medium — investigate same shift.
- **> 100 events / 5 min or spanning 3+ services:** High — escalate immediately.

---

## 5. Determine Urgency and Escalation Decision

Escalate immediately (do not wait) if ANY of the following are true:

- `userIdentity.type` is `Root`
- The ARN is NOT in `splunk/lookups/known_service_accounts.csv`
- Source IP is NOT in `splunk/lookups/trusted_cidr_ranges.csv` AND is not an AWS service IP
- `userAgent` contains known recon tool strings: `pacu`, `scoutsuite`, `cloudsplaining`, `enumerate-iam`, `weirdAAL`
- The burst spans 5 or more distinct `eventSource` values within 10 minutes
- Any `errorCode` of `AccessDenied` appears alongside the enumeration (attacker probing permissions)

---

## 6. PASS / FAIL Criteria

### PASS — Benign FP, No Further Action Required
All of the following must be true:
- ARN found in `splunk/lookups/known_service_accounts.csv`
- Source IP in `splunk/lookups/trusted_cidr_ranges.csv`
- `userAgent` matches a known pipeline or SDK pattern
- Activity is confined to expected services for that pipeline role
- No `AccessDenied` errors present
- Burst correlates with a known deployment window (check change calendar)

**Action:** Document the FP in the alert ticket. Consider adding a suppression rule (see recovery playbook).

### FAIL — Real Alert, Proceed to Investigation
Any of the escalation conditions in Step 5 are met, OR:
- The source IP resolves to a commercial VPN, Tor exit node, or foreign ASN unexpected for your org
- The ARN is a legitimate user/role but activity is outside business hours and outside normal service scope
- Multiple distinct AWS service APIs are being called in rapid succession (cross-service enumeration)

**Action:** Open an incident ticket, assign severity based on volume criteria in Step 4, and proceed to `investigation.md`.

---

## 7. Applicable Lookup CSVs

| Lookup File | Purpose |
|---|---|
| `splunk/lookups/aws_accounts.csv` | Map account IDs to environment (prod/dev/staging) |
| `splunk/lookups/known_service_accounts.csv` | Authorized automation ARNs and roles |
| `splunk/lookups/trusted_cidr_ranges.csv` | Corporate egress IPs, VPN ranges, AWS service CIDR blocks |

---

## 8. Triage Disposition

Record one of the following in the ticket before closing triage:

- `TRIAGE: FP - Pipeline Actor` — known automation, no action
- `TRIAGE: FP - Authorized Audit` — authorized security scan or assessment
- `TRIAGE: ESCALATED - Suspicious Enumeration` — proceed to investigation
- `TRIAGE: ESCALATED - Confirmed Recon Tool` — high severity, notify IR lead
