---
detection_id: CDET-003
detection_name: CloudTrail Logging Disabled
tactic: Defense Evasion
technique: T1562.008
last_updated: 2026-06-18
---

# CDET-003 — CloudTrail Logging Disabled: Triage

**Time budget: 5–10 minutes**

This checklist determines whether the CDET-003 alert is a genuine defense-evasion event requiring immediate escalation, or a benign/FP event that can be closed or downgraded.

---

## 1. Locate and Open the Alert

1. Open the Splunk alert or SIEM ticket for CDET-003.
2. Confirm the raw event contains one of the triggering API calls:
   - `StopLogging`
   - `DeleteTrail`
3. If neither event name is present, flag as **misfire** and close.

---

## 2. Extract Key Fields from the Alert

Record the following fields before proceeding — you will need them in every subsequent step:

| Field | Where to Find It | Expected Values |
|---|---|---|
| `eventName` | CloudTrail event | `StopLogging` or `DeleteTrail` |
| `eventTime` | CloudTrail event | ISO-8601 timestamp |
| `userIdentity.arn` | CloudTrail event | Full principal ARN |
| `userIdentity.type` | CloudTrail event | `IAMUser`, `AssumedRole`, `Root` |
| `userIdentity.sessionContext.sessionIssuer.arn` | CloudTrail event | Role ARN if AssumedRole |
| `requestParameters.name` | CloudTrail event | Trail name or ARN being stopped/deleted |
| `sourceIPAddress` | CloudTrail event | IP or AWS service name |
| `userAgent` | CloudTrail event | CLI, console, SDK string |
| `awsRegion` | CloudTrail event | Region of the API call |
| `recipientAccountId` | CloudTrail event | AWS account ID |

---

## 3. Check Lookup CSVs for Known-Good Actors

Run these Splunk lookups to determine whether the actor is in an approved list. A match does **not** automatically make it benign — verify intent below.

**Approved IAM principals:**
```spl
| inputlookup approved_iam_principals.csv
| where principal_arn="<userIdentity.arn from alert>"
```
File: `splunk/lookups/approved_iam_principals.csv`

**Automation roles (CI/CD pipelines, Terraform, etc.):**
```spl
| inputlookup automation_role_arns.csv
| where role_arn="<sessionIssuer.arn from alert>"
```
File: `splunk/lookups/automation_role_arns.csv`

**Approved AWS accounts:**
```spl
| inputlookup approved_aws_accounts.csv
| where account_id="<recipientAccountId from alert>"
```
File: `splunk/lookups/approved_aws_accounts.csv`

**CloudTrail log buckets (for DeleteTrail cross-check):**
```spl
| inputlookup cloudtrail_log_buckets.csv
```
File: `splunk/lookups/cloudtrail_log_buckets.csv`

---

## 4. Validate the Alert Is Real (Not Test Data or Pipeline)

Answer each question. A "No" answer for questions 4a–4c pushes toward **real alert**.

**4a. Is this a known automation/pipeline actor?**
- Check `automation_role_arns.csv` for the role ARN.
- Verify the action was expected (e.g., Terraform plan/destroy during approved change window).
- Check for an associated change-management ticket (ServiceNow, Jira, etc.) covering this time window.

**4b. Is the source IP consistent with your corporate CIDR or approved automation?**
- Compare `sourceIPAddress` against `splunk/lookups/approved_cidr_ranges.csv`.
- If IP is a raw internet address (non-AWS, non-office), treat as suspicious.
- If `sourceIPAddress` is `AWS Internal` for an `AssumedRole`, check the session issuer.

**4c. Was this during a scheduled maintenance window?**
- Check your change management calendar.
- Legitimate trail disablement during scheduled DR tests should be pre-approved and documented.

**4d. Is the targeted trail the organization's primary/multi-region trail?**
```bash
aws cloudtrail describe-trails --include-shadow-trails \
  --query "trailList[?Name=='<trail-name>']"
```
- If `IsMultiRegionTrail: true` and `HomeRegion` is your primary region, this is higher severity.
- If it is an isolated single-region test trail, still treat seriously but note the reduced blast radius.

**4e. Does the principal have a history of legitimate CloudTrail management?**
```spl
index=aws_cloudtrail eventSource="cloudtrail.amazonaws.com"
  userIdentity.arn="<principal ARN>"
  eventName IN ("StopLogging","DeleteTrail","CreateTrail","StartLogging")
| table _time, eventName, requestParameters.name, sourceIPAddress
| sort -_time
```

---

## 5. Determine Urgency

Use the matrix below to set initial severity and decide whether to escalate immediately.

| Condition | Severity | Action |
|---|---|---|
| `DeleteTrail` on primary multi-region trail | **CRITICAL** | Escalate immediately to Tier-3 / IR lead |
| `StopLogging` on primary trail, unknown actor | **CRITICAL** | Escalate immediately |
| `StopLogging` by known automation, no change ticket | **HIGH** | Escalate to team lead within 15 min |
| `StopLogging` by known automation, valid change ticket | **LOW** | Document and close as FP |
| Any action by `Root` account | **CRITICAL** | Escalate immediately, invoke IR process |
| `sourceIPAddress` is external/unknown IP | **CRITICAL** | Escalate immediately |

---

## 6. PASS / FAIL Criteria

### PASS — Treat as Benign FP (close or downgrade)
- Actor found in `automation_role_arns.csv` **AND** a valid change ticket exists covering this exact time window **AND** the action matches documented pipeline behavior.
- Trail was a non-production, single-region test trail with no attached S3 bucket delivering to critical logging infrastructure.

### FAIL — Treat as Real Alert (proceed to investigation)
- Actor is not in any approved lookup.
- Actor is in an approved lookup but no change ticket exists.
- `eventName` is `DeleteTrail`.
- `sourceIPAddress` is external or unexpected.
- Principal type is `Root`.
- More than one trail was affected in the same time window.
- Any concurrent suspicious events (e.g., `ConsoleLogin`, `GetSessionToken`, enumeration APIs) from the same principal within ±30 minutes.

---

## 7. Triage Decision

- **FAIL (real alert):** Open a P1/P2 incident, assign to Tier-2 analyst, proceed to `investigation.md`.
- **PASS (benign FP):** Document the justification, attach the change ticket reference, close the alert. Consider adding the actor to an allowlist suppression if recurrent.
- **Unclear:** Escalate to Tier-3 or IR lead and proceed to `investigation.md` in parallel.
