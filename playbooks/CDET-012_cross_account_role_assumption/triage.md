---
detection_id: CDET-012
detection_name: Cross-Account Role Assumption
tactic: Lateral Movement
technique: T1550.001
last_updated: 2026-06-18
---

# CDET-012 — Triage Playbook
**Cross-Account Role Assumption**

> **Target completion time:** 5–10 minutes
> **Audience:** Tier-2 SOC Analyst
> **Escalate if:** you cannot rule out attacker-controlled cross-account access within the first 5 minutes.

---

## 1. Pull the Raw Alert

Open the triggering Splunk alert and record every field below before pivoting anywhere else:

| Field | Where to find it | What to record |
|---|---|---|
| `userIdentity.arn` | CloudTrail event | Principal making the `AssumeRole` call |
| `userIdentity.accountId` | CloudTrail event | Source AWS account ID |
| `userIdentity.type` | CloudTrail event | IAMUser / AssumedRole / Root / FederatedUser |
| `requestParameters.roleArn` | CloudTrail event | Target role ARN (cross-account destination) |
| `requestParameters.roleSessionName` | CloudTrail event | Session name chosen by caller — attacker-chosen names are often random strings |
| `responseElements.assumedRoleUser.arn` | CloudTrail event | Full ARN of the resulting session |
| `sourceIPAddress` | CloudTrail event | IP address of caller |
| `userAgent` | CloudTrail event | Tool / SDK used |
| `eventTime` | CloudTrail event | UTC timestamp |
| `awsRegion` | CloudTrail event | Region where STS call was received |
| `errorCode` | CloudTrail event | Absent on success; `AccessDenied` on failed attempts |
| `recipientAccountId` | CloudTrail event | Account that owns the target role |

---

## 2. Validate the Alert Is Real

### 2a. Confirm this is not test or synthetic data

1. Check `userIdentity.accountId` and `recipientAccountId` against `splunk/lookups/approved_aws_accounts.csv`.
   - If both accounts are labeled `lab` or `test`, mark **FP — test data** and close.
2. Look for synthetic-event markers: `sourceIPAddress` matching known test-harness ranges in `splunk/lookups/approved_cidr_ranges.csv`, or a `roleSessionName` with prefix `synthetic_` or `lab_`.

### 2b. Confirm the caller is not a known automation or pipeline identity

1. Look up `userIdentity.arn` in **`splunk/lookups/automation_role_arns.csv`**.
   - If listed AND `requestParameters.roleArn` matches an expected cross-account destination documented in the same file, mark **FP — known pipeline** and close.
   - If listed but the target `roleArn` is unexpected, treat as **suspicious** and continue.
2. Look up `requestParameters.roleArn` in **`splunk/lookups/approved_iam_principals.csv`** to check whether the target role is a known, sanctioned cross-account role.

### 2c. Verify the target account relationship

1. Check `recipientAccountId` against `splunk/lookups/approved_aws_accounts.csv`.
   - If the destination account is **not** in the approved list, the assumption is immediately suspicious — treat as **high-priority real alert**.
2. Cross-reference both the source and destination account IDs with your organisation's account inventory. An unrecognised account ID in either position warrants immediate escalation.

### 2d. Check the caller's recent activity in the source account

```spl
index=aws_cloudtrail userIdentity.arn="<ARN_FROM_ALERT>"
  earliest=-1h latest=now
| stats count BY eventName, eventTime, sourceIPAddress
| sort - eventTime
```

If you see `GetCallerIdentity`, `ListRoles`, `ListUsers`, `ListBuckets`, or similar enumeration events in the 30 minutes before the `AssumeRole` call, treat as **high-confidence attack chain** and escalate immediately.

---

## 3. Urgency Assessment

Answer each question; every "Yes" increases urgency:

- [ ] Is the destination account **not** in `splunk/lookups/approved_aws_accounts.csv`?
- [ ] Is the calling principal **not** in `splunk/lookups/automation_role_arns.csv` or `splunk/lookups/approved_iam_principals.csv`?
- [ ] Is `sourceIPAddress` **not** in `splunk/lookups/approved_cidr_ranges.csv`?
- [ ] Was the call made outside business hours?
- [ ] Does the source IP geo-locate to an unexpected country?
- [ ] Is `requestParameters.roleSessionName` a random or obfuscated string (no recognisable service or user name)?
- [ ] Are there failed `AssumeRole` attempts to other roles within ±15 minutes (role enumeration pattern)?
- [ ] Did a successful assumption occur immediately after or during an active enumeration sequence?

**3 or more Yes answers → escalate to IR lead immediately and open a P1 incident before continuing.**

---

## 4. Lookup CSVs That Apply to CDET-012

| File | Purpose |
|---|---|
| `splunk/lookups/approved_aws_accounts.csv` | Maps account IDs to environment and owner; flag any destination not listed |
| `splunk/lookups/automation_role_arns.csv` | Known CI/CD and automation role ARNs permitted to assume cross-account roles |
| `splunk/lookups/approved_iam_principals.csv` | Sanctioned human and service principals; cross-reference caller ARN |
| `splunk/lookups/approved_cidr_ranges.csv` | Trusted IP ranges for corporate egress, CI/CD runners, and cloud NAT gateways |

---

## 5. PASS / FAIL Decision

| Outcome | Criteria | Next action |
|---|---|---|
| **PASS — Benign FP** | Caller is in `automation_role_arns.csv` AND target role is in `approved_iam_principals.csv` AND source IP is trusted AND destination account is approved | Close alert, add suppression note referencing CDET-012 |
| **PASS — Benign FP (documented)** | Caller is a known engineer, change ticket exists, cross-account access is documented in change management | Close alert, record ticket number |
| **FAIL — Real Alert** | Any urgency check fires OR caller/target account/IP is unknown | Proceed to `investigation.md` immediately |
| **FAIL — Escalate Now** | 3+ urgency checks fire OR destination account is unapproved OR enumeration precedes the assumption | Page IR lead; begin `investigation.md` in parallel |

---

## 6. Triage Notes Template

Paste into your ticketing system before handing off:

```
CDET-012 Triage — <DATE> <TIME UTC>
Analyst: <NAME>
Alert source: Splunk / CloudTrail
Triggering event time (UTC):
Calling identity (ARN):
Source account ID:
Destination account ID:
Target role ARN:
roleSessionName:
Source IP:
In automation_role_arns.csv: YES / NO
In approved_aws_accounts.csv (destination): YES / NO
In approved_cidr_ranges.csv: YES / NO
Urgency checks fired (count):
Verdict: REAL ALERT / BENIGN FP
Next step: investigation.md / CLOSED
```
