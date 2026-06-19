---
detection_id: CDET-001
detection_name: IAM User Created Outside Pipeline
tactic: Persistence
technique: T1136.003
last_updated: 2026-06-18
---

# CDET-001 — Triage Playbook
**IAM User Created Outside Pipeline**

> **Target completion time:** 5–10 minutes
> **Audience:** Tier-2 SOC Analyst
> **Escalate if:** you cannot rule out attacker access within the first 5 minutes.

---

## 1. Pull the Raw Alert

Open the triggering Splunk alert and note the following fields before doing anything else:

| Field | Where to find it | What to record |
|---|---|---|
| `userIdentity.arn` | CloudTrail event | Who made the API call |
| `userIdentity.type` | CloudTrail event | IAMUser / AssumedRole / Root |
| `sourceIPAddress` | CloudTrail event | Calling IP |
| `userAgent` | CloudTrail event | Tool / SDK used |
| `requestParameters.userName` | CloudTrail event | Name of new IAM user |
| `eventTime` | CloudTrail event | UTC timestamp |
| `awsRegion` | CloudTrail event | Region of the call |
| `errorCode` | CloudTrail event | Must be absent / `null` for a successful create |

---

## 2. Validate the Alert Is Real

### 2a. Confirm the event is not test data

1. Check `sourceIPAddress` against the known test-harness IP ranges documented in `splunk/lookups/trusted_cidr_ranges.csv`.
2. Check `requestParameters.userName` for patterns used by your synthetic log generator (e.g., prefix `test_`, `synthetic_`, `lab_`).
3. If the event originated from a known test account (check `userIdentity.accountId` against `splunk/lookups/aws_accounts.csv`), mark **FP — test data** and close.

### 2b. Confirm the caller is not a known CI/CD pipeline identity

1. Look up `userIdentity.arn` in **`splunk/lookups/authorized_automation_roles.csv`**.
   - If the ARN is listed AND the call was made during a documented deployment window, mark **FP — pipeline actor** and close.
   - If the ARN is listed but the time is outside any deployment window, treat as **suspicious** and continue.
2. Check `userAgent` for known pipeline strings (e.g., `aws-sdk-java`, `Terraform`, `Ansible`). These alone are not conclusive — pipeline actors can be impersonated.

### 2c. Check the calling identity's recent history

Run the following Splunk query to see if the caller has performed other sensitive actions in the last 24 hours:

```spl
index=aws_cloudtrail userIdentity.arn="<ARN_FROM_ALERT>"
  earliest=-24h latest=now
  eventName IN (CreateUser, AttachUserPolicy, CreateAccessKey, AddUserToGroup, CreateRole, PutUserPolicy)
| stats count BY eventName, eventTime
| sort - eventTime
```

If multiple privilege-escalation events appear in sequence, treat as **high confidence real alert** and escalate immediately.

---

## 3. Urgency Assessment

Answer the following questions (each "Yes" increases urgency):

- [ ] Was the call made from an IP **not** in `splunk/lookups/trusted_cidr_ranges.csv`?
- [ ] Was the caller identity **not** in `splunk/lookups/authorized_automation_roles.csv`?
- [ ] Was the new user immediately given a policy, group membership, or access key (check within ±5 min)?
- [ ] Is the calling identity a human IAM user rather than a role?
- [ ] Was the call made outside business hours (per your org's timezone)?
- [ ] Does the source IP geo-locate to an unexpected country?

**3 or more Yes answers → escalate to IR lead immediately before continuing investigation.**

---

## 4. Lookup CSVs That Apply to CDET-001

| File | Purpose |
|---|---|
| `splunk/lookups/authorized_automation_roles.csv` | Known pipeline / automation ARNs permitted to create IAM users |
| `splunk/lookups/aws_accounts.csv` | Maps account IDs to environment (prod / staging / lab) |
| `splunk/lookups/trusted_cidr_ranges.csv` | IP ranges for corporate egress, CI/CD runners, and known cloud NAT gateways |
| `splunk/lookups/iam_naming_conventions.csv` | Approved user name patterns; deviations are suspicious |

---

## 5. PASS / FAIL Decision

| Outcome | Criteria | Next action |
|---|---|---|
| **PASS — Benign FP** | Caller is in authorized_automation_roles AND IP is trusted AND username matches approved naming convention | Close alert, add suppression note referencing this playbook |
| **PASS — Benign FP (manual)** | Caller is a known admin, change ticket exists, creation is documented in change management system | Close alert, document ticket number |
| **FAIL — Real Alert** | Any of the urgency checks above fire OR caller/IP are unknown | Proceed to `investigation.md` immediately |
| **FAIL — Escalate Now** | 3+ urgency checks fire OR new user has already received permissions or access keys | Page IR lead, proceed to `investigation.md` in parallel |

---

## 6. Triage Notes Template

Paste into your ticketing system before handing off:

```
CDET-001 Triage — <DATE> <TIME UTC>
Analyst: <NAME>
Alert source: Splunk / CloudTrail
Triggering event time: 
Calling identity (ARN): 
Source IP: 
New IAM username: 
In authorized_automation_roles.csv: YES / NO
In trusted_cidr_ranges.csv: YES / NO
Urgency checks fired (count): 
Verdict: REAL ALERT / BENIGN FP
Next step: investigation.md / CLOSED
```
