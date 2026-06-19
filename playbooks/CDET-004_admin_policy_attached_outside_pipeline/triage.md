---
detection_id: CDET-004
detection_name: Admin Policy Attached Outside Pipeline
tactic: Privilege Escalation
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-004 — Triage Playbook
**Target completion time: 5–10 minutes**

## Purpose
Validate whether the CDET-004 alert represents a real privilege escalation or a benign false positive (authorized pipeline actor, test activity, or approved change).

---

## Step 1 — Retrieve the Raw Alert (1 min)

Open the alert in Splunk and confirm the following fields are populated. A missing `userIdentity.arn` or `sourceIPAddress` is itself suspicious.

| Field | Expected value |
|---|---|
| `eventName` | `AttachUserPolicy` |
| `eventSource` | `iam.amazonaws.com` |
| `requestParameters.policyArn` | should contain `AdministratorAccess` or equivalent admin-managed policy |
| `userIdentity.type` | `IAMUser`, `AssumedRole`, or `Root` |
| `userIdentity.arn` | fully qualified ARN of the actor |
| `sourceIPAddress` | IP of the API caller |
| `userAgent` | e.g., `aws-cli`, `Boto3`, `console.amazonaws.com` |
| `errorCode` | must be absent (blank = success) |
| `recipientAccountId` | confirm this is your monitored account, not a test account |

---

## Step 2 — Check for Known Pipeline Actors (2 min)

Look up the calling identity in the authorized pipeline principals lookup.

**Lookup CSV:** `splunk/lookups/authorized_pipeline_principals.csv`

```spl
| inputlookup authorized_pipeline_principals.csv
| where lower(principal_arn) = lower("<userIdentity.arn from alert>")
```

- If the ARN appears in the lookup with `role = ci_cd_pipeline` → likely **benign FP** (proceed to Step 5).
- If the ARN is absent or the role field is blank → continue to Step 3.

Also check the known admin accounts lookup:

**Lookup CSV:** `splunk/lookups/known_admin_accounts.csv`

```spl
| inputlookup known_admin_accounts.csv
| where lower(account_id) = lower("<recipientAccountId>")
```

---

## Step 3 — Validate the Policy ARN (1 min)

Confirm the attached policy is genuinely privileged. Any of the following ARNs constitute a critical alert:

- `arn:aws:iam::aws:policy/AdministratorAccess`
- `arn:aws:iam::aws:policy/IAMFullAccess`
- Any customer-managed policy with `*` on `*` (requires investigation step to confirm)

If the policy ARN is a read-only or scoped policy, downgrade severity and document before closing.

---

## Step 4 — Check Source IP Geolocation and Business Hours (1 min)

1. Look up `sourceIPAddress` in the threat intel lookup:

   **Lookup CSV:** `splunk/lookups/threat_intel_ips.csv`

   ```spl
   | inputlookup threat_intel_ips.csv
   | where ip = "<sourceIPAddress>"
   ```

2. Note whether the event timestamp falls outside business hours or in an unexpected geography. VPN and AWS internal IPs (`aws-internal`) are expected for console and service activity.

---

## Step 5 — Urgency Decision (1 min)

| Condition | Action |
|---|---|
| Actor not in authorized pipeline lookup AND policy is `AdministratorAccess` | **ESCALATE IMMEDIATELY** — page on-call |
| Actor not in lookup, policy is a custom admin policy | Escalate within 15 minutes after Step 6 |
| Actor is in authorized pipeline lookup but attachment was outside scheduled window | Open change-review ticket, do not escalate immediately |
| Actor in lookup, policy scoped/non-admin | Document as FP and close |

---

## Step 6 — Check for Concurrent Suspicious Events (2 min)

Before escalating, run a quick pivot to see if there are correlated events from the same actor in the last 30 minutes:

```spl
index=aws_cloudtrail userIdentity.arn="<arn>"
| where _time >= relative_time(now(), "-30m")
| stats count by eventName, eventSource
| sort - count
```

Any of the following co-occurring events elevates urgency to **immediate escalation**:
- `CreateLoginProfile` / `UpdateLoginProfile`
- `CreateAccessKey`
- `AssumeRole` (unexpected cross-account)
- `PutUserPolicy` (inline policy backdoor)
- `ConsoleLogin` from foreign IP

---

## Pass/Fail Criteria

### REAL ALERT (escalate / begin investigation)
- Actor ARN not present in `authorized_pipeline_principals.csv`
- Policy ARN is `AdministratorAccess` or equivalent broad-permission policy
- No approved change ticket linked to this event
- Source IP is residential, foreign, or listed in `threat_intel_ips.csv`
- Co-occurring identity manipulation events present

### BENIGN FP (document and close)
- Actor ARN confirmed in `authorized_pipeline_principals.csv` with `role = ci_cd_pipeline`
- Event timestamp falls within scheduled deployment window
- Policy ARN is scoped and non-administrative
- Matching approved change ticket exists in ITSM

---

## Triage Completion

Record your verdict in the alert ticket:
- **Verdict:** Real / FP
- **Evidence summary:** (one sentence)
- **Next step:** Escalate to investigation / Close as FP / Open change-review ticket
- **CDET-004 alert ID:**
- **Analyst:**
- **Triage completed at:**
