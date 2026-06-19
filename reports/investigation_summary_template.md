---
template_version: 1.0
last_updated: 2026-06-18
audience: tier1
---

<!--
COMPLETION GUIDE
================
Time to complete: ~15 minutes
Who fills this out: On-call analyst at handoff, or Tier-1 analyst closing initial triage
How to use:
  1. Fill in the Alert Overview table first — all values come from the GuardDuty finding or SIEM alert.
  2. Write 3–5 bullet points under Key Findings. Be specific: include ARNs, IPs, and API calls.
  3. Build the Evidence Chain as a numbered sequence — this is the story you are handing off.
  4. List only completed actions under Actions Taken.
  5. Capture every unanswered question under Open Questions before handoff.
  6. Next Steps should be actionable tasks with an owner name, not generic statements.
AWS quick references for fast triage:
  - GuardDuty console: https://console.aws.amazon.com/guardduty/
  - CloudTrail event history: https://console.aws.amazon.com/cloudtrail/home#/events
  - IAM last-used data: aws iam get-access-key-last-used --access-key-id AKIA...
-->

# Investigation Summary — Handoff / Ticket Note

| Field | Value |
|---|---|
| **Incident ID** | {{INCIDENT_ID}} |
| **Ticket URL** | {{TICKET_URL}} |
| **Severity** | {{SEVERITY}} |
| **Status** | {{STATUS}} <!-- Triaging / Escalated / Contained / Closed --> |
| **Alert Time** | {{ALERT_TIME_UTC}} UTC |
| **Summary Written** | {{SUMMARY_TIME_UTC}} UTC |
| **Written By** | {{ANALYST_NAME}} |
| **Handoff To** | {{HANDOFF_TO}} <!-- Name or "Tier-2 on-call" --> |

---

## Alert Overview

| Attribute | Value |
|---|---|
| **Alert / Finding Type** | {{ALERT_TYPE}} <!-- e.g. GuardDuty: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B --> |
| **Detection Source** | {{DETECTION_SOURCE}} <!-- GuardDuty / CloudTrail anomaly / Custom rule --> |
| **AWS Account** | {{AWS_ACCOUNT_ID}} ({{AWS_ACCOUNT_ALIAS}}) |
| **AWS Region** | {{AWS_REGION}} |
| **Affected Principal** | {{AFFECTED_PRINCIPAL}} <!-- IAM user ARN or role ARN --> |
| **Source IP** | {{SOURCE_IP}} |
| **IP Reputation** | {{IP_REPUTATION}} <!-- Clean / Suspicious / Known malicious / TOR exit node --> |
| **Initial Verdict** | {{INITIAL_VERDICT}} <!-- True Positive / False Positive / Needs Investigation --> |

---

## Key Findings

- {{FINDING_1}}
  <!-- Example: "IAM user arn:aws:iam::123456789012:user/deploy-bot called GetSecretValue on 14 secrets in us-east-1 between 14:00–14:07 UTC — anomalous for this principal." -->
- {{FINDING_2}}
  <!-- Example: "Source IP 198.51.100.42 is a known Tor exit node per GuardDuty threat intel feed." -->
- {{FINDING_3}}
  <!-- Example: "Access key AKIAIOSFODNN7EXAMPLE was created 380 days ago and has never been rotated." -->
- {{FINDING_4}}
- {{FINDING_5}}

---

## Evidence Chain

Numbered sequence of events that tells the story of the incident. Chronological, UTC.

1. **{{TIME_1}} UTC** — {{EVENT_1}}
   <!-- Example: "14:00:12 UTC — First observed API call: AssumeRole by AKIAIOSFODNN7EXAMPLE from 198.51.100.42" -->
2. **{{TIME_2}} UTC** — {{EVENT_2}}
3. **{{TIME_3}} UTC** — {{EVENT_3}}
4. **{{TIME_4}} UTC** — {{EVENT_4}}
5. **{{TIME_5}} UTC** — {{EVENT_5}}

**Key CloudTrail Event ID(s):** {{CLOUDTRAIL_EVENT_IDS}}
<!-- Comma-separated list of CloudTrail eventID UUIDs for fast log retrieval during handoff -->

**S3 Log Location (if applicable):** `s3://{{CLOUDTRAIL_BUCKET}}/AWSLogs/{{AWS_ACCOUNT_ID}}/CloudTrail/{{AWS_REGION}}/{{LOG_DATE_PATH}}/`

---

## Actions Taken

- [ ] {{ACTION_1}} — completed {{ACTION_1_TIME}} UTC by {{ACTION_1_BY}}
  <!-- Example: "Disabled access key AKIAIOSFODNN7EXAMPLE via aws iam update-access-key" -->
- [ ] {{ACTION_2}} — completed {{ACTION_2_TIME}} UTC by {{ACTION_2_BY}}
- [ ] {{ACTION_3}} — completed {{ACTION_3_TIME}} UTC by {{ACTION_3_BY}}
- [ ] {{ACTION_4}} — completed {{ACTION_4_TIME}} UTC by {{ACTION_4_BY}}

<!-- Check boxes off as actions are confirmed. Leave unchecked if still pending. -->

---

## Open Questions

1. {{OPEN_QUESTION_1}}
   <!-- Example: "Was the access key exposed in a public repo or phished? Git history search not yet performed." -->
2. {{OPEN_QUESTION_2}}
   <!-- Example: "Did the actor successfully exfiltrate data from S3? GetObject calls in us-west-2 not yet reviewed." -->
3. {{OPEN_QUESTION_3}}
4. {{OPEN_QUESTION_4}}

---

## Next Steps

| Priority | Action | Owner | ETA |
|---|---|---|---|
| P1 | {{NEXT_STEP_1}} | {{NEXT_OWNER_1}} | {{NEXT_ETA_1}} |
| P1 | {{NEXT_STEP_2}} | {{NEXT_OWNER_2}} | {{NEXT_ETA_2}} |
| P2 | {{NEXT_STEP_3}} | {{NEXT_OWNER_3}} | {{NEXT_ETA_3}} |
| P2 | {{NEXT_STEP_4}} | {{NEXT_OWNER_4}} | {{NEXT_ETA_4}} |

<!-- P1 = complete before next handoff. P2 = complete within 24 hours. -->

---

*Cross-reference: Analyst Report {{INCIDENT_ID}}-ANALYST | Executive Briefing {{INCIDENT_ID}}-EXEC*
