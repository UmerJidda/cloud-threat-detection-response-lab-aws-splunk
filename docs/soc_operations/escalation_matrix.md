---
last_updated: 2026-06-18
owner: SOC Operations
version: 1.0
---

# Escalation Matrix

This document defines who must be notified, through which channels, and within what timeframe for every CDET alert severity level and special case scenario.

---

## Escalation Path by Severity

### CRITICAL

| Step | Action | Owner | SLA |
|------|--------|-------|-----|
| 1 | Acknowledge alert in PagerDuty | On-Call Analyst | 5 minutes |
| 2 | Notify Senior Analyst via PagerDuty secondary page | On-Call Analyst | 5 minutes |
| 3 | Post initial notification to Slack `#security-incidents` | On-Call Analyst | 5 minutes |
| 4 | SOC Lead joins war room (see [On-Call Procedures](on_call_procedures.md)) | SOC Lead | 10 minutes |
| 5 | CISO briefed via direct call or SMS if containment action is required | SOC Lead | 15 minutes |

Acknowledgment requirement: All notified parties must acknowledge via PagerDuty or Slack within their SLA window. Unacknowledged pages auto-escalate to the next tier after 5 minutes.

---

### HIGH

| Step | Action | Owner | SLA |
|------|--------|-------|-----|
| 1 | Acknowledge alert in PagerDuty | On-Call Analyst | 15 minutes |
| 2 | Begin investigation per [Investigation Standards](investigation_standards.md) | On-Call Analyst | 30 minutes |
| 3 | Notify Senior Analyst if investigation stalls or escalation criteria met | On-Call Analyst | 45 minutes |
| 4 | Post status update to Slack `#security-incidents` | On-Call Analyst | 1 hour |
| 5 | Escalate to SOC Lead if unresolved at 2 hours | Senior Analyst | 2 hours |

Acknowledgment requirement: Initial acknowledgment in PagerDuty within 15 minutes. Slack status update every 30 minutes until disposition.

---

### MEDIUM

| Step | Action | Owner | SLA |
|------|--------|-------|-----|
| 1 | Assign alert to self in Splunk; create incident ticket | On-Call Analyst | 1 hour |
| 2 | Complete triage per [Alert Triage Guide](alert_triage_guide.md) | On-Call Analyst | 2 hours |
| 3 | Notify Senior Analyst if True Positive is confirmed | On-Call Analyst | 2 hours |
| 4 | Escalate to SOC Lead if unresolved by 4-hour mark | Senior Analyst | 4 hours |

Acknowledgment requirement: Ticket created within 1 hour. No PagerDuty page required unless investigation reveals CRITICAL or HIGH indicators.

---

### LOW

| Step | Action | Owner | SLA |
|------|--------|-------|-----|
| 1 | Assign alert; create ticket during next business day | On-Call Analyst (next shift) | Next business day |
| 2 | Triage and disposition per standard process | Assigned Analyst | Next business day |
| 3 | Escalate if triage reveals higher-severity indicators | Assigned Analyst | Per new severity SLA |

Acknowledgment requirement: Ticket assigned and status updated before end of next business day shift.

---

## On-Call Rotation Contacts

All contact details are maintained in PagerDuty under the **CDET On-Call Schedule**. The roles below are placeholders; actual names and contact info are in PagerDuty.

| Role | Responsibility | Contact Channel |
|------|----------------|-----------------|
| On-Call Analyst (Primary) | First responder for all alerts; initial triage and acknowledgment | PagerDuty primary rotation |
| On-Call Analyst (Secondary) | Backup if primary does not acknowledge within 5 minutes (CRITICAL) or 15 minutes (HIGH) | PagerDuty secondary rotation |
| Senior Analyst (On-Call) | Escalation point for complex investigations; approves containment actions | PagerDuty escalation policy tier 2 |
| SOC Lead | War room commander for CRITICAL incidents; CISO liaison | PagerDuty escalation policy tier 3; direct mobile |
| CISO (or Delegate) | Executive notification for CRITICAL incidents requiring containment or breach disclosure | Direct call via SOC Lead; email `ciso-security@[org-domain]` |
| AWS Account Owner | Notified if containment requires AWS-level action (e.g., account suspension, Support case) | Email `cloud-ops@[org-domain]`; Slack `#cloud-operations` |

---

## Special Case — Immediate Escalation Scenarios

The following scenarios bypass normal severity-based SLAs. Escalate directly to the SOC Lead and simultaneously page the Senior Analyst the moment any of these conditions are confirmed.

### Root Account Activity

- Any event where `userIdentity.type = Root` in CloudTrail
- Detection ID format: rules tagged with MITRE T1078.004 (Valid Accounts: Cloud Accounts) and actor = root
- Action: Page SOC Lead immediately; do not wait for triage completion
- Slack message template: `[IMMEDIATE ESCALATION] Root account activity detected. Detection ID: <CDET-ID>. Actor: root. Time: <UTC>. On-Call Analyst: <name>.`

### Defense Evasion

- Any CDET alert tagged with MITRE Tactic TA0005 (Defense Evasion), including but not limited to:
  - `StopLogging` or `DeleteTrail` (CloudTrail)
  - `PutEventSelectors` removing data event logging
  - `DeleteFlowLogs`
  - `DisableAlarmActions` (CloudWatch)
- Action: Page SOC Lead and Senior Analyst simultaneously; preserve all evidence before any remediation
- These events indicate an adversary is actively trying to blind the detection stack

### Mass Destruction

- Any event pattern indicating large-scale resource deletion or data destruction:
  - `TerminateInstances` with more than 5 instances in a single API call
  - `DeleteBucket` on a bucket without versioning or with MFA Delete disabled
  - `DeleteDBInstance` or `DeleteDBCluster` (RDS)
  - `DeleteStack` (CloudFormation) affecting production stacks
- Action: Page SOC Lead and CISO simultaneously; contact AWS Support (if applicable) to flag the account
- Do not attempt containment without explicit SOC Lead approval

---

## Communication Channels

### Slack `#security-incidents`

- Primary channel for all active incident communications
- Every CRITICAL and HIGH incident must have a dedicated thread opened within 5 minutes of acknowledgment
- Thread naming convention: `[CDET-YYYY-NNNN] <Alert Name> | Severity: <SEV> | Status: <OPEN/CONTAINED/CLOSED>`
- Post status updates at minimum every 30 minutes for CRITICAL, every hour for HIGH

### PagerDuty

- Authoritative source for on-call scheduling and escalation policy enforcement
- All acknowledgments and escalations must be recorded in PagerDuty (do not rely on Slack alone)
- Incident timeline in PagerDuty is considered part of the formal record

### Email

- Used for CISO notifications, AWS Support cases, and external notifications
- Email address for security incidents: `security-incidents@[org-domain]`
- CISO: `ciso-security@[org-domain]`
- Cloud Operations: `cloud-ops@[org-domain]`
- All incident-related emails must include the CDET Detection ID in the subject line

---

## Escalation SLA Summary

| Severity | Initial Ack | Notify Senior Analyst | Notify SOC Lead | Notify CISO |
|----------|-----------|-----------------------|-----------------|-------------|
| CRITICAL | 5 min | Immediate | 10 min | 15 min (if containment needed) |
| HIGH | 15 min | 45 min | 2 hr (if unresolved) | As directed by SOC Lead |
| MEDIUM | 1 hr | On True Positive confirm | 4 hr (if unresolved) | As directed by SOC Lead |
| LOW | Next business day | On True Positive confirm | As needed | As directed by SOC Lead |
| Special Cases | Immediate | Immediate | Immediate | CRITICAL special cases only |
