---
last_updated: 2026-06-18
owner: SOC Operations
version: 1.0
---

# Alert Triage Guide

Goal: Disposition any CDET alert within the SLA window using a repeatable, evidence-driven process.

---

## SLA Targets

| Severity | Time to Disposition |
|----------|-------------------|
| CRITICAL | 15 minutes |
| HIGH | 1 hour |
| MEDIUM | 4 hours |
| LOW | Next business day |

The clock starts when the alert enters the queue (PagerDuty page time or Splunk Notable Event creation time, whichever is earlier).

---

## The 3-Question Triage Test

Run these three checks in order before escalating or closing any alert. Document your answer to each question in the incident ticket.

### Question 1 — Is the actor in an approved lookup?

1. Identify the actor ARN or IAM principal from the alert (field: `userIdentity.arn` or `actor_arn`).
2. In Splunk, run:
   ```
   | inputlookup approved_accounts.csv | search arn="<actor_arn>"
   ```
   Replace `<actor_arn>` with the value from the alert. The lookup file lives at `splunk/lookups/approved_accounts.csv`.
3. If the actor is **not** in the lookup, treat this as a strong indicator of compromise and advance immediately to escalation consideration.
4. If the actor **is** in the lookup, note the associated team and expected role before proceeding.

### Question 2 — Was MFA used?

1. From the same alert event, inspect the field `userIdentity.sessionContext.attributes.mfaAuthenticated`.
2. Acceptable values: `true` (console sessions) or `N/A` (programmatic access via access keys — MFA cannot be enforced here; assess separately).
3. If the value is `false` and the session type is console, the absence of MFA is itself an indicator; document it and factor into the disposition.
4. For programmatic access, check whether the access key in use (`userIdentity.accessKeyId`) appears in `splunk/lookups/approved_service_accounts.csv`.

### Question 3 — Is the region expected?

1. Locate the `awsRegion` field in the alert event.
2. Run:
   ```
   | inputlookup approved_regions.csv | search region="<awsRegion>"
   ```
   The lookup file lives at `splunk/lookups/approved_regions.csv`.
3. Activity in an unexpected region (especially a region your organization has never provisioned resources in) is a high-confidence indicator of unauthorized access or initial access via a compromised credential.
4. Document the region and whether it is expected.

---

## How to Open the Alert in Splunk and Find Supporting Context

1. Log in to the Splunk instance and navigate to **Search & Reporting**.
2. Open the **CDET Alerts** dashboard (found under Apps > CDET > Dashboards > Alert Overview).
3. Click the alert ID (format: `CDET-YYYY-NNNN`) to open the Notable Event detail pane.
4. Note the following fields before leaving the detail pane:
   - Detection ID (e.g., `CDET-2026-0042`)
   - Rule name and MITRE ATT&CK tactic/technique tags
   - `userIdentity.arn`
   - `sourceIPAddress`
   - `eventTime` (UTC)
   - `eventName`
   - `awsRegion`
   - `requestParameters` (raw JSON — save a copy to the ticket)
5. Pivot to raw CloudTrail events for the same actor within a 30-minute window around the alert time:
   ```
   index=cloudtrail userIdentity.arn="<actor_arn>"
   earliest=-30m@m latest=+30m@m
   | table _time, eventName, awsRegion, sourceIPAddress, errorCode, requestParameters
   | sort _time
   ```
6. Check for correlated alerts on the same actor within the last 24 hours:
   ```
   index=notable actor_arn="<actor_arn>"
   earliest=-24h
   | table _time, rule_name, severity
   | sort _time
   ```
7. If correlated alerts exist, link them in the incident ticket under "Related Alerts."

---

## How to Check the Detection Playbook Directory

Every CDET detection rule has a corresponding playbook in `docs/detection_engineering/`. The playbook file is named after the detection ID.

1. Identify the detection ID from the alert (format: `CDET-YYYY-NNNN` or the rule name slug).
2. Open the relevant playbook file:
   ```
   docs/detection_engineering/<detection_id>.md
   ```
   If a file for that exact ID does not exist, check `docs/detection_catalog.md` for the rule name and locate the playbook by rule name.
3. The playbook specifies:
   - Intended behavior of the detection logic
   - Known false positive conditions
   - Recommended investigation steps specific to this detection
   - Containment actions and authorization requirements
4. Follow any playbook-specific steps in addition to this general triage guide.

---

## Disposition Options

After completing the 3-question triage test and reviewing supporting context, assign one of the following dispositions in the Splunk Notable Event and the incident ticket.

### True Positive
The activity is confirmed malicious or unauthorized. Proceed to the [Escalation Matrix](escalation_matrix.md) and open a formal incident. Do not close the Notable Event; set status to **In Progress**.

### False Positive
All three triage questions returned benign results, the detection playbook lists this as a known false positive pattern, and there is no additional suspicious context. Set the Notable Event status to **Closed - False Positive**. Document the suppression rationale in the ticket. If this pattern recurs more than twice in 30 days, file a detection tuning request.

### Needs Investigation
The 3-question triage test was inconclusive (e.g., actor is in the approved lookup but region is unexpected, or MFA was absent but the action itself is low-risk). Assign the alert to yourself, set status to **In Progress**, and follow the [Investigation Standards](investigation_standards.md) guide to gather additional evidence. You have until the SLA window expires to reach a final disposition.

### Escalate
Any of the following conditions triggers immediate escalation regardless of other triage results:
- CRITICAL severity alert
- Root account activity
- Defense Evasion tactic detected
- Mass destructive action (DeleteTrail, StopLogging, TerminateInstances at scale, DeleteBucket with versioning disabled)
- Actor not in any approved lookup
- Two or more correlated HIGH alerts on the same actor within 24 hours

Follow the [Escalation Matrix](escalation_matrix.md) for notification procedures.

---

## Triage Checklist Summary

- [ ] Opened Notable Event in Splunk; copied Detection ID and raw event fields to ticket
- [ ] Question 1 complete: actor ARN checked against `splunk/lookups/approved_accounts.csv`
- [ ] Question 2 complete: MFA status documented
- [ ] Question 3 complete: region checked against `splunk/lookups/approved_regions.csv`
- [ ] Detection playbook reviewed at `docs/detection_engineering/<detection_id>.md`
- [ ] Supporting context pivot query run; results attached to ticket
- [ ] Correlated alerts checked for same actor (last 24 hours)
- [ ] Disposition assigned: True Positive / False Positive / Needs Investigation / Escalate
- [ ] SLA window noted; handoff documented if shift ends before disposition
