---
last_updated: 2026-06-18
owner: SOC Operations
version: 1.0
---

# On-Call Procedures

This document defines the responsibilities, protocols, and checklists for analysts assigned to on-call shifts in the CDET SOC.

---

## Shift Handoff Checklist

Complete every item on this checklist before handing off to the incoming analyst. The outgoing analyst is responsible for an accurate and complete handoff. Handoff should be conducted verbally (call or Slack huddle) and confirmed in writing in the `#security-incidents` Slack channel.

### Outgoing Analyst — Pre-Handoff Steps

1. Review all open Notable Events in Splunk. For each open event, confirm the status is accurate (In Progress, Pending Escalation, etc.) and the incident ticket is up to date.
2. For any alert in "Needs Investigation" status, document the current investigation state: what has been checked, what pivots have been run, and what the next step is.
3. Confirm that all PagerDuty incidents from the shift are acknowledged and have a current owner.
4. Post a shift summary to `#security-incidents` using the Post-Shift Report Template (see below).
5. Verbally brief the incoming analyst on:
   - Any active CRITICAL or HIGH incidents still in progress
   - Any detections that fired repeatedly (potential tuning candidates)
   - Any AWS or Splunk infrastructure issues observed during the shift
   - Any pending containment approvals or escalations awaiting response
6. Transfer PagerDuty on-call responsibility to the incoming analyst and confirm they have acknowledged the transfer.
7. Do not end the shift until the incoming analyst has confirmed receipt of the handoff summary.

### Incoming Analyst — Post-Handoff Steps

1. Acknowledge PagerDuty on-call transfer.
2. Read the outgoing analyst's shift summary in `#security-incidents`.
3. Review all open Splunk Notable Events and confirm you understand the current status of each.
4. Verify CDET dashboards are loading correctly in Splunk (CDET > Dashboards > Alert Overview).
5. Confirm that CloudTrail log ingestion is current — check the `Last Event Time` panel on the CDET Overview dashboard. Alert the SOC Lead if ingestion lag exceeds 15 minutes.
6. Confirm receipt of handoff in `#security-incidents` with a message: `[SHIFT START] On-call acknowledged. <Name>. <Shift start time UTC>.`

---

## How to Acknowledge and Take Ownership of an Alert

1. When PagerDuty pages you, acknowledge the incident in PagerDuty within the SLA window defined in the [Escalation Matrix](escalation_matrix.md).
2. Open the linked Splunk Notable Event from the PagerDuty incident or navigate directly to the CDET Alert Overview dashboard.
3. In Splunk, set the Notable Event status to **In Progress** and assign it to your Splunk username.
4. Create an incident ticket in the ticketing system with the following minimum fields:
   - Detection ID (format: `CDET-YYYY-NNNN`)
   - Alert severity
   - Alert time (UTC)
   - Actor ARN
   - Affected resource(s)
   - Your name and shift start time
5. Post an acknowledgment message to the `#security-incidents` Slack channel:
   ```
   [ACK] CDET-YYYY-NNNN | <Alert Name> | Severity: <SEV> | Acknowledged by: <Name> | Time: <UTC>
   ```
6. Begin triage per the [Alert Triage Guide](alert_triage_guide.md).

---

## War Room Protocol for Severity CRITICAL Incidents

A war room is activated automatically for any CRITICAL incident. The SOC Lead commands the war room. All responders join the dedicated Slack thread for the incident.

### Activation

1. On-Call Analyst opens the incident Slack thread in `#security-incidents` within 5 minutes of acknowledgment.
2. SOC Lead joins the thread and assumes command within 10 minutes.
3. SOC Lead sends the war room activation message:
   ```
   [WAR ROOM ACTIVE] CDET-YYYY-NNNN | Commander: <SOC Lead Name> | Analyst: <Name> | Time: <UTC>
   ```
4. All status updates, decisions, and actions taken must be posted in the war room thread in real time. Do not conduct incident communications outside the thread.

### Roles During the War Room

| Role | Responsibility |
|------|----------------|
| SOC Lead (Commander) | Directs investigation; approves containment actions; briefs CISO |
| On-Call Analyst (Lead Investigator) | Runs queries; gathers evidence; executes approved containment |
| Senior Analyst (Support) | Reviews evidence; provides second opinion; assists with pivots |
| CISO or Delegate | Approves actions with potential business impact; authorizes external notification |

### War Room Update Cadence

- Every 15 minutes: Analyst posts a status update in the thread: `[UPDATE T+XX min] <what was found> | <next action> | <blockers>`
- Every 30 minutes: SOC Lead posts a summary update and revised assessment
- At containment: SOC Lead posts a containment summary with actions taken
- At closure: SOC Lead posts a final disposition and opens a post-incident review task

---

## Evidence Preservation Requirements Before Containment

Before taking any containment action (disabling access keys, revoking sessions, isolating instances, blocking IPs), the analyst must preserve the following evidence. Containment that destroys evidence before it is collected is a protocol violation.

1. Export the full CloudTrail event timeline for the actor for the previous 24 hours:
   ```
   index=cloudtrail userIdentity.arn="<actor_arn>"
   earliest=-24h
   | table _time, eventName, awsRegion, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements
   | sort _time
   ```
   Save the result as a CSV and attach it to the incident ticket.

2. Screenshot or export the Splunk Notable Event detail pane, including all correlated alerts.

3. Record the current IAM policy state for the actor (if applicable):
   - Run `aws iam list-attached-user-policies` or `aws iam list-user-policies` for the user
   - Run `aws iam get-user` to capture account metadata
   - Save output to the ticket

4. Record the current session state if a temporary credential is in use:
   - For assumed roles: `aws sts get-caller-identity` (if still active)
   - Note the session token ARN and expiration from `userIdentity.sessionContext`

5. For EC2-related incidents, capture instance metadata before isolation:
   - Instance ID, AMI, security groups, VPC, subnet, public IP
   - Running processes if accessible via SSM: `aws ssm send-command` with `ps aux`

6. Document all evidence file names, hashes (SHA-256), and storage locations in the incident ticket under the "Evidence Log" section.

7. Post evidence preservation confirmation to the war room thread before proceeding to containment:
   ```
   [EVIDENCE PRESERVED] Timeline export attached. IAM state captured. EC2 metadata captured (if applicable). Proceeding to containment request.
   ```

---

## How to Request Containment Approval for Destructive Actions

Containment actions are classified as **Reversible** or **Destructive**. Destructive actions require explicit approval before execution.

### Reversible Actions (Analyst may execute without additional approval)
- Adding an explicit Deny policy to an IAM user or role
- Disabling an IAM access key (`aws iam update-access-key --status Inactive`)
- Revoking all active sessions for an IAM role (via `aws iam delete-role-policy` for inline session policies)

### Destructive Actions (Require SOC Lead approval)
- Deleting an IAM access key (permanent — cannot be recovered)
- Terminating an EC2 instance
- Deleting a resource (S3 objects, snapshots, etc.)
- Modifying or removing SCPs or permission boundaries
- Any action that affects production workloads or availability

### Approval Request Procedure

1. In the war room thread, post a containment request using the following format:
   ```
   [CONTAINMENT REQUEST]
   Action: <exact AWS CLI command or console action>
   Target: <resource ARN or identifier>
   Reason: <why this action is needed>
   Reversible: Yes / No
   Evidence preserved: Yes (see ticket attachment <name>)
   Requesting approval from: SOC Lead
   ```
2. The SOC Lead reviews the request and posts one of:
   - `[APPROVED] Proceed. Authorized by: <SOC Lead Name> <UTC timestamp>`
   - `[DENIED] Do not proceed. Reason: <reason>`
   - `[HOLD] Wait for CISO approval. Reason: <reason>`
3. The analyst executes the action only after receiving explicit `[APPROVED]` confirmation.
4. After execution, post confirmation: `[CONTAINMENT EXECUTED] <action taken> | Time: <UTC> | Executed by: <name>`

---

## Post-Shift Report Template

Post this report to `#security-incidents` at the end of every shift, regardless of whether any alerts fired.

```
[SHIFT REPORT] <Date> | <Shift Start UTC> — <Shift End UTC>
On-Call Analyst: <Name>

ALERTS THIS SHIFT:
- Total Notable Events: <count>
- CRITICAL: <count>
- HIGH: <count>
- MEDIUM: <count>
- LOW: <count>

DISPOSITIONS:
- True Positive: <count> (CDET IDs: <list>)
- False Positive: <count>
- Needs Investigation / Carried Over: <count> (CDET IDs: <list> — briefed to incoming analyst)
- Escalated: <count> (CDET IDs: <list>)

OPEN INCIDENTS:
<List any incidents still In Progress with current status and next steps>

INFRASTRUCTURE NOTES:
<Any Splunk issues, CloudTrail ingestion delays, or AWS service disruptions observed>

TUNING CANDIDATES:
<Any detection rules that fired repeatedly with known false positive patterns — file tuning request if recurring>

HANDOFF TO: <Incoming Analyst Name>
HANDOFF CONFIRMED: Yes / No
```
