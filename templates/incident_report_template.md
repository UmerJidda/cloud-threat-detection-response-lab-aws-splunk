# Incident Report Template

> Copy this template to `incident_response/reports/{YYYY-MM-DD}_{INC-ID}_{short_description}.md`.
> All incident reports are gitignored by default. Store in the reports directory.
> Remove this instruction block before filing.

---

# Incident Report

| Field | Value |
|-------|-------|
| **Incident ID** | INC-YYYY-NNN |
| **Date Opened** | YYYY-MM-DD HH:MM UTC |
| **Date Closed** | YYYY-MM-DD HH:MM UTC |
| **Severity** | critical / high / medium / low |
| **Status** | open / contained / closed |
| **Detection ID** | CDET-NNN |
| **Lead Analyst** | [Name] |
| **Incident Commander** | [Name, if escalated] |

---

## 1. Executive Summary

[Two to four sentences. What happened, when it was detected, what was affected, and how it was resolved. Write for a non-technical audience. Avoid jargon.]

---

## 2. Detection

**Detection trigger:**
[Which detection fired, what event triggered it, and at what time.]

**Alert details:**
- Detection: CDET-NNN — [Detection Name]
- Fired at: YYYY-MM-DD HH:MM UTC
- Severity: [as configured in detection]
- Principal: `[ARN of acting principal]`
- Source IP: `[IP address]`
- Region: `[AWS region]`
- Event: `[CloudTrail eventName]`

**Time to detection:** [elapsed time between first malicious event and alert firing]

---

## 3. Timeline

All times in UTC.

| Time | Event |
|------|-------|
| HH:MM | [First suspicious event observed in CloudTrail] |
| HH:MM | [Detection alert fired in Splunk] |
| HH:MM | [Analyst acknowledged alert] |
| HH:MM | [Investigation began] |
| HH:MM | [True positive confirmed / false positive dismissed] |
| HH:MM | [Escalation, if applicable] |
| HH:MM | [Containment action taken] |
| HH:MM | [Containment confirmed effective] |
| HH:MM | [Recovery complete] |
| HH:MM | [Incident closed] |

---

## 4. Evidence

### CloudTrail Events

[Summary of the key CloudTrail events relevant to this incident. Include event names, principal ARNs, source IPs, and timestamps. Attach the raw NDJSON file if available.]

Key events:

| Time | Event Name | Principal | Source IP | Region |
|------|------------|-----------|-----------|--------|
| HH:MM | [eventName] | [ARN] | [IP] | [region] |

### IAM State at Time of Detection

[Describe the IAM configuration of the affected principal at the time of detection — permissions, group memberships, active access keys.]

### GuardDuty Findings (if applicable)

[List any concurrent or related GuardDuty findings. Include finding type, severity, and resource affected.]

### Security Hub Context (if applicable)

[Any Security Hub findings related to the affected resource or account.]

---

## 5. Scope of Impact

**Affected principals:**
- [List IAM users, roles, or service accounts involved]

**Affected resources:**
- [List S3 buckets, EC2 instances, Lambda functions, or other resources accessed]

**Data accessed or exfiltrated:**
- [Describe any data that may have been accessed. If no data exfiltration, state "No evidence of data exfiltration."]

**Scope determination:**
[Explain how scope was determined and what evidence supports the scope assessment.]

---

## 6. Root Cause

[One to three paragraphs. Describe the root cause of the incident — not just the technical trigger, but the underlying organizational or process failure that allowed the incident to occur.]

**Root cause category:**
- [ ] Compromised credential
- [ ] Insider threat
- [ ] Misconfigured resource
- [ ] Insufficient access controls
- [ ] Social engineering
- [ ] Supply chain
- [ ] Unknown

---

## 7. Containment Actions Taken

| Time | Action | Performed By | Reversible |
|------|--------|-------------|-----------|
| HH:MM | [e.g., Access key AKIAXXXXXXXX deactivated] | [Name] | Yes/No |
| HH:MM | [e.g., Deny-all session policy attached to user] | [Name] | Yes |

---

## 8. Recovery Actions Taken

| Time | Action | Performed By |
|------|--------|-------------|
| HH:MM | [e.g., New access key issued to legitimate owner] | [Name] |
| HH:MM | [e.g., Deny-all session policy removed] | [Name] |

---

## 9. Recommendations

List concrete, actionable recommendations resulting from this incident. Each recommendation should have an owner and target completion date.

| # | Recommendation | Owner | Target Date | Status |
|---|---------------|-------|-------------|--------|
| 1 | [Specific action to prevent recurrence] | [Team] | YYYY-MM-DD | Open |
| 2 | [Detection improvement or new detection] | Detection Engineering | YYYY-MM-DD | Open |
| 3 | [Process or policy change] | [Team] | YYYY-MM-DD | Open |

---

## 10. Detection Improvement Actions

| Action | Type | Detection ID | Status |
|--------|------|-------------|--------|
| [e.g., Add FP suppression for automation role] | Tuning | CDET-NNN | Open |
| [e.g., Create new detection for observed lateral movement] | New detection | TBD | Open |
| [e.g., Lower severity threshold for this detection] | Severity change | CDET-NNN | Open |

---

## 11. Metrics

| Metric | Value |
|--------|-------|
| Time to Detection (TTD) | [minutes/hours] |
| Time to Acknowledge (TTA) | [minutes/hours] |
| Time to Contain (TTC) | [minutes/hours] |
| Time to Close (TTCL) | [hours/days] |
| False positive? | Yes / No |
| Automated containment triggered? | Yes / No |

---

## 12. Approvals

| Role | Name | Date |
|------|------|------|
| Lead Analyst | [Name] | YYYY-MM-DD |
| Incident Commander | [Name, if escalated] | YYYY-MM-DD |
| Security Manager | [Name] | YYYY-MM-DD |
