---
template_version: 1.0
last_updated: 2026-06-18
audience: executive
---

<!--
COMPLETION GUIDE
================
Time to complete: ~20 minutes
Who fills this out: Incident Commander or Security Manager
How to use: Replace every {{PLACEHOLDER}} with the actual value. Remove this comment block when done.
Placeholders reference:
  {{INCIDENT_ID}}       — Ticket/case ID (e.g. INC-2026-0042)
  {{SEVERITY}}          — Critical / High / Medium / Low
  {{DATE_DETECTED}}     — ISO-8601 date/time in UTC (e.g. 2026-06-18 14:32 UTC)
  {{DATE_CONTAINED}}    — ISO-8601 date/time or "Ongoing"
  {{AFFECTED_ACCOUNTS}} — AWS account IDs or aliases, comma-separated
  {{AFFECTED_REGIONS}}  — AWS regions (e.g. us-east-1, eu-west-1)
  {{THREAT_ACTOR}}      — Attribution if known, or "Unknown Threat Actor"
  {{BUSINESS_IMPACT}}   — One-sentence plain-language impact statement
  {{AUTHOR}}            — Your name and title
AWS-specific tip: Pull account aliases from AWS Organizations before filling out Affected Scope.
-->

# Security Incident Executive Briefing

| Field | Value |
|---|---|
| **Incident ID** | {{INCIDENT_ID}} |
| **Severity** | {{SEVERITY}} |
| **Status** | {{STATUS}} <!-- Open / Contained / Closed --> |
| **Detected** | {{DATE_DETECTED}} UTC |
| **Contained** | {{DATE_CONTAINED}} UTC |
| **Prepared By** | {{AUTHOR}} |
| **Report Date** | {{REPORT_DATE}} UTC |

---

## Executive Summary

{{EXECUTIVE_SUMMARY_1_3_SENTENCES}}
<!-- Example: "On {{DATE_DETECTED}}, automated detection identified unauthorized API activity in AWS account {{AFFECTED_ACCOUNTS}}. The activity is consistent with {{THREAT_TYPE}} and was contained by {{DATE_CONTAINED}}. No customer data exposure has been confirmed at this time." -->

**Threat Actor:** {{THREAT_ACTOR}}
**Initial Access Vector:** {{INITIAL_ACCESS_VECTOR}} <!-- e.g. Compromised IAM access key, Phishing, Misconfigured S3 -->

---

## Business Impact

**Overall Business Impact:** {{BUSINESS_IMPACT}}

| Impact Category | Assessment |
|---|---|
| Customer Data Exposure | {{CUSTOMER_DATA_IMPACT}} <!-- None / Possible / Confirmed --> |
| Service Availability | {{SERVICE_AVAILABILITY_IMPACT}} <!-- Unaffected / Degraded / Down --> |
| Financial Exposure | {{FINANCIAL_EXPOSURE}} <!-- None / Under Investigation / Estimated $X --> |
| Regulatory / Compliance | {{REGULATORY_IMPACT}} <!-- None / GDPR notification required / etc. --> |
| Reputational Risk | {{REPUTATIONAL_RISK}} <!-- Low / Medium / High --> |

---

## Affected Scope

- **AWS Accounts:** {{AFFECTED_ACCOUNTS}}
- **AWS Regions:** {{AFFECTED_REGIONS}}
- **AWS Services:** {{AFFECTED_SERVICES}} <!-- e.g. IAM, EC2, S3, Lambda -->
- **IAM Principals:** {{AFFECTED_PRINCIPALS}} <!-- Usernames, roles, or "Under Investigation" -->
- **Resources at Risk:** {{AFFECTED_RESOURCES}} <!-- S3 buckets, EC2 instances, RDS clusters, etc. -->

---

## Response Timeline

| Time (UTC) | Event |
|---|---|
| {{DATE_DETECTED}} | Alert triggered — {{DETECTION_SOURCE}} <!-- e.g. GuardDuty, CloudTrail anomaly --> |
| {{TIME_T1}} | Analyst acknowledged and began triage |
| {{TIME_T2}} | Incident declared; Incident Commander assigned |
| {{TIME_T3}} | {{CONTAINMENT_ACTION_SUMMARY}} |
| {{DATE_CONTAINED}} | Threat contained / Incident closed pending review |

---

## Immediate Actions Taken

1. {{IMMEDIATE_ACTION_1}} <!-- e.g. Disabled compromised IAM access key AKIA... --> 
2. {{IMMEDIATE_ACTION_2}} <!-- e.g. Revoked active sessions via aws iam delete-login-profile --> 
3. {{IMMEDIATE_ACTION_3}} <!-- e.g. Isolated affected EC2 instance i-xxxx via Security Group change --> 
4. {{IMMEDIATE_ACTION_4}} <!-- e.g. Enabled S3 Block Public Access on affected buckets --> 
5. {{IMMEDIATE_ACTION_5}} <!-- Add or remove lines as needed -->

---

## Recommendations

| Priority | Recommendation | Owner | Due Date |
|---|---|---|---|
| P1 | {{RECOMMENDATION_1}} | {{OWNER_1}} | {{DUE_DATE_1}} |
| P2 | {{RECOMMENDATION_2}} | {{OWNER_2}} | {{DUE_DATE_2}} |
| P3 | {{RECOMMENDATION_3}} | {{OWNER_3}} | {{DUE_DATE_3}} |

<!-- Common AWS recommendations: enable MFA delete on S3, enforce MFA for IAM console access,
     enable AWS Config rules, rotate all long-lived access keys, enable CloudTrail in all regions -->

---

*This report is CONFIDENTIAL. Distribution is limited to authorized personnel only.*
*For technical details refer to Analyst Report {{INCIDENT_ID}}-ANALYST.*
