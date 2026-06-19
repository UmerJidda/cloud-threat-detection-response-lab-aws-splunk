---
template_version: 1.0
last_updated: 2026-06-18
audience: analyst
---

<!--
COMPLETION GUIDE
================
Time to complete: 45–90 minutes
Who fills this out: Tier-2 Security Analyst or Incident Responder
How to use:
  1. Replace all {{PLACEHOLDER}} tokens with investigation findings.
  2. Paste CloudTrail event JSON directly into the Evidence Collected code blocks.
  3. Populate the Event Timeline table in chronological order (UTC only).
  4. Record every pivot query in the Pivot Query Log — this is your audit trail.
  5. Tag the ticket with MITRE ATT&CK technique IDs where applicable.
AWS tool reference:
  - CloudTrail Lake / S3 log queries
  - GuardDuty finding detail: aws guardduty get-findings --detector-id ... --finding-ids ...
  - IAM credential report: aws iam generate-credential-report && aws iam get-credential-report
  - VPC Flow Logs in CloudWatch Logs Insights
-->

# Tier-2 Analyst Technical Incident Report

| Field | Value |
|---|---|
| **Incident ID** | {{INCIDENT_ID}} |
| **Severity** | {{SEVERITY}} |
| **MITRE ATT&CK Tactics** | {{MITRE_TACTICS}} <!-- e.g. Initial Access (TA0001), Persistence (TA0003) --> |
| **Detection Source** | {{DETECTION_SOURCE}} <!-- GuardDuty / CloudTrail / Custom Detection Rule / SIEM --> |
| **Analyst** | {{ANALYST_NAME}} |
| **Analysis Start** | {{ANALYSIS_START_UTC}} UTC |
| **Report Version** | {{REPORT_VERSION}} <!-- e.g. 1.0 Draft, 1.1 Final --> |

---

## Detection Summary

**Alert Name:** {{ALERT_NAME}}
**Alert ID / Finding ARN:** {{ALERT_ID}}
**Triggering Rule / GuardDuty Finding Type:** {{FINDING_TYPE}}
<!-- e.g. UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B, Recon:IAMUser/MaliciousIPCaller -->

**Triage Assessment:** {{TRIAGE_ASSESSMENT}} <!-- True Positive / False Positive / Benign Positive -->

**Confidence:** {{CONFIDENCE}} <!-- High / Medium / Low -->

**Summary:**
{{DETECTION_SUMMARY_PARAGRAPH}}
<!-- Describe what the detection fired on, what data source triggered it, and initial analyst assessment. -->

---

## Principal Context

| Attribute | Value |
|---|---|
| **IAM Principal ARN** | {{PRINCIPAL_ARN}} |
| **Principal Type** | {{PRINCIPAL_TYPE}} <!-- IAM User / IAM Role / Federated User / Service Account --> |
| **AWS Account ID** | {{AWS_ACCOUNT_ID}} |
| **Account Alias** | {{AWS_ACCOUNT_ALIAS}} |
| **AWS Region** | {{AWS_REGION}} |
| **Source IP** | {{SOURCE_IP}} |
| **IP Geolocation** | {{IP_GEO}} <!-- Country, ASN, ISP --> |
| **User Agent** | {{USER_AGENT}} <!-- e.g. aws-cli/2.x Boto3/1.x --> |
| **MFA Used** | {{MFA_USED}} <!-- Yes / No / Unknown --> |
| **Key Created Date** | {{KEY_CREATED_DATE}} |
| **Last Key Rotation** | {{LAST_KEY_ROTATION}} |
| **Key Still Active** | {{KEY_ACTIVE}} <!-- Yes / No / Disabled by IR --> |

---

## Event Timeline

All times in UTC. Source columns reference CloudTrail `eventSource` and `eventName`.

| Time (UTC) | Source IP | IAM Principal | AWS Service | API Call | Region | Outcome | Notes |
|---|---|---|---|---|---|---|---|
| {{TIME_1}} | {{IP_1}} | {{PRINCIPAL_1}} | {{SERVICE_1}} | {{API_1}} | {{REGION_1}} | {{OUTCOME_1}} | {{NOTES_1}} |
| {{TIME_2}} | {{IP_2}} | {{PRINCIPAL_2}} | {{SERVICE_2}} | {{API_2}} | {{REGION_2}} | {{OUTCOME_2}} | {{NOTES_2}} |
| {{TIME_3}} | {{IP_3}} | {{PRINCIPAL_3}} | {{SERVICE_3}} | {{API_3}} | {{REGION_3}} | {{OUTCOME_3}} | {{NOTES_3}} |
| {{TIME_N}} | ... | ... | ... | ... | ... | ... | Add rows as needed |

<!-- CloudTrail field map: eventTime → Time, sourceIPAddress → Source IP, userIdentity.arn → IAM Principal,
     eventSource → AWS Service, eventName → API Call, awsRegion → Region, errorCode → Outcome -->

---

## Indicators of Compromise

### IP Addresses
| IP Address | Type | Reputation | First Seen | Last Seen |
|---|---|---|---|---|
| {{IOC_IP_1}} | {{IOC_IP_TYPE_1}} <!-- Source / C2 / Exfil dest --> | {{IOC_IP_REP_1}} <!-- Malicious / Suspicious / Unknown --> | {{IOC_FIRST_1}} | {{IOC_LAST_1}} |
| {{IOC_IP_2}} | {{IOC_IP_TYPE_2}} | {{IOC_IP_REP_2}} | {{IOC_FIRST_2}} | {{IOC_LAST_2}} |

### IAM Artifacts
| Type | Value | Status |
|---|---|---|
| Access Key ID | {{COMPROMISED_KEY_ID}} | {{KEY_STATUS}} <!-- Active / Disabled / Deleted --> |
| IAM User / Role | {{COMPROMISED_PRINCIPAL}} | {{PRINCIPAL_STATUS}} |
| Rogue Policy ARN | {{ROGUE_POLICY_ARN}} <!-- if attacker created a policy --> | {{POLICY_STATUS}} |
| Rogue Role ARN | {{ROGUE_ROLE_ARN}} <!-- if attacker created a role --> | {{ROLE_STATUS}} |

### AWS Resources
| Resource Type | Resource ID / ARN | Status |
|---|---|---|
| {{RESOURCE_TYPE_1}} <!-- e.g. S3 Bucket --> | {{RESOURCE_ID_1}} | {{RESOURCE_STATUS_1}} <!-- Isolated / Deleted / Monitoring --> |
| {{RESOURCE_TYPE_2}} | {{RESOURCE_ID_2}} | {{RESOURCE_STATUS_2}} |

---

## Evidence Collected

### CloudTrail Event — Initial Suspicious Call

```json
{{CLOUDTRAIL_EVENT_1_JSON}}
```

### CloudTrail Event — Privilege Escalation / Lateral Movement

```json
{{CLOUDTRAIL_EVENT_2_JSON}}
```

### GuardDuty Finding (JSON)

```json
{{GUARDDUTY_FINDING_JSON}}
```

### Supporting Artifact

```
{{SUPPORTING_ARTIFACT}}
<!-- Paste VPC Flow Log entry, S3 access log line, Lambda log snippet, etc. -->
```

### IAM Credential Report Excerpt

```csv
{{IAM_CREDENTIAL_REPORT_ROWS}}
<!-- user,arn,user_creation_time,password_enabled,...,access_key_1_last_used_date,... -->
```

---

## Root Cause Analysis

**Root Cause:** {{ROOT_CAUSE_STATEMENT}}
<!-- e.g. "Long-lived IAM access key exposed in a public GitHub repository was discovered and used by a threat actor." -->

**Contributing Factors:**
- {{CONTRIBUTING_FACTOR_1}} <!-- e.g. No key rotation policy enforced via AWS Config -->
- {{CONTRIBUTING_FACTOR_2}} <!-- e.g. No MFA enforced for IAM users -->
- {{CONTRIBUTING_FACTOR_3}}

**MITRE ATT&CK Technique Mapping:**
| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| {{TACTIC_1}} | {{TECHNIQUE_ID_1}} | {{TECHNIQUE_NAME_1}} | {{TECHNIQUE_EVIDENCE_1}} |
| {{TACTIC_2}} | {{TECHNIQUE_ID_2}} | {{TECHNIQUE_NAME_2}} | {{TECHNIQUE_EVIDENCE_2}} |

---

## Containment Actions

| Time (UTC) | Action | Performed By | AWS CLI / Console Command |
|---|---|---|---|
| {{CONTAIN_TIME_1}} | {{CONTAIN_ACTION_1}} | {{CONTAIN_BY_1}} | `{{CONTAIN_CMD_1}}` |
| {{CONTAIN_TIME_2}} | {{CONTAIN_ACTION_2}} | {{CONTAIN_BY_2}} | `{{CONTAIN_CMD_2}}` |
| {{CONTAIN_TIME_3}} | {{CONTAIN_ACTION_3}} | {{CONTAIN_BY_3}} | `{{CONTAIN_CMD_3}}` |

<!-- Common AWS containment commands:
     Disable access key:  aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name ...
     Attach deny policy:  aws iam put-user-policy --user-name ... --policy-name DenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
     Isolate EC2:         aws ec2 modify-instance-attribute --instance-id i-... --groups sg-isolation
     Revoke STS session:  aws iam delete-role-permissions-boundary / invalidate sessions via new deny inline policy -->

---

## Recovery Steps

1. {{RECOVERY_STEP_1}} <!-- e.g. Issue new access key to legitimate owner after identity verification -->
2. {{RECOVERY_STEP_2}} <!-- e.g. Restore S3 bucket policy to last known-good state -->
3. {{RECOVERY_STEP_3}} <!-- e.g. Re-enable CloudTrail logging if it was disabled by attacker -->
4. {{RECOVERY_STEP_4}}
5. {{RECOVERY_STEP_5}}

**Recovery Verified By:** {{RECOVERY_VERIFIER}}
**Recovery Verified At:** {{RECOVERY_VERIFIED_UTC}} UTC

---

## Lessons Learned

| Category | Finding | Recommended Control |
|---|---|---|
| Detection | {{LL_DETECTION_GAP}} | {{LL_DETECTION_CONTROL}} |
| Prevention | {{LL_PREVENTION_GAP}} | {{LL_PREVENTION_CONTROL}} |
| Response | {{LL_RESPONSE_GAP}} | {{LL_RESPONSE_CONTROL}} |
| Tooling | {{LL_TOOLING_GAP}} | {{LL_TOOLING_CONTROL}} |

---

## Pivot Query Log

Record every search query run during the investigation. This is a mandatory audit trail.

| # | Time (UTC) | Platform | Query | Purpose | Result Summary |
|---|---|---|---|---|---|
| 1 | {{PIVOT_TIME_1}} | {{PIVOT_PLATFORM_1}} <!-- CloudTrail Lake / Splunk / Athena / CloudWatch Insights --> | `{{PIVOT_QUERY_1}}` | {{PIVOT_PURPOSE_1}} | {{PIVOT_RESULT_1}} |
| 2 | {{PIVOT_TIME_2}} | {{PIVOT_PLATFORM_2}} | `{{PIVOT_QUERY_2}}` | {{PIVOT_PURPOSE_2}} | {{PIVOT_RESULT_2}} |
| 3 | {{PIVOT_TIME_3}} | {{PIVOT_PLATFORM_3}} | `{{PIVOT_QUERY_3}}` | {{PIVOT_PURPOSE_3}} | {{PIVOT_RESULT_3}} |

---

*Classification: CONFIDENTIAL — Internal Security Use Only*
*Cross-reference: Executive Briefing {{INCIDENT_ID}}-EXEC | Ticket: {{TICKET_URL}}*
