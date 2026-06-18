# Incident Response Playbook Template

> Copy this template to `incident_response/playbooks/{CDET-NNN}_{short_name}.md`.
> Remove this instruction block before committing.

---

# Playbook: [Detection Name]

**Detection ID:** CDET-NNN
**Tactic:** [MITRE ATT&CK Tactic]
**Technique:** [T1NNN.NNN — Technique Name]
**Severity:** critical / high / medium / low
**Last Reviewed:** YYYY-MM-DD

---

## 1. Detection Summary

**What fired:**
[One sentence describing the detection trigger — e.g., "A new IAM user was created by a principal not in the approved provisioning pipeline."]

**Why this matters:**
[One paragraph explaining the threat scenario this detection is designed to catch. Include the adversary objective (persistence, privilege escalation, etc.) and the potential business impact.]

**Expected true positive rate:** [high / medium / low — based on validation data]

---

## 2. Triage Checklist

Complete these steps before escalating or taking containment actions. The goal is to confirm or dismiss within the response SLA.

- [ ] Identify the principal ARN that triggered the alert
- [ ] Check if the principal is in any suppression lookup (`approved_iam_principals.csv`, `automation_role_arns.csv`)
- [ ] Check if the source IP is in `approved_cidr_ranges.csv`
- [ ] Verify the event time — is this during a known change window?
- [ ] Look for a corresponding change ticket or deployment pipeline run
- [ ] Check GuardDuty for concurrent findings on the same principal or resource
- [ ] Check if this principal has any history of similar activity

**False Positive Indicators:**
- [e.g., Source IP matches known CI/CD platform egress range]
- [e.g., Event time matches a scheduled Terraform plan/apply window]
- [e.g., Principal ARN matches a known automation role]

**True Positive Indicators:**
- [e.g., Source IP is outside all known corporate/VPN ranges]
- [e.g., Principal has no history of this API call]
- [e.g., Event occurred at an unexpected time (e.g., 03:00 UTC)]

---

## 3. Investigation Queries

### Splunk — Activity Timeline for Affected Principal

```spl
index=aws_cloudtrail userIdentity.arn="[AFFECTED_ARN]"
| sort _time
| table _time, eventName, eventSource, sourceIPAddress, awsRegion, errorCode, userAgent
```

### Splunk — All Activity from Source IP

```spl
index=aws_cloudtrail sourceIPAddress="[SOURCE_IP]"
| sort _time
| table _time, eventName, userIdentity.arn, awsRegion, errorCode
```

### Splunk — Recent GuardDuty Findings

```spl
index=aws_alerts sourcetype="aws:guardduty:finding"
| where 'service.action.networkConnectionAction.remoteIpDetails.ipAddressV4'="[SOURCE_IP]"
   OR resource.instanceDetails.instanceId="[RESOURCE_ID]"
| table _time, title, severity, type, description
```

### AWS CLI — Current IAM State for Affected Principal

```bash
# Get current user details
aws iam get-user --user-name [USERNAME]

# List access keys and their status
aws iam list-access-keys --user-name [USERNAME]

# List attached policies
aws iam list-attached-user-policies --user-name [USERNAME]

# List group memberships
aws iam list-groups-for-user --user-name [USERNAME]
```

### AWS CLI — Collect Fresh IAM Snapshot

```bash
python -m scripts.aws_collectors.collect_cli --collector iam \
  --region [REGION] --output-dir data/investigation/
```

---

## 4. Evidence Preservation

**Preserve before any containment action that modifies state.**

- [ ] Export CloudTrail events for affected principal (see Investigation Queries above)
- [ ] Capture current IAM state for affected principal
- [ ] Screenshot or export GuardDuty findings
- [ ] Record all access key IDs and their creation/last-used timestamps
- [ ] Note the current policy attachments for the principal
- [ ] Capture Security Hub findings if relevant

---

## 5. Containment Actions

**Always confirm with a senior analyst before taking containment actions.**

### Option A — Disable Access Key (least disruptive)

```bash
aws iam update-access-key \
  --user-name [USERNAME] \
  --access-key-id [KEY_ID] \
  --status Inactive
```

### Option B — Revoke Active Sessions (immediate)

```bash
# Attach policy that denies all actions for sessions issued before this moment
aws iam put-user-policy \
  --user-name [USERNAME] \
  --policy-name DenyAllUntilReviewed \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "[CURRENT_TIMESTAMP_ISO8601]"
        }
      }
    }]
  }'
```

### Option C — Delete Access Key (permanent, use only if compromise confirmed)

```bash
aws iam delete-access-key \
  --user-name [USERNAME] \
  --access-key-id [KEY_ID]
```

---

## 6. Escalation Criteria

Escalate to senior security staff or incident commander if:

- [ ] The affected principal has administrative permissions
- [ ] Evidence of successful data access or exfiltration
- [ ] Multiple principals or accounts are affected
- [ ] Containment actions are not available (insufficient response permissions)
- [ ] The source IP belongs to a known threat actor
- [ ] SLA for this severity has elapsed without resolution

---

## 7. Recovery Steps

After confirmed containment:

- [ ] Rotate any credentials that may have been exposed
- [ ] Audit all actions taken by the compromised principal during the incident window
- [ ] Verify no persistent access mechanisms were established (new users, new keys, new role trust relationships)
- [ ] Re-enable services or restore configurations modified during containment
- [ ] Re-run collectors to verify clean post-incident state

```bash
python -m scripts.aws_collectors.collect_cli --all \
  --region [REGION] --output-dir data/investigation/post_containment/
```

---

## 8. Reporting Obligations

| Obligation | Trigger | Timeline | Owner |
|------------|---------|----------|-------|
| Internal escalation | Any confirmed true positive | Immediate | Analyst |
| Management notification | HIGH or CRITICAL confirmed TP | Within 1 hour | Incident Commander |
| [Regulatory notification] | [Specific data exposure criteria] | [Per regulation] | Legal/Compliance |

---

## 9. Post-Incident Lessons Learned

After the incident is closed, answer the following:

1. Was the detection effective? Did it fire at the right time with sufficient context?
2. Was the playbook sufficient? Were any investigation steps missing?
3. Was containment achievable within the SLA? What slowed response?
4. Should any suppression rules be added or removed?
5. Should this detection's severity or confidence be adjusted?
6. Are there related detection gaps that this incident revealed?

Document answers in the incident report using `templates/incident_report_template.md`.

---

## 10. Related Detections

| Detection ID | Name | Relationship |
|-------------|------|-------------|
| [CDET-NNN] | [Name] | [e.g., Often co-fires with this detection] |
