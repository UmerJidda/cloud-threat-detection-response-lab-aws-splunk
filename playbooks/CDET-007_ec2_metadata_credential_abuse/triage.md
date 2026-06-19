---
detection_id: CDET-007
detection_name: EC2 Metadata Credential Abuse
tactic: Credential Access
technique: T1552.005
last_updated: 2026-06-18
---

# CDET-007 — EC2 Metadata Credential Abuse: Triage

**Time target:** 5–10 minutes  
**Goal:** Confirm whether the alert is a real incident or a benign false positive, and determine escalation priority.

---

## 1. Retrieve the Raw Alert

1. Open the triggering Splunk alert or SIEM event for CDET-007.
2. Confirm the alert fired on an `AssumeRole` event, not a different STS call.
3. Note the following fields before doing anything else:

| Field | Where to find it |
|---|---|
| `userIdentity.sessionContext.ec2RoleArn` | CloudTrail event JSON |
| `sourceIPAddress` | CloudTrail `sourceIPAddress` field |
| `userAgent` | CloudTrail `userAgent` field |
| `requestParameters.roleArn` | CloudTrail `requestParameters` |
| `responseElements.assumedRoleUser.arn` | CloudTrail `responseElements` |
| `eventTime` | CloudTrail `eventTime` (UTC) |
| `awsRegion` | CloudTrail `awsRegion` |
| `recipientAccountId` | CloudTrail `recipientAccountId` |

---

## 2. Validate — Not Test Data or Known Pipeline Actor

4. Check whether the source IP is an internal CIDR or a known automation range:
   - Cross-reference `sourceIPAddress` against `splunk/lookups/trusted_cidr_ranges.csv`.
   - If the IP is listed as `trusted=true`, note the owner and proceed to step 6.

5. Check whether the IAM role ARN is a known CI/CD or automation role:
   - Cross-reference `userIdentity.sessionContext.ec2RoleArn` against `splunk/lookups/known_automation_roles.csv`.
   - If matched and `auto_approve=true`, this is likely a benign FP — document and close.

6. Confirm the EC2 instance that holds this role actually exists and is running:

```bash
aws ec2 describe-instances \
  --filters "Name=iam-instance-profile.arn,Values=<instance-profile-arn>" \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,IP:PublicIpAddress,LaunchTime:LaunchTime}' \
  --output table
```

7. Verify the `sourceIPAddress` in the `AssumeRole` event does NOT match the EC2 instance's own public IP. If the IP differs, that is the core indicator of compromise.

---

## 3. Determine Urgency

8. Answer each question; a single YES escalates immediately:

- [ ] Is `sourceIPAddress` a known threat-intel hit? (check `splunk/lookups/threat_intel_ips.csv`)
- [ ] Did the assumed role have broad permissions (e.g., `AdministratorAccess`, `PowerUserAccess`, or wildcard `sts:AssumeRole`)?
- [ ] Was the `AssumeRole` followed within 5 minutes by `GetCallerIdentity`, `ListBuckets`, `DescribeInstances`, or `ListRoles`? (reconnaissance pattern)
- [ ] Is the target account a production account?
- [ ] Has this role been assumed from this IP more than once in the last 24 hours?

9. If **two or more** boxes are checked, **escalate to Tier 3 / IR lead immediately** before continuing investigation.

---

## 4. CloudTrail Fields to Examine at Triage

Focus on these specific fields in the raw CloudTrail JSON for the triggering event:

```
eventName          → must be "AssumeRole"
eventSource        → must be "sts.amazonaws.com"
userIdentity.type  → should be "AssumedRole" with an EC2 instance profile
userIdentity.sessionContext.sessionIssuer.type → "Role"
userIdentity.sessionContext.sessionIssuer.arn  → the EC2 instance role ARN
sourceIPAddress    → compare to EC2's own public IP
userAgent          → "aws-sdk-*" or "python-boto3" is normal; curl/wget/custom is suspicious
```

---

## 5. PASS / FAIL Criteria

### PASS — Benign False Positive

All of the following must be true:

- `sourceIPAddress` matches the EC2 instance's own Elastic IP or is listed in `trusted_cidr_ranges.csv`
- The role ARN is in `known_automation_roles.csv` with `auto_approve=true`
- No subsequent reconnaissance API calls within 10 minutes
- `userAgent` matches a known SDK pattern for this workload

**Action:** Document the event, add a suppression note in the detection tuning log, close the alert.

### FAIL — Real Alert (Proceed to Investigation)

Any of the following is true:

- `sourceIPAddress` is external and does not match the EC2 instance's public IP
- Role ARN is not in the automation allowlist
- `userAgent` is `curl`, `python-requests`, a Kali/pentesting tool, or empty
- Reconnaissance API calls follow the `AssumeRole` event
- IP appears in `threat_intel_ips.csv`

**Action:** Proceed to `investigation.md`. Do not revoke credentials or stop the instance yet.

---

## 6. Lookup CSVs Referenced

| CSV | Purpose |
|---|---|
| `splunk/lookups/trusted_cidr_ranges.csv` | Known internal and automation IP ranges |
| `splunk/lookups/known_automation_roles.csv` | CI/CD and pipeline roles exempt from this detection |
| `splunk/lookups/threat_intel_ips.csv` | Known malicious IPs from threat feeds |
| `splunk/lookups/iam_role_sensitivity.csv` | Role ARN to sensitivity tier mapping |

---

## 7. Escalation Contacts

- **Tier 3 / IR Lead:** Follow your org's escalation runbook.
- **AWS Account Owner:** Identified via `splunk/lookups/account_owners.csv` keyed on `recipientAccountId`.
- **On-call:** Page via standard on-call rotation if production account is confirmed affected.

> CDET-007 triage complete. Move to `investigation.md` if alert is FAIL.
