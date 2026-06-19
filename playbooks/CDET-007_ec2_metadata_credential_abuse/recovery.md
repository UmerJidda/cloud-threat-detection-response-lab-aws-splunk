---
detection_id: CDET-007
detection_name: EC2 Metadata Credential Abuse
tactic: Credential Access
technique: T1552.005
last_updated: 2026-06-18
---

# CDET-007 — EC2 Metadata Credential Abuse: Recovery

**Audience:** Tier-2 SOC analyst with AWS experience  
**Prerequisites:** Containment complete; IR Lead notified; blast radius fully documented

---

## 1. Verify the Threat Has Been Fully Removed

Before restoring normal operations, confirm all attacker-controlled access paths are closed.

### 1a. Confirm the stolen credential is no longer usable

```bash
# Check whether CDET-007-IncidentRevoke policy is still attached
aws iam get-role-policy \
  --role-name "<role-name>" \
  --policy-name "CDET-007-IncidentRevoke-<date>"
```

- Confirm `DateLessThan` condition covers the period of the incident.
- Run Splunk query to verify no successful API calls from `<attacker_ip>` in the last 30 minutes:

```spl
index=aws_cloudtrail sourceIPAddress="<attacker_ip>" errorCode!="AccessDenied"
  earliest=-30m
| table _time, eventName, sourceIPAddress, userIdentity.arn, errorCode
```

If any rows return with `errorCode` empty or `None`, the attacker has a second credential. Escalate immediately.

### 1b. Check for new IAM entities created during the incident

```bash
# List all IAM users created in the incident window
aws iam list-users \
  --query "Users[?CreateDate>='<T0>'].{User:UserName,Created:CreateDate,ARN:Arn}" \
  --output table

# List all IAM roles created in the incident window
aws iam list-roles \
  --query "Roles[?CreateDate>='<T0>'].{Role:RoleName,Created:CreateDate,ARN:Arn}" \
  --output table

# List all access keys created after T=0
aws iam list-users --query 'Users[*].UserName' --output text | \
  tr '\t' '\n' | while read USER; do
    aws iam list-access-keys --user-name "$USER" \
      --query "AccessKeyMetadata[?CreateDate>='<T0>'].{User:UserName,Key:AccessKeyId,Status:Status,Created:CreateDate}" \
      --output text
  done
```

Delete any entities that cannot be attributed to a known legitimate change:

```bash
# Disable suspicious access key before deleting (safer — allows review)
aws iam update-access-key \
  --user-name "<username>" \
  --access-key-id "<key-id>" \
  --status Inactive

# After confirming it is attacker-created:
aws iam delete-access-key \
  --user-name "<username>" \
  --access-key-id "<key-id>"
```

### 1c. Verify no persistent backdoor mechanisms were installed

```spl
index=aws_cloudtrail
  (eventName=CreateUser OR eventName=CreateRole OR eventName=AttachRolePolicy
   OR eventName=PutRolePolicy OR eventName=CreateLoginProfile
   OR eventName=UpdateAssumeRolePolicy OR eventName=AddUserToGroup)
  userIdentity.accessKeyId="<stolen_access_key_id>"
| table _time, eventName, requestParameters
| sort _time
```

Investigate every hit. Compare against expected change management tickets.

### 1d. Verify no S3 data was exfiltrated

```spl
index=aws_cloudtrail eventName=GetObject sourceIPAddress="<attacker_ip>"
| stats count, sum(eval(tonumber(requestParameters.bytesReturned))) as total_bytes
    by requestParameters.bucketName
| sort -total_bytes
```

For any bucket with hits, review the objects accessed and classify the data sensitivity. If PII or regulated data was accessed, trigger your data breach notification process.

---

## 2. Restore Normal Operations

### 2a. Replace the compromised EC2 instance (recommended path)

The safest recovery is to terminate the compromised instance and launch a replacement from a clean AMI. This eliminates any persistence the attacker may have established on the host.

```bash
# Launch replacement from approved AMI
aws ec2 run-instances \
  --image-id "<approved-ami-id>" \
  --instance-type "<instance-type>" \
  --subnet-id "<subnet-id>" \
  --security-group-ids "<original-sg-id>" \
  --iam-instance-profile Name="<instance-profile-name>" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=<name>},{Key=incident-replaced,Value=CDET-007}]" \
  --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled"
```

After the replacement is healthy, terminate the original:

```bash
# IR Lead approval required
aws ec2 terminate-instances --instance-ids "<original-instance-id>"
```

### 2b. If the instance must be reused (not recommended)

If the instance cannot be replaced (e.g., it holds stateful data not yet migrated to EBS), at minimum:

1. Restore the instance from the forensic snapshot taken during containment.
2. Patch the vulnerability that allowed the initial compromise.
3. Enforce IMDSv2 (confirmed in containment step 4).
4. Re-run your AMI hardening baseline and verify with AWS Inspector.

### 2c. Restore the IAM role to a clean state

1. Remove the CDET-007 incident revocation policy:

```bash
aws iam delete-role-policy \
  --role-name "<role-name>" \
  --policy-name "CDET-007-IncidentRevoke-<date>"
```

2. Review and tighten the role's attached policies — apply least-privilege. If the role had `AdministratorAccess`, replace it with a scoped policy.

3. Remove the isolation security group from the VPC if it is no longer needed:

```bash
aws ec2 delete-security-group --group-id "$ISOLATION_SG"
```

4. Remove the NACL deny rules added during containment (if the new instance has a different IP and the rules are no longer relevant):

```bash
aws ec2 delete-network-acl-entry --network-acl-id "$NACL_ID" --rule-number 1 --ingress
aws ec2 delete-network-acl-entry --network-acl-id "$NACL_ID" --rule-number 1 --egress
```

---

## 3. Hardening Steps to Prevent Recurrence

### 3a. Enforce IMDSv2 account-wide (closes the root SSRF/IMDS vector)

```bash
# Set account-level default to require IMDSv2 for all new instances
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Audit existing instances still using IMDSv1
aws ec2 describe-instances \
  --filters "Name=metadata-options.http-tokens,Values=optional" \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,Name:Tags[?Key==`Name`]|[0].Value}' \
  --output table
```

### 3b. Apply least-privilege to EC2 instance roles

- Audit every EC2 instance role with `sts:AssumeRole` permission. Remove it unless the workload explicitly requires role chaining.
- Replace broad managed policies (`AmazonEC2FullAccess`, `AmazonS3FullAccess`) with scoped resource-level policies.

### 3c. Enable GuardDuty findings for credential exfiltration

Ensure the following GuardDuty finding types are enabled and alert to your SIEM:

- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
- `CredentialAccess:IAMUser/AnomalousBehavior`
- `Recon:IAMUser/MaliciousIPCaller`

```bash
aws guardduty list-detectors --query 'DetectorIds' --output text | \
  xargs -I{} aws guardduty get-detector --detector-id {}
```

Verify `Status: ENABLED` and `FindingPublishingFrequency: FIFTEEN_MINUTES` or `SIX_HOURS`.

### 3d. Implement SCP to restrict AssumeRole from non-EC2 IPs (if applicable)

If your organization uses AWS Organizations, add a Service Control Policy to deny `sts:AssumeRole` using EC2 instance credentials from outside known CIDR ranges:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyEC2RoleUseOutsideAWS",
    "Effect": "Deny",
    "Action": "sts:AssumeRole",
    "Resource": "*",
    "Condition": {
      "NotIpAddress": {
        "aws:SourceIp": ["<trusted-cidr-1>", "<trusted-cidr-2>"]
      },
      "StringEquals": {
        "aws:PrincipalType": "AssumedRole"
      }
    }
  }]
}
```

Consult with the platform team before applying SCPs — they affect all accounts in the OU.

### 3e. Patch the root cause

Determine how the attacker reached the IMDS endpoint:

| Root Cause | Remediation |
|---|---|
| SSRF in web application | Patch the SSRF vulnerability; enforce IMDSv2 (hop limit=1 blocks SSRF) |
| RCE via unpatched software | Patch and rebuild from clean AMI; enable AWS Inspector for continuous scanning |
| Exposed SSH / RDP | Restrict security group; use SSM Session Manager instead of direct SSH |
| Compromised developer laptop with AWS credentials | Rotate all developer access keys; enforce MFA |
| Insider threat | HR and legal involvement; audit all access for the user |

---

## 4. Detection Tuning Recommendations

### 4a. Suppression (reduce FP noise)

Add the following to `splunk/lookups/known_automation_roles.csv` if investigation revealed a legitimate use case:

- CI/CD roles that legitimately assume cross-account roles from a fixed NAT IP — add IP + role combination with `auto_approve=true`.
- Only suppress after documenting the business justification and getting IR Lead sign-off.

### 4b. Enrichment (improve signal quality)

Enrich CDET-007 alerts with:

1. **Instance metadata at alert time:** Add EC2 instance name, owner tag, environment tag to the alert.
2. **IP reputation:** Auto-lookup `sourceIPAddress` in `threat_intel_ips.csv` and append `threat_score`.
3. **Role sensitivity tier:** Look up the role ARN in `iam_role_sensitivity.csv` and include `sensitivity_tier` in the alert.
4. **Velocity:** Add a count of how many times this IP has triggered CDET-007 in the last 7 days.

### 4c. Threshold adjustments

If CDET-007 is firing on legitimate cross-account role use from a peered VPC or Transit Gateway with a non-EC2 egress IP, consider adding a `sourceIPAddress` filter using `NOT IN` with the trusted CIDR lookup rather than suppressing the entire role.

---

## 5. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

**Timeline and Scope**
- [ ] Full attack timeline documented from initial access to detection to containment
- [ ] Dwell time calculated (time from initial compromise to CDET-007 alert)
- [ ] Blast radius confirmed — all attacker-touched resources identified

**Root Cause**
- [ ] Initial access vector identified (SSRF / RCE / other)
- [ ] Root cause document written and shared with platform/application team
- [ ] Vulnerability patched or mitigated and verified

**Detection and Response**
- [ ] Time to detect (alert fire time minus attack start time) recorded
- [ ] Time to contain recorded
- [ ] CDET-007 detection rule reviewed — did it fire at the right time? Any missed events?
- [ ] Any detection gaps identified for follow-on attacker actions (lateral movement, exfil)?
- [ ] Suppression or enrichment changes applied per section 4

**Hardening**
- [ ] IMDSv2 enforced on the affected instance and account default updated
- [ ] EC2 instance role policies scoped to least-privilege
- [ ] GuardDuty `InstanceCredentialExfiltration` finding verified active
- [ ] Replacement instance rebuilt from clean AMI (if applicable)

**Evidence and Compliance**
- [ ] All evidence artifacts stored in IR S3 case folder with Object Lock
- [ ] Evidence retention confirmed per your organization's retention policy
- [ ] Data breach assessment completed (if PII/regulated data was accessed)
- [ ] Incident ticket updated with all findings and closed

**Process Improvement**
- [ ] Lessons learned documented
- [ ] Playbook gaps identified — update `triage.md`, `investigation.md`, `containment.md`, or `recovery.md` as needed
- [ ] Detection engineering backlog updated with any new detection ideas

> CDET-007 recovery complete. Incident closed.
