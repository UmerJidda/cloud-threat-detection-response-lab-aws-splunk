---
detection_id: CDET-011
detection_name: Unauthorized EC2 Instance Launch
tactic: Impact
technique: T1496
last_updated: 2026-06-18
---

# CDET-011 — Recovery Playbook

**Audience:** Tier-2 SOC analyst and IR lead.  
**Prerequisite:** Containment actions from `containment.md` are complete and confirmed.

---

## 1. Verify Threat is Fully Removed

Before restoring normal operations, confirm that no attacker-controlled resources remain active.

### 1a. Confirm all attacker-launched instances are stopped or terminated

```bash
# Check each identified instance ID
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID_1> <INSTANCE_ID_2> \
  --region <REGION> \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,LaunchTime:LaunchTime}'
```

Expected state: `stopped` or `terminated` for all attacker-launched instances.

### 1b. Confirm IAM actor is still blocked

```bash
# Verify deny policy is in place (until account owner confirms clean state)
aws iam list-user-policies --user-name <USERNAME>
aws iam get-user-policy --user-name <USERNAME> --policy-name CDET-011-ContainmentDenyAll

# Verify access key is still inactive
aws iam list-access-keys --user-name <USERNAME>
```

### 1c. Multi-region scan for any missed instances

```bash
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "=== $region ==="
  aws ec2 describe-instances \
    --region "$region" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,LaunchTime:LaunchTime,KeyName:KeyName}' \
    --output table 2>/dev/null
done
```

Review output for any GPU instances or recently launched instances not belonging to known workloads.

### 1d. Check for persistence mechanisms left by the attacker

```bash
# Check for any IAM roles or users created by the attacker
aws iam list-roles --query 'Roles[?CreateDate>=`<INCIDENT_DATE>`]'
aws iam list-users --query 'Users[?CreateDate>=`<INCIDENT_DATE>`]'

# Check for any new access keys created around the incident time
aws iam list-access-keys --user-name <USERNAME>
```

```spl
index=aws_cloudtrail
  (eventName=CreateUser OR eventName=CreateRole OR eventName=CreateAccessKey
   OR eventName=CreateLoginProfile OR eventName=AddUserToGroup)
  userIdentity.arn="<ATTACKER_ARN>"
  earliest=<INCIDENT_START_TIME>
| table _time, eventName, requestParameters, responseElements
| sort _time
```

---

## 2. Restore Normal Operations

Execute only after Step 1 confirms the threat is fully removed.

### 2a. Rotate the compromised IAM credentials

```bash
# Delete the compromised access key (IR lead approval required)
aws iam delete-access-key \
  --access-key-id <COMPROMISED_KEY_ID> \
  --user-name <USERNAME>

# Issue new access key for the legitimate owner (only if this is a service account)
aws iam create-access-key --user-name <USERNAME>
```

If this was a human user account, do NOT issue a new key until the root cause of the credential leak is confirmed and resolved.

### 2b. Remove the containment deny policy (IR lead approval required)

```bash
aws iam delete-user-policy \
  --user-name <USERNAME> \
  --policy-name CDET-011-ContainmentDenyAll

# OR for a role:
aws iam delete-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name CDET-011-ContainmentDenyAll
```

### 2c. Terminate attacker-launched instances (IR lead approval; after forensic imaging if needed)

```bash
aws ec2 terminate-instances \
  --instance-ids <INSTANCE_ID_1> <INSTANCE_ID_2> \
  --region <REGION>
```

### 2d. Audit and clean up any attacker-created IAM resources

```bash
# Delete any backdoor IAM users created by the attacker
aws iam delete-user --user-name <ATTACKER_CREATED_USER>

# Delete any backdoor roles
aws iam delete-role --role-name <ATTACKER_CREATED_ROLE>

# Delete any additional access keys created by the attacker
aws iam delete-access-key --access-key-id <KEY_ID> --user-name <USERNAME>
```

---

## 3. Hardening Steps to Prevent Recurrence

### 3a. Enforce IMDSv2 on all EC2 instances

IMDSv1 allows credential theft via SSRF. Enforce IMDSv2 organization-wide:

```bash
# Require IMDSv2 on existing instances
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-tokens required \
  --http-endpoint enabled \
  --region <REGION>

# Set account-level default to require IMDSv2 for new instances
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --region <REGION>
```

### 3b. Apply SCP to restrict EC2 instance types

If your organization does not use GPU instances legitimately, use a Service Control Policy to deny their launch:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGPUInstances",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringLike": {
          "ec2:InstanceType": ["p2.*", "p3.*", "p4.*", "g4dn.*", "g5.*", "inf1.*"]
        }
      }
    }
  ]
}
```

### 3c. Apply SCP to restrict EC2 launches to approved regions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnapprovedRegions",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
        }
      }
    }
  ]
}
```

### 3d. Enable AWS Config Rules

Enable the following AWS Config managed rules:

- `ec2-instance-no-public-ip` — flag instances with public IPs in non-DMZ subnets
- `iam-user-unused-credentials-check` — rotate or disable stale credentials
- `access-keys-rotated` — enforce 90-day key rotation
- `guardduty-enabled-centralized` — ensure GuardDuty is active in all regions

### 3e. Enable GuardDuty findings for T1496

Ensure GuardDuty is enabled in all regions and that the following finding types trigger alerts:

- `CryptoCurrency:EC2/BitcoinTool.B`
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- `Recon:IAMUser/MaliciousIPCaller`

### 3f. Remediate the credential exposure root cause

Review how the access key was exposed and address the root cause:

| Likely exposure vector | Remediation |
|---|---|
| Hardcoded in code/GitHub | Scan repos with `git-secrets` or `truffleHog`; rotate all exposed keys |
| EC2 instance metadata (IMDSv1) | Enforce IMDSv2 (Step 3a above) |
| Exposed in S3 object | Audit S3 bucket policies; enable Macie for sensitive data discovery |
| Phishing / social engineering | MFA enforcement; security awareness training |
| Overpermissioned Lambda env var | Move secrets to Secrets Manager; rotate key |

---

## 4. Detection Tuning Recommendations

### 4a. Suppression (reduce false positives)

- Add approved CI/CD pipeline roles to `splunk/lookups/known_service_accounts.csv`
- Add approved regions to `splunk/lookups/approved_regions.csv`
- Add ASG-managed instance launches to an allowlist keyed on the Auto Scaling group name in `requestParameters`

### 4b. Enrichment (improve signal quality)

- Join `RunInstances` events with a GPU instance type lookup table to pre-filter for high-risk types
- Enrich actor ARNs with HR/identity data (role owner, last login, department) at alert time
- Add a field extraction for `requestParameters.userData` decoded content in the Splunk pipeline

### 4c. New detection opportunities identified

| Opportunity | Recommended new detection |
|---|---|
| Mining pool outbound traffic | VPC Flow Log detection on ports 3333, 4444, 14444 |
| IMDSv1 credential theft | CloudTrail `GetMetadata` + unusual subsequent `RunInstances` |
| New IAM entity created then used to launch instances | Sequence detection: `CreateUser`/`CreateRole` → `RunInstances` within 1 hour |

---

## 5. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

**Timeline and Impact:**
- [ ] Full attack timeline documented (T0 credential exposure through T5 recovery)
- [ ] Total EC2 compute costs incurred by attacker calculated and documented
- [ ] Number of regions affected recorded
- [ ] Data exposure risk assessed (did instance have access to sensitive S3/RDS data?)

**Detection Effectiveness:**
- [ ] Time from first malicious API call to alert (MTTD) calculated
- [ ] Time from alert to containment (MTTC) calculated
- [ ] Gaps in detection coverage identified and logged as improvement items

**Process:**
- [ ] Playbook gaps or inaccuracies documented and this playbook updated
- [ ] Lookup CSVs updated with any new approved actors/regions identified
- [ ] Detection rule tuning completed (see Section 4)
- [ ] Hardening actions from Section 3 tracked to completion with owners assigned

**Communication:**
- [ ] Incident report shared with account owner and security leadership
- [ ] AWS support case opened if account charges need to be disputed
- [ ] Lessons learned shared with broader security team

**Legal / Compliance:**
- [ ] Evidence package retained per data retention policy
- [ ] Compliance team notified if regulated data was potentially accessible
- [ ] Determination made on whether external disclosure is required
