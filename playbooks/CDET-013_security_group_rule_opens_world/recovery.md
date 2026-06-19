---
detection_id: CDET-013
detection_name: Security Group Opens Ingress to World
tactic: Defense Evasion
technique: T1562.007
last_updated: 2026-06-18
---

# CDET-013 — Recovery Playbook
## Security Group Opens Ingress to World

**Prerequisite:** Containment actions from `containment.md` are complete and confirmed.  
**Goal:** Restore normal operations, verify full threat removal, harden against recurrence, and tune detection.

---

## 1. Verify the Threat Has Been Fully Removed

Before restoring any service, confirm the following:

### 1a. Confirm no world-open rules remain

```bash
# Scan all security groups in the account/region for 0.0.0.0/0 or ::/0 ingress rules
aws ec2 describe-security-groups \
  --region <awsRegion> \
  --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]
           .{SgId:GroupId,Name:GroupName,Rules:IpPermissions}" \
  --output json

# Also check for IPv6
aws ec2 describe-security-groups \
  --region <awsRegion> \
  --query "SecurityGroups[?IpPermissions[?Ipv6Ranges[?CidrIpv6=='::/0']]]
           .{SgId:GroupId,Name:GroupName}" \
  --output json
```

Expected result: the originally affected `<groupId>` should no longer appear in the output, and no new world-open rules should exist that were not there before the incident.

### 1b. Confirm the compromised credential is inactive or rotated

```bash
aws iam list-access-keys --user-name <userName>
# Status should be "Inactive" or the key should no longer exist
```

### 1c. Confirm no persistence mechanisms were established

Run these checks for the time window from `T0` to present:

```bash
# New IAM users created
aws iam list-users \
  --query "Users[?CreateDate>='\''<T0_date>T00:00:00Z'\'']" \
  --output json

# New access keys created for existing users
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time <T0_epoch> \
  --region <awsRegion>

# New key pairs created (EC2 backdoor access)
aws ec2 describe-key-pairs \
  --region <awsRegion> \
  --query "KeyPairs[?CreateTime>='\''<T0_date>T00:00:00Z'\'']"
```

### 1d. Verify no unauthorized scheduled tasks or Lambda functions were created

```bash
# Check for new Lambda functions created after T0
aws lambda list-functions \
  --region <awsRegion> \
  --query "Functions[?LastModified>='\''<T0_date>'\''].{Name:FunctionName,Modified:LastModified}"

# Check CloudWatch Events / EventBridge rules
aws events list-rules \
  --region <awsRegion> \
  --query "Rules[?CreatedBy=='<compromisedPrincipal>']"
```

### 1e. Review VPC Flow Logs for post-containment traffic

Confirm no inbound `ACCEPT` traffic on the previously exposed port has occurred after the rule was revoked:

```bash
aws logs filter-log-events \
  --log-group-name "<vpcFlowLogGroup>" \
  --filter-pattern "[version, accountId, interfaceId, srcAddr, dstAddr,
                    srcPort, dstPort=<openedPort>, protocol, packets,
                    bytes, start, end, action=ACCEPT, logStatus]" \
  --start-time <containment_epochMs> \
  --region <awsRegion>
```

Expected result: zero `ACCEPT` entries after the containment timestamp.

---

## 2. Restore Normal Operations

1. Remove the quarantine security group (if applied) and restore the original SG set:

   ```bash
   aws ec2 modify-network-interface-attribute \
     --network-interface-id <networkInterfaceId> \
     --groups <originalSgId1> <originalSgId2> \
     --region <awsRegion>
   ```

2. Issue a new access key for the affected IAM user/role if the original was disabled:

   ```bash
   # Create a new access key
   aws iam create-access-key --user-name <userName>

   # Deliver new credentials to the user via secure channel (password manager / Secrets Manager)
   # Then delete the old inactive key
   aws iam delete-access-key \
     --user-name <userName> \
     --access-key-id <oldAccessKeyId>
   ```

3. Verify application health after security group restoration. Confirm that legitimate services (load balancer health checks, monitoring agents, etc.) are passing.

4. Remove the temporary deny-all inline policy from any role if it was applied:

   ```bash
   aws iam delete-role-policy \
     --role-name <roleName> \
     --policy-name INCIDENT_RESPONSE_DENY_ALL
   ```

5. Clean up the quarantine security group:

   ```bash
   aws ec2 delete-security-group \
     --group-id $QUARANTINE_SG \
     --region <awsRegion>
   ```

---

## 3. Hardening Steps to Prevent Recurrence

### 3a. Enforce least-privilege on SG modification permissions

Scope the `ec2:AuthorizeSecurityGroupIngress` permission using an IAM condition that blocks world-open CIDRs. Add to the relevant IAM policy:

```json
{
  "Effect": "Deny",
  "Action": [
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress"
  ],
  "Resource": "*",
  "Condition": {
    "IpAddress": {
      "aws:RequestedRegion": "*"
    },
    "StringEquals": {
      "ec2:Cidr": ["0.0.0.0/0", "::/0"]
    }
  }
}
```

> Note: As of 2024, AWS supports the `ec2:Cidr` condition key for SG rule actions — verify key availability in your account with the IAM policy simulator.

### 3b. Enable AWS Config rule for world-open security groups

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "restricted-ssh",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "INCOMING_SSH_DISABLED"
    }
  }' \
  --region <awsRegion>

aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "vpc-sg-open-only-to-authorized-ports",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
    }
  }' \
  --region <awsRegion>
```

### 3c. Add the affected SG to the sensitive SGs lookup

Update `splunk/lookups/sensitive_security_groups.csv` to ensure future alerts on this SG auto-escalate.

### 3d. Enable automatic remediation via AWS Config

Consider attaching an AWS Systems Manager Automation document (`AWS-DisablePublicAccessForSecurityGroup`) as an auto-remediation action on the Config rule to close world-open rules within seconds of creation.

### 3e. Rotate all long-term IAM credentials for affected principals

Enforce MFA on the IAM user and review the password policy:

```bash
aws iam update-login-profile --user-name <userName> --password-reset-required
```

### 3f. Enable CloudTrail in all regions if not already active

```bash
aws cloudtrail describe-trails --include-shadow-trails
# Verify IsMultiRegionTrail=true and IncludeGlobalServiceEvents=true
```

---

## 4. Detection Tuning Recommendations

### 4a. Suppression (reduce noise from known benign actors)

- Add verified CI/CD pipeline roles that legitimately manage SG rules to `splunk/lookups/approved_sg_modifiers.csv`.
- Add known infrastructure-as-code orchestration roles (Terraform, CDK) with their specific source IP ranges to the lookup and add a `| lookup` filter in the CDET-013 detection SPL.
- Suppress alerts where `requestParameters.dryRun = true`.

### 4b. Enrichment (increase signal quality)

- Enrich alerts with instance tags (environment, owner, tier) by joining against an asset inventory lookup: `splunk/lookups/ec2_asset_inventory.csv`.
- Add a field `is_sensitive_sg` by looking up `requestParameters.groupId` in `splunk/lookups/sensitive_security_groups.csv` and use it to auto-set severity to `critical`.
- Enrich `sourceIPAddress` with geo-IP and ISP/ASN data to surface anomalous login origins automatically.
- Add a `time_since_key_creation` calculated field to flag incidents where the access key is less than 7 days old (newly created keys used for this action are a strong indicator of compromise).

### 4c. Threshold tuning

- If alert volume is high due to legitimate automation, consider adding a secondary condition: alert only when `fromPort` is in `[22, 3389, 0, 8080, 8443]` OR when `toPort - fromPort >= 1000` (broad port ranges).
- This keeps detection focused on high-risk exposures while reducing low-signal ephemeral ports used by known internal services.

---

## 5. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Root cause documented: how did the threat actor obtain the credential/access?
- [ ] Timeline finalized and attached to the incident ticket
- [ ] Affected resources fully inventoried (instances, SGs, IAM principals)
- [ ] Evidence preserved per retention policy (CloudTrail JSON, SPL results, Flow Logs)
- [ ] Forensic EC2 snapshots labeled and stored (or disposed of per policy if FP)
- [ ] All temporary containment resources removed (quarantine SG, deny-all policies)
- [ ] Hardening steps from section 3 tracked in a follow-up ticket with due dates
- [ ] Detection tuning changes from section 4 deployed and validated in Splunk
- [ ] `splunk/lookups/approved_sg_modifiers.csv` and `sensitive_security_groups.csv` updated
- [ ] CDET-013 detection SPL reviewed for any missed coverage gaps surfaced by this incident
- [ ] Lessons learned shared with the broader security team
- [ ] Incident ticket closed with final severity, MITRE technique (T1562.007), and root cause tag
