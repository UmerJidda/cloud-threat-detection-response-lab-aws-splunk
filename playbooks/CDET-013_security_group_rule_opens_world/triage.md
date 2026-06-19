---
detection_id: CDET-013
detection_name: Security Group Opens Ingress to World
tactic: Defense Evasion
technique: T1562.007
last_updated: 2026-06-18
---

# CDET-013 — Triage Playbook
## Security Group Opens Ingress to World

**Target completion time:** 5–10 minutes  
**Goal:** Determine whether this alert is a real threat or a benign false positive and decide if immediate escalation is required.

---

## Step 1 — Validate the Alert Is Real (not test data / pipeline noise)

1. Open the triggering alert in Splunk or your SIEM and confirm:
   - `eventName` = `AuthorizeSecurityGroupIngress`
   - `eventSource` = `ec2.amazonaws.com`
   - `awsRegion` is a region your organization operates in (not a sandbox/test region)
   - `userIdentity.type` is not `AWSService` (pipeline actors such as AWS Config remediation, Elastic Beanstalk, EKS node bootstrapping will appear as `AWSService` and are generally safe to suppress — cross-check against `splunk/lookups/trusted_service_roles.csv`)

2. Check the alert timestamp. Confirm it is within the last 24 hours and is not a replayed or backfilled test event:
   - Look for `requestParameters.dryRun = true` — dry-run calls produce the same CloudTrail event but do not make changes; treat as **benign FP**.
   - If the account ID or principal ARN appears in `splunk/lookups/known_ci_cd_roles.csv`, note it but do not auto-dismiss — verify the target SG still.

3. Confirm this is not duplicate alerting from a prior open incident (search for existing JIRA/ServiceNow tickets referencing the same `groupId`).

---

## Step 2 — Identify the Affected Resource

4. Record the following fields from the CloudTrail event:

   | Field | Where to find it |
   |-------|-----------------|
   | Security Group ID | `requestParameters.groupId` |
   | Account ID | `recipientAccountId` |
   | Region | `awsRegion` |
   | VPC ID | `requestParameters.vpcId` (if present) |
   | Caller principal | `userIdentity.arn` |
   | Source IP | `sourceIPAddress` |
   | User-Agent | `userAgent` |

5. Pull the current state of the security group to confirm the world-open rule is still active:

   ```bash
   aws ec2 describe-security-groups \
     --group-ids <groupId> \
     --region <awsRegion> \
     --query "SecurityGroups[*].{Name:GroupName,IngressRules:IpPermissions}"
   ```

   - If `CidrIp: 0.0.0.0/0` or `CidrIpv6: ::/0` is present on a non-standard port (not 80/443), treat as **high urgency**.
   - If the rule has already been removed, the threat actor may have cleaned up — continue investigation, do not dismiss.

---

## Step 3 — Determine Urgency

6. Ask these questions to set urgency:

   | Question | Yes → Escalate now | No → Continue triage |
   |----------|-------------------|----------------------|
   | Is the port TCP/22 (SSH), TCP/3389 (RDP), or TCP/0 (all)? | YES | No |
   | Is the security group attached to a production EC2 instance or RDS? | YES | No |
   | Is the caller IP address outside your corporate IP ranges (`splunk/lookups/corporate_ip_ranges.csv`)? | YES | No |
   | Is the caller principal not listed in `splunk/lookups/approved_sg_modifiers.csv`? | YES | No |
   | Has the principal performed other suspicious API calls in the last 30 minutes? | YES | No |

7. **If two or more YES answers:** immediately escalate to Tier-3 / Incident Commander and open a P1 incident. Do not wait for full investigation.

---

## Step 4 — Lookup CSVs to Reference

| Lookup file | Purpose |
|-------------|---------|
| `splunk/lookups/approved_sg_modifiers.csv` | IAM roles/users allowed to modify security groups |
| `splunk/lookups/trusted_service_roles.csv` | AWS service principals that legitimately call EC2 SG APIs |
| `splunk/lookups/known_ci_cd_roles.csv` | Automation/pipeline roles (require verification, not auto-suppress) |
| `splunk/lookups/corporate_ip_ranges.csv` | Expected source IPs for human operators |
| `splunk/lookups/sensitive_security_groups.csv` | SGs protecting production/PCI/HIPAA assets (auto-escalate) |

---

## Step 5 — PASS / FAIL Decision

### REAL ALERT (escalate / proceed to investigation.md)
- Caller principal is **not** in `approved_sg_modifiers.csv` AND source IP is external, OR
- Port opened is a sensitive admin port (22, 3389, 0–65535 all), OR
- Security group is in `sensitive_security_groups.csv`, OR
- The rule has **not** been removed and the SG is attached to a running instance.

### BENIGN FALSE POSITIVE (close with notes)
- Event has `requestParameters.dryRun = true`, OR
- Caller is an AWS-managed service principal (`userIdentity.type = AWSService`) in `trusted_service_roles.csv`, AND the opened port is 80 or 443, OR
- Alert matches a known change-management ticket that was approved and the rule is already removed by the pipeline.

> **Always document your PASS/FAIL reasoning in the incident ticket before closing or escalating.**
