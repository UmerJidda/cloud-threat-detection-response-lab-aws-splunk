---
detection_id: CDET-013
detection_name: Security Group Opens Ingress to World
tactic: Defense Evasion
technique: T1562.007
last_updated: 2026-06-18
---

# CDET-013 — Containment Playbook
## Security Group Opens Ingress to World

**Prerequisite:** Investigation is in progress. Evidence has been collected per `investigation.md`.  
**Goal:** Stop the active threat with minimum service disruption and preserve forensic integrity.

> **STOP:** Before executing any containment action, confirm that evidence collection (section 5 of `investigation.md`) is complete. Removing a security group rule before capturing VPC Flow Logs and CloudTrail context may destroy key forensic data.

---

## Approval Requirements

| Action | Approval required |
|---|---|
| Revoke the world-open SG rule | Tier-2 analyst self-authorizes for prod incidents |
| Disable an IAM access key | Tier-2 analyst self-authorizes |
| Isolate (detach SG / attach quarantine SG) | Incident Commander or Tier-3 approval |
| Terminate an EC2 instance | Incident Commander + application owner approval |
| Detach or delete an IAM role/policy | Tier-3 + Security Manager approval |

---

## Containment Actions — Priority Order

### Action 1 — Remove the World-Open Ingress Rule (PRIMARY, execute first)

This is the most important step. It closes the exposure without affecting instance availability.

1. Identify the exact rule to revoke from the CloudTrail `requestParameters.ipPermissions` field captured during investigation.

2. Revoke the specific offending rule. Replace `<groupId>`, `<protocol>`, `<fromPort>`, `<toPort>`, `<awsRegion>` with actual values:

   ```bash
   # Example: revoke TCP 22 open to 0.0.0.0/0
   aws ec2 revoke-security-group-ingress \
     --group-id <groupId> \
     --protocol tcp \
     --port <fromPort>-<toPort> \
     --cidr 0.0.0.0/0 \
     --region <awsRegion>

   # If IPv6 was also opened (::/0), run this as well
   aws ec2 revoke-security-group-ingress \
     --group-id <groupId> \
     --ip-permissions '[{"IpProtocol":"tcp","FromPort":<fromPort>,"ToPort":<toPort>,
       "Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]' \
     --region <awsRegion>
   ```

3. Verify the rule has been removed:

   ```bash
   aws ec2 describe-security-groups \
     --group-ids <groupId> \
     --region <awsRegion> \
     --query "SecurityGroups[*].IpPermissions"
   ```

   Confirm `0.0.0.0/0` and `::/0` are no longer present for the affected port.

---

### Action 2 — Disable the Compromised IAM Credential

If the caller is determined to be compromised (external IP, unexpected principal, etc.), disable the credential **before** the threat actor can make further changes.

```bash
# Disable an IAM user access key (reversible)
aws iam update-access-key \
  --user-name <userName> \
  --access-key-id <accessKeyId> \
  --status Inactive

# Revoke all active sessions for an IAM role (forces re-authentication)
aws iam delete-role-policy \
  --role-name <roleName> \
  --policy-name <inlinePolicyName>

# Alternatively, attach an explicit deny policy to the role to block all actions
aws iam put-role-policy \
  --role-name <roleName> \
  --policy-name INCIDENT_RESPONSE_DENY_ALL \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }'
```

> Note: An explicit deny policy blocks active STS sessions immediately because STS sessions evaluate IAM policies at the time of each API call. This is the fastest way to neutralize an active session without deleting credentials.

---

### Action 3 — Isolate the Exposed Instance (if active compromise suspected)

If VPC Flow Logs show accepted inbound connections from external IPs after the rule was added, the instance may be actively compromised. Isolate it by replacing its security group with a quarantine SG that blocks all traffic.

**Requires Incident Commander approval.**

1. Create a quarantine security group (no inbound, no outbound rules):

   ```bash
   QUARANTINE_SG=$(aws ec2 create-security-group \
     --group-name "INCIDENT-QUARANTINE-CDET013-$(date +%Y%m%d%H%M)" \
     --description "Incident response quarantine SG - CDET-013" \
     --vpc-id <vpcId> \
     --region <awsRegion> \
     --query 'GroupId' --output text)
   echo "Quarantine SG: $QUARANTINE_SG"
   ```

2. Identify the network interface(s) of the affected instance:

   ```bash
   aws ec2 describe-instances \
     --instance-ids <instanceId> \
     --region <awsRegion> \
     --query "Reservations[*].Instances[*].NetworkInterfaces[*].
              {NiId:NetworkInterfaceId,Groups:Groups}" \
     --output json
   ```

3. Replace the security groups on each network interface:

   ```bash
   aws ec2 modify-network-interface-attribute \
     --network-interface-id <networkInterfaceId> \
     --groups $QUARANTINE_SG \
     --region <awsRegion>
   ```

4. Record the original SG IDs before replacing (you captured them during investigation) so they can be restored.

---

### Action 4 — Take EC2 Instance Snapshot Before Any Further Action

If the instance may have been accessed, preserve a forensic snapshot before any further remediation:

```bash
# List volumes attached to the instance
aws ec2 describe-volumes \
  --filters "Name=attachment.instance-id,Values=<instanceId>" \
  --region <awsRegion> \
  --query "Volumes[*].{VolumeId:VolumeId,Device:Attachments[0].Device}"

# Create a snapshot of each volume
aws ec2 create-snapshot \
  --volume-id <volumeId> \
  --description "INCIDENT-CDET013-forensic-snapshot-$(date +%Y%m%d%H%M)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[
    {Key=incident,Value=CDET-013},
    {Key=purpose,Value=forensics}]' \
  --region <awsRegion>
```

---

## What NOT To Do

- **Do NOT terminate the instance** before taking a forensic snapshot. Termination destroys ephemeral storage and running process memory.
- **Do NOT delete the CloudTrail event** or modify the audit log in any way.
- **Do NOT delete the compromised IAM user or role** before the investigation is complete. Deletion removes history and may alert the threat actor.
- **Do NOT close all SG rules** without understanding the application's legitimate traffic requirements — this may cause a production outage.
- **Do NOT rotate the access key** (delete old + create new) before capturing the last-used timestamp and all associated CloudTrail events. Deletion is irreversible from an audit perspective.
- **Do NOT remove the quarantine SG from the instance** without Incident Commander approval, even if an application owner requests it.

---

## Rollback Steps (if containment action was a False Positive)

If after further review the alert is determined to be a false positive:

### Restore the revoked security group rule

```bash
aws ec2 authorize-security-group-ingress \
  --group-id <groupId> \
  --protocol <protocol> \
  --port <fromPort>-<toPort> \
  --cidr <originalCidr> \
  --region <awsRegion>
```

> Only restore the exact original rule. Do not add a broader rule as a workaround.

### Re-enable a disabled access key

```bash
aws iam update-access-key \
  --user-name <userName> \
  --access-key-id <accessKeyId> \
  --status Active
```

### Remove the deny-all inline policy from a role

```bash
aws iam delete-role-policy \
  --role-name <roleName> \
  --policy-name INCIDENT_RESPONSE_DENY_ALL
```

### Restore original security groups to a network interface

```bash
aws ec2 modify-network-interface-attribute \
  --network-interface-id <networkInterfaceId> \
  --groups <originalSgId1> <originalSgId2> \
  --region <awsRegion>
```

> Document all rollback actions in the incident ticket with timestamps and approvals.
