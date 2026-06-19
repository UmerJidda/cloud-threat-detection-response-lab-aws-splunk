---
detection_id: CDET-011
detection_name: Unauthorized EC2 Instance Launch
tactic: Impact
technique: T1496
last_updated: 2026-06-18
---

# CDET-011 — Containment Playbook

**Audience:** Tier-2 SOC analyst with AWS CLI access.  
**Prerequisite:** Complete `investigation.md` before executing any containment action. Evidence must be preserved first.

---

## Approval Requirements

| Action | Approval required |
|---|---|
| Disable IAM access key | Tier-2 analyst (self-authorize) |
| Attach deny policy to IAM principal | Tier-2 analyst (self-authorize) |
| Isolate instance (security group swap) | Tier-2 analyst (self-authorize) |
| Terminate EC2 instances | IR lead or on-call manager |
| Delete IAM access key | IR lead or on-call manager |
| Disable IAM user/role | IR lead or on-call manager |
| Any action in a production account | IR lead sign-off required |

---

## Containment Priority Order

Execute in sequence. Do not skip steps. Do not skip to termination before completing evidence preservation (Step 0).

---

### Step 0 — Confirm Evidence is Preserved (Prerequisite)

Before taking any action, verify the `investigation.md` checklist is complete and the evidence package is saved. Containment actions can alter or destroy forensic data.

- [ ] CloudTrail events exported
- [ ] `describe-instances` output saved
- [ ] `userData` decoded and saved
- [ ] IAM policy snapshots saved

---

### Step 1 — Disable the Compromised IAM Access Key (Immediate)

This stops new API calls without deleting the key (preserves audit trail).

```bash
# Disable — does NOT delete; keeps key for forensic reference
aws iam update-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive \
  --user-name <USERNAME>

# Verify the key is now inactive
aws iam list-access-keys --user-name <USERNAME>
```

If the actor is an assumed-role session (not a long-lived key), proceed to Step 2 immediately.

---

### Step 2 — Attach an Explicit Deny Policy to the IAM Principal

Apply a deny-all inline policy to the IAM user or role. This blocks any active sessions even if temporary credentials are still valid.

```bash
# Create the deny policy document
cat > /tmp/deny_all_policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllCDET011Containment",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF

# Apply to IAM user
aws iam put-user-policy \
  --user-name <USERNAME> \
  --policy-name CDET-011-ContainmentDenyAll \
  --policy-document file:///tmp/deny_all_policy.json

# OR apply to IAM role
aws iam put-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name CDET-011-ContainmentDenyAll \
  --policy-document file:///tmp/deny_all_policy.json
```

---

### Step 3 — Isolate the Launched Instances (Network Containment)

Replace the instance's security group with a quarantine security group that has no inbound or outbound rules. This stops mining pool communications and prevents lateral movement without terminating the instance.

```bash
# Create the quarantine security group (one-time setup; reuse if it exists)
aws ec2 create-security-group \
  --group-name CDET-011-Quarantine \
  --description "CDET-011 Containment: No inbound or outbound traffic" \
  --vpc-id <VPC_ID> \
  --region <REGION>

# Note the new security group ID (sg-XXXXXXXX) from the output above

# Remove all outbound rules from quarantine SG (default allows all outbound)
aws ec2 revoke-security-group-egress \
  --group-id <QUARANTINE_SG_ID> \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
  --region <REGION>

# Swap security groups on each compromised instance
aws ec2 modify-instance-attribute \
  --instance-id <INSTANCE_ID> \
  --groups <QUARANTINE_SG_ID> \
  --region <REGION>
```

Repeat the security group swap for each instance ID identified in the investigation.

---

### Step 4 — Stop the Instances (Requires IR Lead Approval)

Stopping (not terminating) preserves the instance for forensic analysis while halting compute costs and mining activity.

```bash
aws ec2 stop-instances \
  --instance-ids <INSTANCE_ID_1> <INSTANCE_ID_2> \
  --region <REGION>

# Confirm stopped state
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID_1> <INSTANCE_ID_2> \
  --region <REGION> \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name}'
```

---

### Step 5 — Multi-Region Sweep and Contain

If the investigation identified instances in multiple regions, repeat Steps 3 and 4 for each region.

```bash
# List all running instances launched by the actor across regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  aws ec2 describe-instances \
    --region "$region" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Region:Placement.AvailabilityZone,Type:InstanceType}' \
    --output table 2>/dev/null
done
```

---

### Step 6 — Notify and Log

- Open or update the incident ticket with all containment actions taken, timestamps, and approvers.
- Notify the AWS account owner and security leadership.
- Record the CloudTrail `eventId` values for all containment API calls (these are themselves audit events).

---

## What NOT to Do

**Do NOT terminate instances before evidence is preserved.** Termination destroys ephemeral storage, memory state, and may remove evidence needed for forensics or legal proceedings.

**Do NOT delete the IAM access key immediately.** Disabling is sufficient for containment. Deletion removes forensic linkage and cannot be undone.

**Do NOT modify the original CloudTrail events or S3 log buckets.** Any log modification could invalidate the evidence chain.

**Do NOT remove the deny-all policy without IR lead sign-off.** Premature removal re-enables the attacker.

**Do NOT reboot instances during containment.** Rebooting can clear volatile memory evidence.

---

## Rollback / False Positive Undo Steps

If investigation concludes the alert was a benign false positive (all triage PASS criteria met after full investigation), reverse containment in the following order:

1. **Remove the deny-all policy** (requires IR lead confirmation):

```bash
# Remove from IAM user
aws iam delete-user-policy \
  --user-name <USERNAME> \
  --policy-name CDET-011-ContainmentDenyAll

# OR remove from IAM role
aws iam delete-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name CDET-011-ContainmentDenyAll
```

2. **Re-enable the access key:**

```bash
aws iam update-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --status Active \
  --user-name <USERNAME>
```

3. **Restore original security groups on instances:**

```bash
aws ec2 modify-instance-attribute \
  --instance-id <INSTANCE_ID> \
  --groups <ORIGINAL_SG_ID_1> <ORIGINAL_SG_ID_2> \
  --region <REGION>
```

4. **Restart stopped instances** (if they were stopped during investigation):

```bash
aws ec2 start-instances \
  --instance-ids <INSTANCE_ID> \
  --region <REGION>
```

5. Document the false positive rationale and update `splunk/lookups/known_service_accounts.csv` if the actor is a legitimate service account that was missing from the lookup.
