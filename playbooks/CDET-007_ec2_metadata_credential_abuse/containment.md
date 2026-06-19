---
detection_id: CDET-007
detection_name: EC2 Metadata Credential Abuse
tactic: Credential Access
technique: T1552.005
last_updated: 2026-06-18
---

# CDET-007 — EC2 Metadata Credential Abuse: Containment

**Audience:** Tier-2 SOC analyst with AWS experience  
**Prerequisites:** Investigation complete; blast radius documented; escalation path confirmed

---

## Approval Requirements

| Action | Approval Required |
|---|---|
| Revoke temporary STS credentials (deny policy) | Tier-2 self-authorize if active exfiltration confirmed |
| Isolate EC2 instance (replace security group) | Tier-2 self-authorize if active exfiltration confirmed |
| Stop EC2 instance | **IR Lead or Account Owner approval required** |
| Terminate EC2 instance | **IR Lead or Account Owner approval required — forensic image first** |
| Revoke IAM role entirely | **IR Lead or Account Owner approval required** |
| Modify production load balancer / DNS | **Change Management approval required** |

When in doubt, isolate first and escalate before taking destructive actions.

---

## Containment Actions — Priority Order

### Step 1: Revoke the Stolen Temporary Credentials (Immediate — No Approval Required)

Temporary STS credentials cannot be directly revoked, but you can force all sessions for the role to fail by attaching a deny-all inline policy with a condition on the issue time.

1. Determine the `eventTime` of the triggering CDET-007 `AssumeRole` event (T=0 from investigation).
2. Attach the following inline policy to the EC2 role. Replace `<issue-time>` with a timestamp slightly before T=0 (e.g., 5 minutes earlier) to avoid revoking legitimate sessions:

```bash
ROLE_NAME="<role-name>"
ISSUE_TIME="<YYYY-MM-DDTHH:MM:SSZ>"   # 5 minutes before T=0

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "CDET-007-IncidentRevoke-$(date +%Y%m%d)" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$ISSUE_TIME\"
        }
      }
    }]
  }"
```

3. Verify the policy is attached:

```bash
aws iam get-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "CDET-007-IncidentRevoke-$(date +%Y%m%d)"
```

4. Test that the stolen credential is now denied:
   - If the attacker's session is still active, any subsequent API call will return `AccessDenied`.
   - Monitor Splunk for continued `AccessDenied` events from `<attacker_ip>` — these confirm the revocation is working.

---

### Step 2: Isolate the EC2 Instance (Immediate — No Approval Required if Active Threat)

Replace the instance's security group(s) with a forensic isolation security group that allows no inbound or outbound traffic. This preserves the instance state for forensics while cutting off the attacker's access path.

1. Create the isolation security group (do this once; reuse for future incidents):

```bash
VPC_ID="<vpc-id>"

ISOLATION_SG=$(aws ec2 create-security-group \
  --group-name "IR-Isolation-SG-CDET-007" \
  --description "CDET-007 incident isolation - no inbound or outbound" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)

echo "Isolation SG: $ISOLATION_SG"

# Remove the default outbound allow-all rule
aws ec2 revoke-security-group-egress \
  --group-id "$ISOLATION_SG" \
  --protocol all --port all --cidr 0.0.0.0/0
```

2. Record the current security groups on the instance before replacing them:

```bash
INSTANCE_ID="<instance-id>"

aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[*].Instances[*].SecurityGroups' \
  --output json > "original_sgs_${INSTANCE_ID}.json"

cat "original_sgs_${INSTANCE_ID}.json"
```

3. Replace all security groups with the isolation SG:

```bash
aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --groups "$ISOLATION_SG"
```

4. Verify:

```bash
aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[*].Instances[*].SecurityGroups' \
  --output table
```

---

### Step 3: Block the Attacker IP at the Network Level (Immediate)

Add a NACL deny rule on the subnet containing the EC2 instance to block the attacker IP:

```bash
NACL_ID="<nacl-id>"      # Get from VPC console or describe-network-acls
ATTACKER_IP="<attacker-ip>/32"

# Deny inbound from attacker IP (rule number 1 = highest priority)
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --ingress \
  --cidr-block "$ATTACKER_IP"

# Deny outbound to attacker IP
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --egress \
  --cidr-block "$ATTACKER_IP"
```

---

### Step 4: Enforce IMDSv2 on the Affected Instance (Prevent Re-exploitation)

This closes the IMDS credential theft vector without stopping the instance:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id "$INSTANCE_ID" \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

Verify:

```bash
aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[*].Instances[*].MetadataOptions'
```

Expected output: `"HttpTokens": "required"`.

---

### Step 5: Capture a Forensic Memory/Disk Snapshot (Before Stop/Terminate — IR Lead Approval)

If IR Lead approves stopping the instance for deeper forensics:

```bash
# Snapshot all EBS volumes before stopping
for VOL_ID in $(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[*].Instances[*].BlockDeviceMappings[*].Ebs.VolumeId' \
  --output text); do
  aws ec2 create-snapshot \
    --volume-id "$VOL_ID" \
    --description "CDET-007 forensic snapshot - $INSTANCE_ID - $(date +%Y%m%d)" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=incident,Value=CDET-007},{Key=instance,Value=$INSTANCE_ID}]"
done
```

Only after snapshots are confirmed complete (`aws ec2 describe-snapshots --filters Name=status,Values=completed`), stop the instance:

```bash
# IR Lead approval required
aws ec2 stop-instances --instance-id "$INSTANCE_ID"
```

---

## What NOT to Do

| Do NOT | Reason |
|---|---|
| Delete the CloudTrail logs or S3 trail bucket | Destroys evidence required for investigation and potential legal proceedings |
| Terminate the EC2 instance without a forensic snapshot | Loses volatile memory and instance store data |
| Delete the IAM role immediately | Removes the audit trail linking the role to the incident; use deny policy first |
| Rotate the root account credentials without IR Lead sign-off | May disrupt legitimate operations and complicate attribution |
| Run `aws cloudtrail delete-trail` | Destroys ongoing audit capability |
| Stop the instance before capturing snapshots | Volatile instance store data is lost on stop |
| Modify GuardDuty findings before they are exported | Alters the forensic record |
| Revoke all IAM roles in the account | Causes widespread outage affecting unrelated workloads |

---

## Rollback / Undo Steps (If Containment Action Was a False Positive)

### Undo Step 1: Remove the Credential Revocation Policy

```bash
aws iam delete-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "CDET-007-IncidentRevoke-$(date +%Y%m%d)"
```

Note: Any existing sessions that were denied will need to re-authenticate — the temporary credentials themselves cannot be "un-revoked." Applications using this role will automatically obtain new credentials on their next API call.

### Undo Step 2: Restore Original Security Groups

```bash
# Use the saved original_sgs_<instance-id>.json from step 2
ORIGINAL_SGS=$(cat "original_sgs_${INSTANCE_ID}.json" | python3 -c \
  "import json,sys; sgs=json.load(sys.stdin)[0][0]; print(' '.join([sg['GroupId'] for sg in sgs]))")

aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --groups $ORIGINAL_SGS
```

### Undo Step 3: Remove the NACL Deny Rules

```bash
aws ec2 delete-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --ingress

aws ec2 delete-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --egress
```

### Undo Step 4: IMDSv2 Enforcement

IMDSv2 enforcement is a hardening improvement and should not be rolled back unless the application is confirmed incompatible. If rollback is required:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id "$INSTANCE_ID" \
  --http-tokens optional
```

> CDET-007 containment complete. Move to `recovery.md`.
