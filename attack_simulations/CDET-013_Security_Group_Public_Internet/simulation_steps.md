# CDET-013 — Simulation Steps: Security Group Opened to Public Internet

**WARNING**: These steps modify EC2 Security Group rules. Opening rules to 0.0.0.0/0 creates real network exposure if applied to production security groups. Use a dedicated test security group. The cleanup steps must be run immediately.

---

## Prerequisites

- AWS CLI configured (`aws configure`)
- IAM permissions: `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`, `ec2:DescribeSecurityGroups`, `ec2:CreateSecurityGroup`
- An existing VPC (or use the default VPC)

---

## Phase 0: Create a Test Security Group

```bash
# Get the default VPC
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)

echo "Using VPC: $DEFAULT_VPC"

# Create a dedicated test security group
SG_ID=$(aws ec2 create-security-group \
  --group-name "cdet013-test-sg-$(date +%s)" \
  --description "CDET-013 Security Test — Delete after test" \
  --vpc-id "$DEFAULT_VPC" \
  --query GroupId \
  --output text)

echo "Test Security Group: $SG_ID"

# Tag it clearly
aws ec2 create-tags \
  --resources "$SG_ID" \
  --tags \
    Key=Purpose,Value=CDET013-security-test \
    Key=AutoDelete,Value=true \
    Key=Owner,Value=security-team
```

---

## Phase 1: Check Existing Rules

```bash
# View current rules for the security group
aws ec2 describe-security-groups \
  --group-ids "$SG_ID" \
  --output json

# List ALL security groups with overly permissive inbound rules (read-only audit)
aws ec2 describe-security-groups \
  --filters \
    "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName,Description]' \
  --output table
```

---

## Phase 2: Add Rule — IPv4 Global Access (THE DETECTION EVENT)

### SSH Backdoor (Port 22)

```bash
# THE PRIMARY DETECTION EVENT — triggers CDET-013
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

echo "CloudTrail AuthorizeSecurityGroupIngress event generated"
echo "CDET-013 should fire on port 22 open to 0.0.0.0/0"
```

### RDP Backdoor (Port 3389)

```bash
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 3389 \
  --cidr 0.0.0.0/0
```

### Database Port Exposure (Port 3306 — MySQL)

```bash
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 3306 \
  --cidr 0.0.0.0/0
```

---

## Phase 3: Add Rule — IPv6 Global Access

Both IPv4 and IPv6 variants must be blocked. Detection rules should cover both:

```bash
# IPv6 equivalent — equally dangerous on IPv6-enabled VPCs
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --ip-permissions '[{
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "Ipv6Ranges": [{"CidrIpv6": "::/0", "Description": "Test IPv6 rule"}]
  }]'
```

---

## Phase 4: Using JSON Format (Full Control)

The JSON format allows setting descriptions and adding multiple rules atomically:

```bash
# Complete rule set via JSON — more realistic attacker approach
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --ip-permissions '[
    {
      "IpProtocol": "tcp",
      "FromPort": 0,
      "ToPort": 65535,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "temp-debug-access"
        }
      ]
    }
  ]'
# This is the most aggressive variant: all TCP ports open to the internet
```

---

## Phase 5: Immediate Revocation (Cleanup — CRITICAL)

Run these commands immediately after confirming the CloudTrail events are generated:

```bash
# Revoke the SSH rule
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Revoke the RDP rule
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 3389 \
  --cidr 0.0.0.0/0

# Revoke MySQL rule
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 3306 \
  --cidr 0.0.0.0/0

# Revoke IPv6 rule
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --ip-permissions '[{
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
  }]'

# Verify the security group is now empty
aws ec2 describe-security-groups \
  --group-ids "$SG_ID" \
  --query 'SecurityGroups[0].IpPermissions'

# Delete the test security group
aws ec2 delete-security-group --group-id "$SG_ID"
echo "Test security group $SG_ID deleted"
```

---

## Full Verification After Test

```bash
# Confirm CloudTrail recorded both the authorize AND revoke events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,EventName,Resources[0].ResourceName]' \
  --output table

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RevokeSecurityGroupIngress \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,EventName,Resources[0].ResourceName]' \
  --output table
```
