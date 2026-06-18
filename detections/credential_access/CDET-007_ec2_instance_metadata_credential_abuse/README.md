# CDET-007 — EC2 Instance Metadata Credential Exfiltration

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-007 |
| **Severity** | Critical |
| **Confidence** | High |
| **Tactic** | Credential Access |
| **Technique** | T1552.005 — Unsecured Credentials: Cloud Instance Metadata |
| **Status** | Testing |
| **Data Source** | CloudTrail + GuardDuty |
| **Schedule** | Every 5 minutes |

## Detection Logic

The EC2 Instance Metadata Service (IMDS) exposes temporary IAM role credentials to the instance at `169.254.169.254`. An adversary who can reach the IMDS endpoint (SSRF, RCE, direct access) can steal these credentials and use them from any external IP.

This detection has two independent branches:

**Branch A — CloudTrail IP Anomaly:** Detects when an AssumedRole session issued to an EC2 instance (`sessionIssuer.type=EC2Instance`) is used from a source IP that is not in the known EC2 private CIDR ranges. Legitimate EC2 API calls originate from the instance's private IP or the NAT gateway's Elastic IP.

**Branch B — GuardDuty Corroboration:** Detects GuardDuty's `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding types, which are generated when GuardDuty observes EC2 instance credentials being used from an IP that is not associated with the instance.

Both branches generate critical severity. Branch B has near-zero false positive rate.

## Required Lookups

**`ec2_private_cidr_ranges.csv`** — must include:
- All private CIDR ranges used by EC2 subnets (10.x, 172.16.x, 192.168.x)
- All NAT gateway Elastic IPs (these are public IPs but represent legitimate EC2 egress)
- Any other known legitimate egress IPs for EC2 workloads

```csv
cidr,description,is_known_ec2_ip
10.0.0.0/8,Internal VPC CIDR,true
172.16.0.0/12,Internal VPC CIDR,true
203.0.113.10/32,NAT Gateway us-east-1a,true
```

## Example Alert Output

```
detection_id    : CDET-007
detection_branch: cloudtrail_ip_anomaly
severity        : critical
event_name      : GetObject
instance_role_arn: arn:aws:iam::123456789012:role/web-server-role
session_principal: arn:aws:sts::123456789012:assumed-role/web-server-role/i-0abc123
event_source_ip : 198.51.100.77
region          : us-east-1
```

## Investigation Guidance

1. Look up the EC2 instance associated with the role (`instance_role_arn`) — check if it is running and in a healthy state
2. The external IP (`event_source_ip`) is the attacker's IP — search for it in threat intelligence
3. Review all API calls made from this session across all services
4. Determine if the IMDS endpoint was accessible (IMDSv1 is vulnerable to SSRF; IMDSv2 requires session tokens)
5. Identify the SSRF or RCE vector that allowed IMDS access
