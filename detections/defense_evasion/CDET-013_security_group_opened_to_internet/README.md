# CDET-013 — Security Group Opened to Public Internet

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-013 |
| **Severity** | High / Critical (port-dependent) |
| **Confidence** | High |
| **Tactic** | Defense Evasion |
| **Technique** | T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 10 minutes |

## Detection Logic

AWS Security Groups are the primary network firewall for EC2 and other compute resources. An attacker who modifies a security group to allow `0.0.0.0/0` (any IP) inbound effectively bypasses the network boundary, enabling direct external access to internal resources. This is commonly done to:

- Open an SSH/RDP backdoor to a compromised instance
- Expose a database port for direct exfiltration
- Allow a malicious tool deployed on the instance to receive inbound connections

The detection fires on any `AuthorizeSecurityGroupIngress` event that adds a rule with `0.0.0.0/0` or `::/0` (IPv6 any) as the source CIDR, from a principal not in the approved list.

### Port Risk Classification

| Category | Ports | Severity |
|----------|-------|----------|
| Remote access | 22 (SSH), 3389 (RDP) | Critical |
| Database | 3306, 5432, 1433, 27017, 6379 | Critical |
| All traffic | Protocol -1 | Critical |
| Any other port | Any | High |

## Example Alert Output

```
detection_id  : CDET-013
severity      : critical
high_risk_port: SSH (22) — critical exposure
group_id      : sg-0abc1234567890def
from_port     : 22
to_port       : 22
ip_protocol   : tcp
cidr_range    : 0.0.0.0/0
principal_arn : arn:aws:iam::123456789012:user/ops-user
event_source_ip: 198.51.100.12
region        : us-east-1
```

## Containment Guidance

1. Immediately revoke the specific inbound rule: `aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol <proto> --port <port> --cidr 0.0.0.0/0`
2. If SSH/RDP was opened, check instance auth logs for any connections that occurred during the exposure window
3. For database port exposures, check if any data was accessed from external IPs
4. Review the full security group rule set for any other unauthorized rules
5. Identify why the principal had `ec2:AuthorizeSecurityGroupIngress` permission and reduce if not required

## Tuning Notes

- Add all approved deployment/load-balancer roles to `approved_iam_principals.csv`
- For environments where `0.0.0.0/0` on 443 is explicitly permitted (public-facing ELB), add the managing principal to the approved lookup rather than modifying the detection
- Do not lower severity for port 443 in environments where EC2 instances run databases or sensitive services
