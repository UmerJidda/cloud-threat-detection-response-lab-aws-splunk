# CDET-013 — Security Group Opened to Public Internet

**Tactic:** Defense Evasion  
**MITRE ATT&CK:** T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall  
**Severity:** High  
**Data Source:** AWS CloudTrail

---

## Technique Overview

After achieving initial access to an AWS environment, an attacker frequently modifies EC2 Security Groups to establish persistent inbound network access. By adding an ingress rule that permits traffic from `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6) on a specific port, the attacker creates a direct network path from the public internet to a specific EC2 instance or service — bypassing any existing access controls that rely on IP whitelisting.

This technique enables:
- Establishing a direct command-and-control (C2) channel to a compromised instance
- Exposing internal databases directly to the internet for bulk exfiltration
- Creating a persistent backdoor that survives instance restarts and credential rotation

---

## Why an Attacker Modifies Security Groups After Initial Compromise

Initial access typically comes through a stolen IAM access key or credential, which provides API access but not direct network access to the instance. An attacker who wants to:
- **Run interactive commands on a compromised instance** needs SSH (port 22) or RDP (port 3389) access
- **Exfiltrate a database directly** needs network access to the database port
- **Maintain C2 communications** needs a reliable inbound channel that the victim's network perimeter doesn't block

Security group modification is the fastest path to achieve these goals when the compromised IAM credentials have `ec2:AuthorizeSecurityGroupIngress` permissions.

---

## SSH vs. RDP Backdoors

**SSH (Port 22 — Linux instances)**:
- Direct terminal access for interactive compromise
- Attacker typically deploys their public key to `~/.ssh/authorized_keys` as a persistence mechanism
- Once the SG is open, the attacker can SSH from any IP address globally
- Detection: port 22 open to 0.0.0.0/0 combined with new SSH key addition

**RDP (Port 3389 — Windows instances)**:
- Graphical desktop access for Windows servers
- Commonly used for financially motivated attacks (ransomware operators use RDP extensively)
- Open port 3389 to 0.0.0.0/0 is also exploited for brute force even without prior compromise
- Detection: port 3389 open to 0.0.0.0/0 is a direct policy violation in most organizations

**Other common backdoor ports**:
- Port 443 (HTTPS): Blends into normal traffic, used for C2 frameworks (Cobalt Strike, Metasploit)
- Port 4444/8888: Common reverse shell ports (Metasploit defaults)
- Port 5985/5986 (WinRM): Remote management for Windows
- Port 27017/3306/5432: Database ports (MongoDB, MySQL, PostgreSQL) — exfiltration targets

---

## The "Temporary" Access Pattern

Attackers performing insider-threat-adjacent activity or social engineering attacks sometimes present security group changes as "temporary" to reduce scrutiny:

> "I need to quickly debug this production issue — I'll open port 22 temporarily and remove it in an hour."

This framing is effective because:
- Temporary changes feel less alarming than permanent ones
- The change is justified by a plausible operational need
- Change management processes may have a "break glass" expedited path
- The attacker counts on the team forgetting to remove the rule

Detection systems must alert on the authorization event itself, not wait to see if the rule is revoked. The time window between adding and exploiting an open SG rule can be minutes.

---

## VPC vs. Global Exposure

**Security Group (0.0.0.0/0)**: Makes the resource accessible from the **entire internet**. Any IP address globally can attempt connections. This is the highest-risk configuration.

**Security Group (10.0.0.0/8 or RFC1918)**: Restricts access to private IP ranges — a VPC-internal or VPN-routed access pattern. Lower risk than global exposure, but still may expose resources to lateral movement from any compromised VPC instance.

**Security Group (specific CIDR)**: IP whitelisting — restricts to known IP ranges. Legitimate for corporate office IP ranges or known partner IPs.

The CDET-013 alert fires specifically when the CIDR is `0.0.0.0/0` or `::/0` — true global exposure.

---

## Security Groups vs. NACLs

**Security Groups** are stateful, instance-level firewalls:
- Applied per network interface (ENI)
- Allow rules only (no explicit deny)
- Stateful: return traffic is automatically allowed
- Evaluated as a whole (all rules considered, most permissive wins)
- Can be changed at any time without instance restart

**Network ACLs (NACLs)** are stateless, subnet-level firewalls:
- Applied at the subnet level (affects all resources in subnet)
- Allow and deny rules
- Stateless: return traffic must be explicitly allowed
- Rules evaluated in order (lowest rule number first, first match wins)
- Changes affect all instances in the subnet

An attacker prefers security groups because:
- More granular (can target one specific instance, not an entire subnet)
- Simpler API (single `AuthorizeSecurityGroupIngress` call vs. NACL rule management)
- Less likely to be monitored than NACLs (security groups are the primary control)

---

## References

- MITRE ATT&CK T1562.007: https://attack.mitre.org/techniques/T1562/007/
- AWS Security Groups documentation: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
- AWS NACLs documentation: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
