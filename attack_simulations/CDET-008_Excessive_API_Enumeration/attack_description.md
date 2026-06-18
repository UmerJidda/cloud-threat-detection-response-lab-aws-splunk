# CDET-008 — Excessive API Enumeration

**Tactic:** Discovery  
**MITRE ATT&CK:** T1580 — Cloud Infrastructure Discovery  
**Severity:** Medium  
**Data Source:** AWS CloudTrail

---

## Technique Overview

Cloud reconnaissance is the foundational phase of nearly every successful cloud attack. Before an adversary can escalate privileges, exfiltrate data, or establish persistence, they must understand what resources exist and how they are configured. In AWS, this phase consists entirely of read-only API calls — which means no resources are created or modified, making the activity largely invisible to alerting rules that focus on write operations.

The attacker goal is to build a complete map of the victim's AWS environment: which services are in use, how they are configured, what data they hold, and where misconfigurations exist that can be exploited.

---

## Adversary Tooling

Sophisticated threat actors rarely enumerate AWS manually. Purpose-built offensive toolkits automate the discovery phase:

**Pacu** (Rhinosecurity Labs) is the most widely used AWS exploitation framework. Its enumeration modules (`enum__all`, `enum__services`) call hundreds of List/Describe/Get APIs automatically, building a complete picture of the environment. Pacu also tracks session state so an attacker can pause and resume enumeration.

**ScoutSuite** (NCC Group) performs multi-cloud security audits. When run offensively, it generates thousands of API calls in minutes. Its HTML report summarizes all misconfigurations, making it trivially easy for an attacker to identify targets.

**CloudMapper** builds network diagrams of AWS infrastructure. An attacker with a visual map of VPCs, subnets, and security groups can immediately identify network paths to valuable resources.

**Prowler** is an open-source AWS security tool that runs hundreds of CIS benchmark checks. An attacker using Prowler obtains a prioritized list of security weaknesses in the target environment.

---

## The List/Describe/Get API Pattern

AWS organizes its read-only APIs into three verb families:

- **List** APIs return collections of resource identifiers (e.g., `ListBuckets`, `ListRoles`, `ListFunctions`). These are the first calls an attacker makes — low cost, reveals breadth.
- **Describe** APIs return configuration details for specific resources (e.g., `DescribeInstances`, `DescribeSecurityGroups`). These follow List calls to drill into each resource.
- **Get** APIs retrieve individual resource content or policy documents (e.g., `GetBucketPolicy`, `GetRolePolicy`, `GetFunctionConfiguration`). These reveal the sensitive details needed to identify exploitable misconfigurations.

A typical enumeration sequence: List → filter interesting targets → Describe each → Get policies and configurations → cross-reference for attack paths.

---

## Why Read-Only Permissions Are Dangerous

Many organizations operate under the assumption that read-only access is inherently safe. This is incorrect. Read-only access to AWS APIs provides:

1. **Complete infrastructure inventory**: Every EC2 instance, RDS database, Lambda function, S3 bucket, ECS cluster, and EKS node — including private IP addresses, VPC placement, and instance metadata.

2. **IAM policy enumeration**: The full list of roles, users, groups, and their attached policies. An attacker can identify which role has administrative access, which service accounts have overly broad permissions, and which trust relationships exist between services.

3. **Network topology**: VPC CIDR blocks, subnet assignments, route tables, security group rules, peering connections, and VPN configurations. This is a complete network map.

4. **Secret locations**: SSM Parameter Store path listings, Secrets Manager secret names (not values, but names reveal what exists). An attacker who knows a secret is named `prod/database/master-password` knows exactly what to target for privilege escalation.

5. **Data asset identification**: S3 bucket names, RDS cluster endpoints, DynamoDB table names, and their encryption status. Unencrypted resources are prioritized attack targets.

The SecurityAudit managed IAM policy — intended for legitimate auditing — grants exactly this breadth of read-only access. In the wrong hands, it constitutes full reconnaissance capability.

---

## What Attackers Look For

During enumeration, attackers specifically prioritize:

**Unencrypted S3 buckets**: Buckets without server-side encryption or with public access enabled. Public buckets are immediately exploitable for data exfiltration. Private unencrypted buckets become targets once initial access is achieved.

**Overly permissive security groups**: Inbound rules allowing 0.0.0.0/0 (all internet) on ports like 22 (SSH), 3389 (RDP), 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL), or 27017 (MongoDB) indicate directly exposed services.

**Unused IAM roles with high permissions**: Service roles that have not been used recently (CloudTrail last used date) but carry administrative permissions are prime candidates for takeover — the legitimate service owner may not notice unauthorized use.

**Lambda functions with sensitive environment variables**: Functions often store database credentials, API keys, or internal service URLs in environment variables, visible via `GetFunctionConfiguration`.

**RDS instances with public accessibility**: `publiclyAccessible: true` on a database combined with a permissive security group represents direct database exposure.

**SSM Parameter Store paths**: Hierarchical paths like `/prod/db/password` or `/app/api-key` reveal where credentials are stored, guiding later credential access techniques.

---

## Velocity Thresholds: Automation vs. Human Browsing

CloudTrail records every API call with a timestamp and caller identity. The key differentiator between legitimate AWS Console browsing and automated enumeration is API call velocity.

**Normal human behavior**:
- 2–10 API calls per minute
- Calls concentrated on 1–3 services
- Organic gaps (think time, page loads)
- Consistent with working hours

**Automated enumeration signatures**:
- 50–500+ API calls in a 2-hour window
- Calls spanning 5+ distinct AWS services
- Sub-second intervals between calls (impossible for human console interaction)
- Calls to APIs that are never called via the AWS Console (many CLI-only APIs)
- Sequential exhaustion of paginated results (GetPaginator patterns)

CDET-008 triggers at: **≥50 API calls** AND **≥5 unique API event names** within a **2-hour sliding window** for a single IAM principal.

At tool-level rates, Pacu's `enum__all` module can generate 200–500 API calls in under 10 minutes. ScoutSuite full enumeration typically produces 1,000–3,000 API calls in 5–15 minutes.

---

## Attack Chain Position

Enumeration (T1580) is almost always the second phase after initial access (T1078 — Valid Accounts). An attacker who has stolen an IAM access key will run enumeration before any destructive or exfiltration action. Detection of CDET-008 therefore represents an opportunity to catch an attack in progress before high-impact techniques are executed.

---

## References

- MITRE ATT&CK T1580: https://attack.mitre.org/techniques/T1580/
- Pacu Framework: https://github.com/RhinoSecurityLabs/pacu
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- CloudMapper: https://github.com/duo-labs/cloudmapper
- Prowler: https://github.com/prowler-cloud/prowler
