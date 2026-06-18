# MITRE ATT&CK Matrix — Cloud Coverage

## Scope

This matrix covers MITRE ATT&CK for Enterprise — Cloud (IaaS) as it applies to AWS environments. The scope is limited to the tactics and techniques observable through CloudTrail, GuardDuty, Security Hub, IAM, and network configuration data collected by this program.

**Framework version:** MITRE ATT&CK v15
**Platform scope:** AWS (IaaS)

---

## Coverage Legend

| Symbol | Meaning |
|--------|---------|
| ✅ Active | Detection authored, validated, and deployed to Splunk |
| 🔄 Testing | Detection authored; validation in progress |
| 📋 Planned | Technique identified as in-scope; detection not yet authored |
| ⬜ Out of Scope | Technique not observable through available data sources |
| ❌ Gap | Technique in scope but no detection planned |

---

## Initial Access

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1078 | T1078.004 | Valid Accounts: Cloud Accounts | 🔄 Testing | CDET-006 |
| T1190 | — | Exploit Public-Facing Application | ⬜ Out of Scope | — |
| T1566 | T1566.002 | Phishing: Spearphishing Link | ⬜ Out of Scope | — |

**Notes:** Root account activity is the highest-priority initial access signal. All root API usage and console logins are alerted unconditionally.

---

## Execution

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1059 | T1059.009 | Command and Scripting Interpreter: Cloud API | 📋 Planned | — |
| T1651 | — | Cloud Administration Command | 📋 Planned | — |

---

## Persistence

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1098 | T1098.001 | Account Manipulation: Additional Cloud Credentials | 🔄 Testing | CDET-002 |
| T1098 | T1098.003 | Account Manipulation: Additional Cloud Roles | 📋 Planned | — |
| T1136 | T1136.003 | Create Account: Cloud Account | 🔄 Testing | CDET-001 |
| T1078 | T1078.004 | Valid Accounts: Cloud Accounts (persistence via key retention) | 📋 Planned | — |
| T1525 | — | Implant Internal Image | ⬜ Out of Scope | — |
| T1505 | T1505.004 | Server Software Component: IIS Components | ⬜ Out of Scope | — |

---

## Privilege Escalation

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1078 | T1078.004 | Valid Accounts: Cloud Accounts (escalation) | 🔄 Testing | CDET-004 |
| T1484 | T1484.001 | Domain Policy Modification: Group Policy Modification | ⬜ Out of Scope | — |
| T1484 | T1484.002 | Domain or Tenant Policy Modification: Trust Modification | 🔄 Testing | CDET-005 |

**Notes:** IAM privilege escalation through policy attachment (`AttachUserPolicy`, `PutRolePolicy`) and trust modification are both covered. Both managed and inline policy escalation paths are detected by CDET-004.

---

## Defense Evasion

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1562 | T1562.008 | Impair Defenses: Disable Cloud Logs | 🔄 Testing | CDET-003 |
| T1562 | T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | 🔄 Testing | CDET-013 |
| T1070 | T1070.004 | Indicator Removal: File Deletion | 🔄 Testing | CDET-014 |
| T1078 | T1078.004 | Valid Accounts: Cloud Accounts (evasion via legitimate credentials) | 📋 Planned | — |
| T1550 | T1550.001 | Use Alternate Authentication Material: Application Access Token | 🔄 Testing | CDET-012 |

---

## Credential Access

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1552 | T1552.005 | Unsecured Credentials: Cloud Instance Metadata | 🔄 Testing | CDET-007 |
| T1528 | — | Steal Application Access Token | 📋 Planned | — |
| T1110 | — | Brute Force | 📋 Planned | — |
| T1606 | T1606.002 | Forge Web Credentials: SAML Tokens | ⬜ Out of Scope | — |

**Notes:** EC2 instance metadata service (IMDSv1) abuse is the primary pattern for credential theft in AWS. CDET-007 covers both CloudTrail-based anomaly detection and GuardDuty InstanceCredentialExfiltration findings.

---

## Discovery

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1580 | — | Cloud Infrastructure Discovery | 🔄 Testing | CDET-008 |
| T1087 | T1087.004 | Account Discovery: Cloud Account | 📋 Planned | — |
| T1619 | — | Cloud Storage Object Discovery | 📋 Planned | — |
| T1613 | — | Container and Resource Discovery | 📋 Planned | — |
| T1069 | T1069.003 | Permission Groups Discovery: Cloud Groups | 📋 Planned | — |

---

## Lateral Movement

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1550 | T1550.001 | Use Alternate Authentication Material: Application Access Token | 🔄 Testing | CDET-012 |
| T1534 | — | Internal Spearphishing | ⬜ Out of Scope | — |
| T1021 | T1021.007 | Remote Services: Cloud Services | 📋 Planned | — |

**Notes:** Cross-account role assumption chains are the primary lateral movement vector in AWS. CDET-012 detects both single-hop and chained (multi-hop) cross-account assumptions.

---

## Collection

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1530 | — | Data from Cloud Storage Object | 📋 Planned | — |
| T1213 | T1213.003 | Data from Information Repositories: Code Repositories | ⬜ Out of Scope | — |
| T1074 | T1074.002 | Data Staged: Remote Data Staging | 📋 Planned | — |

---

## Exfiltration

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1537 | — | Transfer Data to Cloud Account | 🔄 Testing | CDET-009 |
| T1567 | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | 📋 Planned | — |
| T1020 | — | Automated Exfiltration | 📋 Planned | — |

---

## Impact

| Technique | Sub-Technique | Name | Coverage | Detection ID |
|-----------|--------------|------|----------|-------------|
| T1485 | — | Data Destruction | 🔄 Testing | CDET-010 |
| T1486 | — | Data Encrypted for Impact (ransomware) | 📋 Planned | — |
| T1496 | — | Resource Hijacking | 🔄 Testing | CDET-011 |
| T1489 | — | Service Stop | 📋 Planned | — |
| T1499 | T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood | ⬜ Out of Scope | — |
| T1561 | T1561.001 | Disk Wipe: Disk Content Wipe | ⬜ Out of Scope | — |

---

## Coverage Statistics

| Tactic | Total In-Scope | Active | Testing | Planned | Gap |
|--------|---------------|--------|---------|---------|-----|
| Initial Access | 1 | 0 | 1 | 0 | 0 |
| Execution | 2 | 0 | 0 | 2 | 0 |
| Persistence | 4 | 0 | 2 | 2 | 0 |
| Privilege Escalation | 2 | 0 | 2 | 0 | 0 |
| Defense Evasion | 4 | 0 | 4 | 0 | 0 |
| Credential Access | 3 | 0 | 1 | 2 | 0 |
| Discovery | 5 | 0 | 1 | 4 | 0 |
| Lateral Movement | 2 | 0 | 1 | 1 | 0 |
| Collection | 2 | 0 | 0 | 2 | 0 |
| Exfiltration | 3 | 0 | 1 | 2 | 0 |
| Impact | 4 | 0 | 2 | 2 | 0 |
| **Total** | **32** | **0** | **15** | **17** | **0** |

*Coverage statistics updated as of Phase 2 (Detection Engineering Library). All 14 authored detections are in Testing status.*
