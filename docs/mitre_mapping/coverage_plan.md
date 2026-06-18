# Detection Coverage Plan

## Objective

This document defines which MITRE ATT&CK techniques will be covered by this detection program, the priority order for development, and the rationale for technique selection. It serves as the roadmap for detection authorship across all phases.

---

## Prioritization Criteria

Detections are prioritized using four factors:

1. **Threat relevance** — How frequently is this technique observed against AWS environments in the wild? (Based on CrowdStrike, Mandiant, and AWS threat intelligence reports.)
2. **Signal quality** — How unambiguously observable is the technique in CloudTrail or other available data sources?
3. **Business impact** — What is the potential blast radius if an attacker successfully executes this technique without detection?
4. **Detection difficulty** — How hard is it to write a high-fidelity detection without excessive false positives?

Each technique is scored 1–3 on each criterion (higher = more important or easier). Priority = sum of scores.

---

## Tier 1 — High Priority (Target: Phase 3)

These detections cover the most impactful and most commonly observed adversary behaviors in AWS environments.

| Technique | Name | Threat | Signal | Impact | Difficulty | Priority |
|-----------|------|--------|--------|--------|-----------|---------|
| T1562.008 | Impair Defenses: Disable Cloud Logs | 3 | 3 | 3 | 3 | **12** |
| T1136.003 | Create Account: Cloud Account | 3 | 3 | 3 | 3 | **12** |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | 3 | 3 | 3 | 3 | **12** |
| T1078.004 | Valid Accounts: Cloud Accounts (console login) | 3 | 3 | 3 | 2 | **11** |
| T1484.002 | Trust Modification | 3 | 3 | 3 | 2 | **11** |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata | 3 | 2 | 3 | 2 | **10** |
| T1537 | Transfer Data to Cloud Account | 3 | 2 | 3 | 2 | **10** |

### Rationale — Tier 1

**T1562.008 (Disable CloudTrail):** Adversaries routinely disable logging as a first post-compromise action. This is a critical blind spot if undetected. Signal is unambiguous — `StopLogging` and `DeleteTrail` have no legitimate operational use during normal hours.

**T1136.003 (Create Cloud Account):** Creating a new IAM user is a primary persistence mechanism. The signal is clean and the false positive rate is manageable with a pipeline exclusion lookup.

**T1098.001 (Additional Cloud Credentials):** Creating new access keys for existing users is the most common method for maintaining persistence after initial compromise. Detecting `CreateAccessKey` on sensitive principals is high-priority.

**T1078.004 (Valid Accounts):** Compromised credential use is the most common initial access method in cloud environments. Geolocation anomalies on console login are a strong signal.

---

## Tier 2 — Medium Priority (Target: Phase 4)

These detections cover important TTPs with moderate false positive rates that require more sophisticated tuning.

| Technique | Name | Threat | Signal | Impact | Difficulty | Priority |
|-----------|------|--------|--------|--------|-----------|---------|
| T1580 | Cloud Infrastructure Discovery | 3 | 2 | 2 | 2 | **9** |
| T1087.004 | Account Discovery: Cloud Account | 3 | 2 | 2 | 2 | **9** |
| T1485 | Data Destruction | 2 | 2 | 3 | 2 | **9** |
| T1496 | Resource Hijacking | 2 | 2 | 3 | 2 | **9** |
| T1070.004 | Indicator Removal: File Deletion | 2 | 2 | 2 | 2 | **8** |
| T1021.007 | Remote Services: Cloud Services | 2 | 2 | 2 | 2 | **8** |
| T1530 | Data from Cloud Storage Object | 2 | 2 | 2 | 2 | **8** |

---

## Tier 3 — Hunting Queries (Target: Phase 6)

These are lower-confidence searches suitable for threat hunting rather than automated alerting. They are expected to require significant analyst time per hit.

| Technique | Name | Notes |
|-----------|------|-------|
| T1619 | Cloud Storage Object Discovery | High volume; useful for baseline deviation hunts |
| T1074.002 | Data Staged: Remote Data Staging | Difficult to distinguish from legitimate cross-region replication |
| T1528 | Steal Application Access Token | Requires application log correlation not available via CloudTrail alone |
| T1567.002 | Exfiltration to Cloud Storage | Requires S3 access log correlation |
| T1110 | Brute Force | CloudTrail provides limited signal; ConsoleLogin failures are low-fidelity |

---

## Detection Development Schedule

| Phase | Detections | Techniques |
|-------|-----------|-----------|
| Phase 3 | CDET-001 to CDET-007 | All Tier 1 techniques |
| Phase 4 | CDET-008 to CDET-014 | Tier 2 techniques |
| Phase 6 | Hunting queries HQ-001 to HQ-005 | Tier 3 techniques |

---

## Coverage Gaps and Acceptance

The following techniques are recognized gaps in this program. They are out of scope due to data source limitations or intentional de-prioritization.

| Technique | Name | Gap Reason |
|-----------|------|-----------|
| T1190 | Exploit Public-Facing Application | Requires WAF/application logs; not in current data scope |
| T1566.002 | Phishing: Spearphishing Link | Requires email gateway logs; not in current data scope |
| T1606.002 | Forge Web Credentials: SAML Tokens | Requires IdP logs not available via CloudTrail |
| T1486 | Data Encrypted for Impact | Limited observable signal in management plane logs |

These gaps are reviewed at each program phase review. If new data sources become available, gap techniques may be promoted to Tier 1 or 2.
