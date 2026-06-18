# Severity Framework

## Overview

Detection severity communicates the risk level of a true positive. It is set by the detection author based on the inherent danger of the behavior when it is genuinely malicious — not based on frequency, data source, or how loud the alert will be.

Severity is used for:
- Prioritizing analyst response time (SLA enforcement)
- Routing alerts to the appropriate team or escalation path
- Reporting and trend analysis
- Detection coverage gap assessment

---

## Severity Levels

### Critical

**Definition:** The detected behavior is almost exclusively malicious. Legitimate causes are extremely rare. If this fires, assume active compromise until proven otherwise.

**Characteristics:**
- Immediate analyst response required (within 15 minutes during business hours)
- Automated containment actions may be pre-approved for this severity
- Generates escalation to senior staff if not acknowledged within SLA

**Examples:**
- Root account API activity (any call from the root principal)
- CloudTrail logging disabled in any region
- Mass IAM credential deletion
- Data exfiltration to unknown external account
- GuardDuty finding: UnauthorizedAccess or Backdoor category at severity ≥ 8.0

---

### High

**Definition:** The detected behavior is a strong indicator of malicious intent. Legitimate causes exist but are uncommon and should be verifiable in seconds.

**Characteristics:**
- Analyst response required within 1 hour
- Requires investigation before ruling out as false positive
- Not eligible for automated suppression without documented justification

**Examples:**
- New IAM user created outside approved provisioning pipeline
- Admin policy attached to user or role
- New cross-account trust relationship created
- Console login from unexpected geolocation
- Access key created for a sensitive principal
- Security group rule opened to 0.0.0.0/0 on a sensitive port

---

### Medium

**Definition:** Suspicious behavior that has plausible legitimate explanations. Context and corroboration are required before escalation.

**Characteristics:**
- Analyst review required within 4 hours
- May be triaged to low-priority queue if corroborating evidence is absent
- Can be suppressed via lookup table for known-good patterns

**Examples:**
- AssumeRole activity from an unusual principal
- IAM enumeration (multiple List/Describe calls in a short window)
- Security group public exposure on non-standard ports
- GuardDuty finding: Recon or Stealth category at severity 4.0–6.9
- Access key last used from a different region than usual
- New role with unusual trust policy

---

### Low

**Definition:** Weak signal. Useful for hunting and correlation; not actionable alone.

**Characteristics:**
- Review within 24 hours
- Primarily useful when correlated with other alerts
- High expected false positive rate — suppression is expected

**Examples:**
- Single failed API call (AccessDenied)
- Describe/List API calls with no subsequent write activity
- IAM user password changed
- GuardDuty finding: Policy category
- Minor security group configuration change

---

## Severity Assignment Criteria

Use the following decision framework when assigning severity to a new detection:

```
1. Is the behavior almost exclusively malicious with essentially no legitimate use case?
   YES → Critical

2. Does the behavior represent a significant security control failure, and legitimate
   causes are rare or immediately verifiable?
   YES → High

3. Does the behavior warrant investigation but has known-good patterns that account
   for a meaningful portion of occurrences?
   YES → Medium

4. Is the behavior a weak signal that requires corroboration to be meaningful?
   YES → Low
```

---

## Confidence Score

In addition to severity, each detection carries a confidence score that represents how often the detection fires as a true positive in practice.

| Confidence | Description |
|------------|-------------|
| High | Detection fires as true positive in ≥ 80% of cases |
| Medium | True positive in 40–79% of cases |
| Low | True positive in < 40% of cases; requires significant corroboration |

Confidence is set initially by the detection author based on available data and is updated when sufficient alert volume has been collected to make an empirical measurement.

**Severity and confidence are independent.** A detection can be Critical severity with Low confidence (e.g., a new detection before any real-world validation data).

---

## Combined Risk Rating

For reporting and prioritization purposes, a combined risk rating is calculated:

| Severity | High Confidence | Medium Confidence | Low Confidence |
|----------|-----------------|-------------------|----------------|
| Critical | P0 | P0 | P1 |
| High | P1 | P1 | P2 |
| Medium | P2 | P2 | P3 |
| Low | P3 | P3 | P3 |

**P0** — Immediate response, executive notification if unresolved within 1 hour
**P1** — High-priority queue, response within 1 hour business hours
**P2** — Standard queue, response within 4 hours
**P3** — Low-priority queue, batch review within 24 hours

---

## Severity in Splunk

Detection severity is surfaced in Splunk via the `severity` field set in the detection SPL:

```spl
| eval severity="high"
| eval urgency=case(
    severity="critical", "1",
    severity="high",     "2",
    severity="medium",   "3",
    severity="low",      "4",
    true(),              "5"
  )
```

The `urgency` field maps to Splunk Enterprise Security's built-in priority system for Notable Event triage.
