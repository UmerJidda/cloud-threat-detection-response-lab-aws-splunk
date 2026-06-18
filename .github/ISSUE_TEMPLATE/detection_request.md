---
name: Detection Request
about: Request a new detection for a specific adversary TTP
title: '[DETECTION REQUEST] <MITRE Technique ID> - <Brief Description>'
labels: detection-request, needs-triage
assignees: ''
---

## Detection Request

### Threat Description

<!-- What adversary behavior should this detect? Be specific. -->

### MITRE ATT&CK Mapping

- **Tactic:** <!-- e.g., Defense Evasion (TA0005) -->
- **Technique:** <!-- e.g., T1562.008 – Impair Defenses: Disable Cloud Logs -->
- **ATT&CK URL:** <!-- https://attack.mitre.org/techniques/TXXXX/YYY/ -->

### Why This Detection Is Needed

<!-- What's the threat intelligence, red team finding, or gap analysis driving this? -->

### Required Log Sources

<!-- Which AWS logs are needed? CloudTrail, GuardDuty, VPC Flow Logs, S3 Access Logs, etc. -->

- [ ] CloudTrail
- [ ] VPC Flow Logs
- [ ] GuardDuty
- [ ] S3 Access Logs
- [ ] Other: ___________

### Expected Data (Sample Event)

```json
// Paste a sanitized sample CloudTrail event or other log entry if available
```

### Detection Hypothesis

<!-- Complete this sentence: "This detection fires when an actor does X, which indicates Y" -->

### Known False Positive Scenarios

<!-- What legitimate activity might trigger this detection? -->

### Priority

- [ ] Critical (active threat, immediate need)
- [ ] High (known TTP in environment, high risk)
- [ ] Medium (coverage gap, moderate risk)
- [ ] Low (nice-to-have, low risk)

### Additional Context

<!-- Any other relevant information, threat intel reports, or references -->
