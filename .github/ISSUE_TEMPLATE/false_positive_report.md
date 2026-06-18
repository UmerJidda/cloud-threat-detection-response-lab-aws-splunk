---
name: False Positive Report
about: Report a detection that fired incorrectly on legitimate activity
title: '[FALSE POSITIVE] <Detection ID> - <Brief Description>'
labels: false-positive, needs-triage
assignees: ''
---

## False Positive Report

### Detection Information

- **Detection ID:** <!-- e.g., DETECT-0005 -->
- **Detection Name:** <!-- e.g., CloudTrail Logging Disabled -->
- **Date/Time of False Positive:** <!-- YYYY-MM-DD HH:MM UTC -->
- **Environment:** <!-- lab | staging | production -->

### What Happened

<!-- Describe what legitimate activity triggered the alert -->

### Why This Is a False Positive

<!-- Explain why this should NOT have fired — what was the intended behavior? -->

### Log Evidence

```json
// Paste the CloudTrail event or Splunk search result that triggered (sanitize sensitive data)
```

### Splunk Alert Details

- **Alert fired at:** <!-- timestamp -->
- **Actor (IAM principal):** <!-- role ARN or username, sanitized -->
- **Source IP:** <!-- if relevant -->
- **AWS Region:** <!-- e.g., us-east-1 -->

### Suggested Suppression

<!-- How should we tune the detection to avoid this FP in the future?
     e.g., "Exclude the IAM role arn:aws:iam::*:role/TerraformRole from this detection" -->

### Frequency

- [ ] This was a one-time occurrence
- [ ] This happens occasionally (< once/week)
- [ ] This fires frequently (daily or more)

### Business Impact

<!-- Did this FP cause any disruption, unnecessary incident response, etc.? -->
