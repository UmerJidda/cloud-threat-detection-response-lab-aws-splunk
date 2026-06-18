# Security Policy

## Scope

This repository contains detection engineering content, attack simulation scripts, and automated response code intended for use in **isolated, authorized lab environments only**.

## Responsible Use

- All attack simulation scripts in `attack_simulation/` must only be run against environments you own or have explicit written authorization to test
- Never deploy automation scripts against production AWS accounts without thorough review and change management approval
- Response automation (Lambda functions, Splunk Adaptive Response) should be tested in lab before production use
- No real AWS credentials, access keys, secrets, or PII should ever be committed to this repository

## Reporting Security Issues

If you discover a security vulnerability in this project's code (e.g., a credential leak, insecure automation logic, or code injection risk):

1. **Do not open a public GitHub issue**
2. Email the maintainer directly with subject line: `[SECURITY] CloudThreatDetectionLab - <brief description>`
3. Include: description of the issue, steps to reproduce, potential impact, and suggested fix if available
4. You will receive acknowledgment within 48 hours and a resolution timeline within 7 days

## What Qualifies as a Security Issue

- Hardcoded credentials, tokens, or secrets in any file
- Command injection vulnerabilities in Python scripts
- Insecure IAM permissions in example policies (overly permissive)
- Logic errors in response automation that could cause unintended resource destruction
- Insecure handling of log data or sensitive CloudTrail events

## What Does Not Qualify

- Attack simulation scripts behaving as documented (they are intentionally adversarial)
- Detections that generate false positives (use the False Positive issue template instead)
- Feature requests or documentation improvements

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch | ✅ Yes |
| develop branch | ⚠️ Best effort |
| feature branches | ❌ No |
