# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial repository structure and documentation framework
- README with architecture diagram, MITRE ATT&CK coverage table, and project roadmap
- CONTRIBUTING.md with detection submission standards, SPL style guide, and Python style guide
- SECURITY.md with responsible disclosure policy
- GitHub issue templates for detection requests, false positive reports, and bug reports
- GitHub PR template with detection validation checklist
- CI workflow skeleton for detection validation pipeline
- `config/lab_config.example.yaml` — reference configuration for lab environment
- `config/mitre_mappings.yaml` — ATT&CK technique to detection ID mappings
- `detections/README.md` — detection catalog and metadata schema documentation
- `.gitignore` — Python, AWS, and Splunk-specific ignore patterns

---

## [0.1.0] - 2026-06-15

### Added
- Project inception: Cloud Threat Detection & Response Lab
- Defined scope: AWS CloudTrail, GuardDuty, VPC Flow Logs → Splunk SIEM
- Established MITRE ATT&CK v15 (IaaS) as the detection coverage framework
- Defined 12 initial detection targets across 8 MITRE tactics
- Selected technology stack: Python 3.11, Splunk 9.x, Boto3, pytest, moto
