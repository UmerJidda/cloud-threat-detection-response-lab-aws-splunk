# Contributing to Cloud Threat Detection Lab

Thank you for contributing to this detection engineering project. This document describes the standards and process for submitting contributions.

---

## Code of Conduct

All contributors are expected to maintain a professional, inclusive, and constructive environment. Harassment, discrimination, or bad-faith contributions will not be tolerated.

---

## Types of Contributions

### New Detections

Before building a new detection:

1. Search existing detections to avoid duplicates
2. Open a **Detection Request** issue using the provided template
3. Ensure the TTP is mappable to MITRE ATT&CK
4. Confirm the required log sources are available in the lab

Each detection must include:
- Detection metadata YAML header
- Annotated SPL query
- MITRE ATT&CK mapping
- At least one test case (true positive simulation)
- Response action reference
- Tuning notes for known false positives

### False Positive Reports

Use the **False Positive Report** issue template. Include:
- Detection name and ID
- Environment context (region, service, account type)
- Specific log event that triggered incorrectly
- Suggested tuning or suppression logic

### Bug Reports

Use the **Bug Report** issue template for issues with automation scripts, tooling, or CI pipeline failures.

### Documentation

Documentation PRs are welcome. Follow the existing formatting conventions. Do not alter detection logic in documentation-only PRs.

---

## Branching Strategy

```
main          → Stable, validated detections only
develop       → Integration branch for reviewed but not yet promoted content
feature/*     → Individual detection or feature development
hotfix/*      → Urgent fixes to production detections
```

All contributions must be submitted via Pull Request to `develop`. Direct commits to `main` are not permitted.

---

## Detection Submission Checklist

Before opening a Pull Request, verify:

- [ ] Detection file follows the naming convention: `DETECT-XXXX_short_description.yaml`
- [ ] MITRE ATT&CK tactic and technique are correctly mapped
- [ ] Required data sources are documented
- [ ] SPL query has been tested against sample data
- [ ] False positive rate has been assessed
- [ ] Tuning notes are included
- [ ] Response action is referenced or created
- [ ] Unit test added under `tests/unit/`
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] PR template checklist is completed

---

## SPL Style Guide

- Use explicit field names; avoid `*` wildcards in index searches
- Comment non-obvious SPL logic with `| comment` or inline `/* */` where applicable (SPL 9.x)
- Use `stats` over `chart` unless visualization is required
- Apply `| eval` for derived fields before aggregation
- Name saved searches: `DETECT - [TTP Description] - [Data Source]`
- Threshold values must be externalized to macros (see `splunk/macros/`)

Example naming:
```
DETECT - New IAM Access Key Created - CloudTrail
DETECT - CloudTrail Logging Disabled - CloudTrail
DETECT - S3 Bucket Public ACL Set - CloudTrail
```

---

## Python Style Guide

- Python 3.11+
- Follow PEP 8; use `ruff` for linting (`ruff check .`)
- Type annotations required on all function signatures
- No hardcoded credentials, ARNs, or account IDs — use environment variables or AWS Parameter Store
- All Lambda functions must have unit tests with `moto` mocking AWS services
- Log using the standard `logging` module; no `print()` in production code

---

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

Types:
- `feat` — New detection or feature
- `fix` — Bug fix or FP suppression
- `docs` — Documentation only
- `test` — Test additions or fixes
- `refactor` — Code restructuring without behavior change
- `ci` — CI/CD pipeline changes
- `chore` — Dependency updates, config changes

Examples:
```
feat(detection): add CloudTrail logging disabled detection (T1562.008)
fix(detection): reduce FP rate in IAM key creation alert for service accounts
docs(playbook): add IR playbook for EC2 metadata abuse
test(automation): add unit tests for isolate_ec2 Lambda function
```

---

## Testing

Run the full test suite before submitting:

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Lint
ruff check .

# Unit tests
pytest tests/unit/ -v

# Integration tests (requires lab connectivity)
pytest tests/integration/ -v --lab-mode
```

All tests must pass before a PR can be merged.

---

## Review Process

1. Automated CI runs on all PRs (lint, tests, SPL syntax check)
2. Peer review required from at least one maintainer
3. Detection PRs require validation evidence (screenshot or log sample showing TP)
4. Approved PRs are merged to `develop`; promotion to `main` happens on release cycles

---

## Questions

Open a GitHub Discussion or tag a maintainer in your PR for guidance.
