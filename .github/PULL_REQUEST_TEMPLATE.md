# Pull Request

## Summary

<!-- What does this PR do? One or two sentences. -->

## Type of Change

- [ ] New detection
- [ ] Detection tuning / FP reduction
- [ ] New automation / response action
- [ ] Bug fix
- [ ] Documentation update
- [ ] Test improvement
- [ ] CI/CD change
- [ ] Dependency update

---

## For Detection PRs — Validation Checklist

### Detection Quality
- [ ] Detection YAML follows the schema defined in `detections/README.md`
- [ ] MITRE ATT&CK tactic, technique, and sub-technique are correctly mapped
- [ ] Hypothesis clearly explains what adversary behavior is being detected
- [ ] SPL query has been tested in Splunk and returns expected results
- [ ] Required data sources are documented

### False Positive Assessment
- [ ] False positive scenarios have been identified and documented
- [ ] Tuning notes are included
- [ ] FP rate estimated: _____ alerts/day in normal environment

### Testing
- [ ] True positive test case documented (simulation script or sample event referenced)
- [ ] Detection fires correctly against simulated attack data (evidence attached or described below)
- [ ] Unit test added under `tests/unit/` if automation is included

### Documentation
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Response action references an existing or new IR playbook
- [ ] `config/mitre_mappings.yaml` updated with new detection entry

---

## For Automation / Script PRs — Checklist

- [ ] No hardcoded credentials, ARNs, or account IDs
- [ ] Environment variables used for all secrets and configuration
- [ ] `dry_run` mode supported and defaults to `True`
- [ ] Unit tests cover the main code paths (using `moto` for AWS calls)
- [ ] Error handling with meaningful log messages
- [ ] Type annotations on all function signatures

---

## Validation Evidence

<!-- For detections: paste a screenshot of the alert firing, or describe the test scenario -->
<!-- For automation: describe the test environment and results -->

```
// Paste relevant log output, Splunk search results, or test output here
```

---

## Related Issues

Closes #<!-- issue number -->

## Reviewer Notes

<!-- Anything specific you want reviewers to focus on? -->
