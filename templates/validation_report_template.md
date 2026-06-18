# Detection Validation Report Template

> The validation framework generates this report automatically after each run.
> This template documents the expected format and can be used for manual validation runs.
> Copy to `data/validation_results/{YYYY-MM-DD}_validation_report.md` for manual reports.

---

# Detection Validation Report

| Field | Value |
|-------|-------|
| **Report Date** | YYYY-MM-DD HH:MM UTC |
| **Run Type** | full / single-detection / regression |
| **Environment** | sample-data / historical-cloudtrail / post-simulation |
| **Total Detections Tested** | N |
| **Overall Result** | PASS / FAIL / PARTIAL |

---

## Summary

| Status | Count |
|--------|-------|
| PASS | N |
| FAIL | N |
| ERROR | N |
| SKIPPED | N |
| **Total** | N |

**Coverage:** N of M planned detections have passing validation suites (N%)

---

## Validation Results by Detection

| Detection ID | Name | Test Cases | Passed | Failed | Errors | Status |
|-------------|------|-----------|--------|--------|--------|--------|
| CDET-001 | [Name] | N | N | N | N | PASS / FAIL |
| CDET-002 | [Name] | N | N | N | N | PASS / FAIL |

---

## Detailed Results

### CDET-NNN — [Detection Name]

**Overall Status:** PASS / FAIL
**Severity:** critical / high / medium / low
**Tactic:** [ATT&CK Tactic]
**Technique:** T1NNN.NNN

#### Test Case Results

**Test Case 1: [Name]**
- Input file: `data/samples/[filename].ndjson`
- Expected alert: true / false
- Actual alert: true / false
- Matched events: N
- Status: **PASS / FAIL**
- Duration: NNms

**Test Case 2: [Name]**
- Input file: `data/samples/[filename].ndjson`
- Expected alert: true / false
- Actual alert: true / false
- Status: **PASS / FAIL**

#### Notes

[Any observations about this detection's validation results — tuning recommendations, borderline cases, or issues with test data.]

---

## Failed Detections

[For each FAIL status, provide the detail needed to diagnose and fix the failure.]

### CDET-NNN — [Detection Name] — FAIL

**Failure Reason:**
[Describe why the test case failed — detection did not fire when expected, fired when it should not have, or produced incorrect output fields.]

**Failing Test Case:**
- Expected: `expected_alert: true`
- Actual: Detection did not fire
- Input events processed: N
- Events that matched pre-filter: N
- Events that matched final filter: N

**Recommended Fix:**
[Specific recommendation — e.g., adjust SPL filter condition, update test data, fix field name reference.]

---

## Coverage Analysis

### Coverage by ATT&CK Tactic

| Tactic | Planned | Active | Validated | Coverage % |
|--------|---------|--------|-----------|------------|
| Initial Access | N | N | N | N% |
| Persistence | N | N | N | N% |
| Privilege Escalation | N | N | N | N% |
| Defense Evasion | N | N | N | N% |
| Credential Access | N | N | N | N% |
| Discovery | N | N | N | N% |
| Lateral Movement | N | N | N | N% |
| Exfiltration | N | N | N | N% |
| Impact | N | N | N | N% |
| **Total** | N | N | N | N% |

### Coverage Gaps

Techniques identified as in-scope for this program but without a passing active detection:

| Technique | Tactic | Status | Gap Reason |
|-----------|--------|--------|-----------|
| T1NNN.NNN | [Tactic] | Planned | Detection not yet authored |
| T1NNN.NNN | [Tactic] | Testing | Test cases failing |

---

## Validation Run Configuration

| Parameter | Value |
|-----------|-------|
| Input source | sample-data / historical / post-simulation |
| CloudTrail lookback (if historical) | N hours |
| AWS account | [account ID or "N/A for sample"] |
| AWS region | [region or "N/A for sample"] |
| Validation framework version | [version] |
| Python version | [version] |

---

## Action Items

| # | Action | Owner | Priority | Due Date |
|---|--------|-------|----------|----------|
| 1 | [Fix failing test case for CDET-NNN] | Detection Engineering | High | YYYY-MM-DD |
| 2 | [Add test cases for CDET-NNN (currently draft)] | Detection Engineering | Medium | YYYY-MM-DD |
| 3 | [Author missing detection for T1NNN.NNN gap] | Detection Engineering | Low | YYYY-MM-DD |
