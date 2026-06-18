# Detection Tuning Guidelines

## Overview

Detection tuning is the process of reducing false positives while preserving true positive coverage. Tuning is not a one-time activity — it is an ongoing operational discipline. These guidelines govern when, how, and to what degree detections should be tuned.

---

## Tuning Principles

1. **Tune suppressions, not logic.** Prefer adding entries to lookup tables over modifying the SPL query. Lookup-based suppression can be updated by operations staff without a deployment cycle.

2. **Never suppress by behavior alone.** A suppression must be anchored to a specific principal ARN, account ID, or a documented business justification. Suppressing on "looks like automation" without an ARN creates future blind spots.

3. **Document every suppression.** Suppressions that are not documented become invisible debt. Every lookup table entry must have a `reason` column and a `date_added` column.

4. **Test after tuning.** After any tuning change, re-run the detection's validation suite to confirm true positive test cases still pass.

5. **Measure, then tune.** Do not tune based on intuition. Measure the false positive rate over at least 72 hours of production data before making threshold adjustments.

6. **Time-bound suppressions where possible.** Temporary suppressions (e.g., during a change window) should have an `expiry_date` field and be reviewed when they expire.

---

## Pre-Promotion Tuning Checklist

Before promoting a detection from Testing to Active, complete the following:

- [ ] Run detection against 30 days of CloudTrail history (if available)
- [ ] Count FP candidates — events that fired but are likely benign
- [ ] Categorize each FP candidate (automation, known service, expected pattern)
- [ ] Add suppression lookup entries for known-good principals
- [ ] Verify positive test cases still pass after suppression
- [ ] Document expected FP rate in `detection.yaml` under `false_positive_notes`
- [ ] Set `confidence` based on measured FP/TP ratio

---

## Suppression Architecture

### Lookup Tables

All suppression lookup tables are stored in `splunk/lookups/`. Each table follows this schema:

**`approved_iam_principals.csv`**
```
arn,reason,date_added,expiry_date,added_by
arn:aws:iam::123456789012:role/TerraformRole,Infrastructure automation via Terraform CI,2024-01-15,,security-engineer@example.com
```

**`automation_role_arns.csv`**
```
arn,service_name,reason,date_added,added_by
arn:aws:iam::123456789012:role/GithubActionsRole,GitHub Actions,CICD pipeline for application deployments,2024-01-15,security-engineer@example.com
```

**`approved_cidr_ranges.csv`**
```
cidr,description,owner,date_added
10.0.0.0/8,Internal corporate network,Network Team,2024-01-15
198.51.100.0/24,VPN egress pool,IT Operations,2024-01-15
```

### Using Lookups in SPL

```spl
`aws_cloudtrail_index`
eventName=CreateUser
| eval principal_arn=coalesce('userIdentity.arn', "unknown")
| lookup approved_iam_principals arn AS principal_arn OUTPUT approved, reason AS suppression_reason
| where isnull(approved) OR approved!="true"
```

### Expiry Review Process

Monthly, run the following to identify expired suppressions:

```spl
| inputlookup approved_iam_principals
| where isnotnull(expiry_date) AND expiry_date < now()
| table arn, reason, expiry_date, added_by
```

---

## Threshold Tuning

For detections that trigger on volume thresholds (e.g., API enumeration), thresholds should be set based on the following process:

### Step 1 — Baseline Measurement

Run the detection logic without a threshold filter over 30 days of data:

```spl
`aws_cloudtrail_index`
earliest=-30d
eventName IN ("ListUsers", "ListRoles", "ListPolicies", ...)
| eval principal_arn=coalesce('userIdentity.arn', "unknown")
| stats count AS total_calls BY principal_arn, date_mday
| stats avg(total_calls) AS avg_daily, max(total_calls) AS max_daily, p95(total_calls) AS p95_daily
  BY principal_arn
```

### Step 2 — Set Threshold at 3× Baseline

The initial threshold should be set at approximately 3× the 95th percentile of baseline call volume for a given principal type. This provides headroom above normal variation without suppressing low-volume attacks.

### Step 3 — Validate Against Attack Simulation Data

Run the detection against the sample dataset representing the attack scenario. Confirm the simulated attack crosses the threshold.

### Step 4 — Document

Record the baseline measurement, threshold rationale, and review date in `detection.yaml`.

---

## Post-Deployment Tuning Monitoring

After a detection reaches Active status, monitor the following weekly for the first month, then monthly thereafter:

| Metric | Target | Action if Exceeded |
|--------|--------|--------------------|
| FP/day | < 5 (HIGH/CRITICAL), < 20 (MEDIUM/LOW) | Investigate FP categories; add lookup entries |
| Total alerts/day | Review if > 100 | Threshold may need adjustment |
| True positives confirmed | At least 1 per 90 days | Review if detection is covering its intended behavior |
| Suppression entry growth | < 20 new entries/month | Investigate if suppression is masking systematic FP issue |

---

## False Positive Escalation

If a detection generates FPs that cannot be resolved through lookup-based suppression without creating unacceptable blind spots, escalate to a logic review:

### Logic Review Process

1. Collect 10+ representative FP events
2. Identify the common distinguishing attribute(s) that separate FPs from TPs
3. Evaluate whether adding that attribute as a filter condition would exclude any TP scenario
4. If TP coverage can be maintained, update `detection.spl`
5. Update test cases in `detection.yaml` to cover the adjusted logic
6. Peer review required before merging

### When to Deprecate

Deprecate a detection rather than tune it if:
- The FP rate exceeds 95% and cannot be reduced without eliminating TP coverage
- The underlying data source has changed such that the detection logic is no longer valid
- A more precise detection supersedes this one
- The threat scenario is no longer relevant to the environment

---

## Change Control for Tuning

| Change Type | Review Required | CI Required |
|-------------|-----------------|-------------|
| Add entry to suppression lookup | No peer review | Re-run validation suite |
| Remove entry from suppression lookup | Brief review (comment in PR) | Re-run validation suite |
| Change SPL logic | Full peer review | Full CI pipeline |
| Change severity | Brief review | Full CI pipeline |
| Change threshold | Brief review + baseline data | Full CI pipeline |
| Deprecate detection | Senior engineer approval | N/A |

All changes are tracked via Git commit history. Lookup table changes must include the `reason`, `date_added`, and `added_by` fields in the CSV row.
