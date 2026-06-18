# Attack Simulation Template

> Copy this template to `attack_simulation/scenarios/{CDET-NNN}_{short_name}_simulation.md`.
> Remove this instruction block before committing.
>
> IMPORTANT: Attack simulations must only be executed in authorized, isolated AWS environments
> that you own or have explicit written permission to test. Never run against production accounts.

---

# Attack Simulation: [Attack Scenario Name]

**Simulation ID:** SIM-NNN
**Target Detection:** CDET-NNN
**ATT&CK Technique:** T1NNN.NNN — [Technique Name]
**Risk Level:** low / medium / high
**Permissions Required:** [e.g., iam:CreateUser, iam:AttachUserPolicy]
**Last Validated:** YYYY-MM-DD
**Author:** [Name]

---

## Objective

[One paragraph describing what this simulation demonstrates. Include:
- The adversary TTP being simulated
- The expected detection trigger
- The data artifacts produced in CloudTrail or other sources]

---

## Prerequisites

### Environment Requirements

- [ ] Isolated AWS test account (separate from any production or shared environment)
- [ ] CloudTrail enabled and logging to S3 in the target region
- [ ] GuardDuty enabled (if relevant to the scenario)
- [ ] AWS credentials with sufficient permissions (see below)
- [ ] Splunk instance connected to the test account's log stream

### Required Permissions

The operator executing this simulation requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "[list required permissions here]"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note:** These permissions exceed the read-only collection role. A separate set of credentials scoped to this simulation must be used. Do not use the same credentials used for telemetry collection.

### Pre-Simulation State Snapshot

Before executing, capture the baseline state:

```bash
python -m scripts.aws_collectors.collect_cli --all \
  --region [REGION] --output-dir data/investigation/pre_simulation/
```

---

## Simulation Steps

### Step 1 — [Action Name]

**Description:** [What this step does and why]

**AWS CLI Command:**
```bash
aws [service] [command] \
  --[parameter] "[value]" \
  --region [REGION]
```

**Expected CloudTrail Event:**
- `eventName`: [API call]
- `userIdentity.type`: [IAM / AssumedRole / Root]
- `requestParameters`: [key fields to appear]

**Verification:**
```bash
# Confirm the action succeeded
aws [service] [describe-command] --[resource-id] [ID]
```

---

### Step 2 — [Action Name]

**Description:** [What this step does and why]

**AWS CLI Command:**
```bash
aws [service] [command] --[parameter] "[value]"
```

**Expected CloudTrail Event:**
- `eventName`: [API call]

---

### Step N — [Final Action]

[Continue numbering steps as needed]

---

## Expected Detection Behavior

| Detection | Expected Result | Expected Timing |
|-----------|----------------|-----------------|
| CDET-NNN | Alert fires | Within [N] minutes of simulation |
| [Other CDET] | Alert fires / Does not fire | [Timing] |

**Expected CloudTrail events produced by this simulation:**

```json
[
  {
    "eventName": "[FIRST_EVENT]",
    "eventSource": "[service].amazonaws.com",
    "userIdentity": {
      "type": "IAMUser",
      "arn": "[SIMULATION_ROLE_ARN]"
    }
  },
  {
    "eventName": "[SECOND_EVENT]",
    "eventSource": "[service].amazonaws.com"
  }
]
```

---

## Sample Dataset Generation

After executing the simulation:

1. Collect CloudTrail events covering the simulation window:
```bash
python -m scripts.aws_collectors.collect_cli --collector cloudtrail \
  --region [REGION] --lookback-hours 1 \
  --output-dir data/samples/
```

2. Filter the output to only the simulation events:
```bash
# Rename the output file to follow sample naming convention
mv data/samples/cloudtrail_*.ndjson \
   data/samples/cloudtrail_[scenario_description].ndjson
```

3. Review and anonymize if necessary before committing to the repository.

---

## Cleanup

**Execute these cleanup steps in reverse order of simulation. Do not skip cleanup.**

```bash
# Step N cleanup — [describe what is being reversed]
aws [service] [delete-command] --[resource-id] [ID]

# Step N-1 cleanup
aws [service] [delete-command] --[resource-id] [ID]

# Verify clean state
python -m scripts.aws_collectors.collect_cli --all \
  --region [REGION] --output-dir data/investigation/post_simulation/
```

---

## Atomic Red Team Mapping

If an equivalent Atomic Red Team test exists, reference it:

| Atomic Test | Technique | Test Number |
|-------------|-----------|-------------|
| [Test Name] | T1NNN.NNN | [Atomic Test #N] |

**Differences from Atomic Red Team test:**
[Note any differences in approach, scope, or cleanup procedure]

---

## Notes and Observations

[Document any observations from executing this simulation:
- Timing between event generation and detection firing
- Unexpected events generated
- Detection gaps observed
- Tuning recommendations]
