# Detection Template

> Copy this template to `detections/{tactic}/{CDET-NNN}_{short_name}/` and fill in all sections.
> Remove this instruction block before committing.

---

## Detection Metadata

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-NNN |
| **Name** | [Short descriptive name of the behavior detected] |
| **Status** | draft |
| **Severity** | critical / high / medium / low |
| **Confidence** | high / medium / low |
| **Created** | YYYY-MM-DD |
| **Author** | [Name or team] |

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | [e.g., Persistence] |
| **Technique ID** | [e.g., T1136.003] |
| **Technique Name** | [e.g., Create Account: Cloud Account] |
| **Secondary Techniques** | [if applicable] |

---

## Hypothesis

**What adversary behavior does this detect?**

[One paragraph describing the adversary action this detection is designed to catch. Write from the attacker's perspective — what are they trying to accomplish, and how does this API call or event pattern reveal that intent.]

**Why is this detectable in CloudTrail / GuardDuty / Security Hub?**

[Explain the specific data artifact that makes this behavior observable. Reference the exact field names that carry signal.]

---

## Data Requirements

| Field | Value |
|-------|-------|
| **Primary Data Source** | cloudtrail / guardduty / securityhub / iam |
| **Splunk Index** | aws_cloudtrail / aws_security / aws_alerts |
| **Sourcetype** | aws:cloudtrail:normalized / aws:guardduty:finding / etc. |

**Required Fields:**
- `eventName`
- `userIdentity.arn`
- `sourceIPAddress`
- [list any other required fields]

---

## Detection Logic

**Detection File:** `detection.spl`

**SPL Summary:**

[1–3 sentence plain-English description of what the SPL query does. This should be understandable without reading the SPL.]

**Thresholds (if applicable):**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| [e.g., Minimum API calls] | [e.g., 50] | [e.g., 3× 95th percentile baseline] |

---

## False Positive Analysis

**Expected false positive sources:**

| Source | Description | Suppression Method |
|--------|-------------|-------------------|
| [e.g., Terraform pipeline] | [IAM user creation from CI/CD role] | [Add role ARN to approved_iam_principals.csv] |

**Expected FP rate before suppression:** [estimate, e.g., 5–10 per day]
**Expected FP rate after suppression:** [estimate, e.g., < 1 per day]

---

## Test Cases

### Positive Test Case (expected_alert: true)

**Scenario:** [Describe the attack scenario this test represents]

**Input file:** `data/samples/cloudtrail_{scenario_name}.ndjson`

**What the test event represents:**
- Event: `[eventName]`
- Principal: `[arn:aws:iam::123456789012:user/attacker]`
- Source IP: `[external or unexpected IP]`
- Key distinguishing field: `[field=value]`

---

### Negative Test Case (expected_alert: false)

**Scenario:** [Describe the legitimate activity this test represents]

**Input file:** `data/samples/cloudtrail_{scenario_name}_benign.ndjson`

**Why this should not alert:**
- [e.g., Principal is in the approved_iam_principals lookup]
- [e.g., Source IP is in approved_cidr_ranges lookup]

---

## Response

**Playbook:** `incident_response/playbooks/CDET-NNN_{short_name}.md`

**Automated Response Actions:**
- [ ] Notify security team via SNS
- [ ] [Other automated action if applicable]

---

## Tuning Notes

[Any additional context for tuning this detection in specific environments. Note known automation patterns, expected regional behavior, or business processes that will need lookup entries.]

---

## References

- [MITRE ATT&CK technique URL]
- [Relevant threat intelligence reports]
- [Related detection IDs]
