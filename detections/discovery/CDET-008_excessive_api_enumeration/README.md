# CDET-008 — Excessive API Enumeration by Single Principal

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-008 |
| **Severity** | Medium |
| **Confidence** | Medium |
| **Tactic** | Discovery |
| **Technique** | T1580 — Cloud Infrastructure Discovery |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Hourly |

## Detection Logic

After initial access, adversaries enumerate the cloud environment to understand its attack surface: what IAM principals exist, what services are running, what data stores are accessible, and what permissions can be escalated. This enumeration produces a burst of List/Describe/Get API calls across multiple services within a short window.

The detection aggregates Read-only API calls over a 2-hour window, grouping by the acting principal. It fires when a single principal makes:
- **≥ 50 enumeration calls** (volume threshold)
- **≥ 5 unique API names** (breadth threshold — ensures this is systematic scanning, not a high-frequency single operation)

Both thresholds must be met to reduce FP rate from normal operational activity.

## Threshold Rationale

The 50-call / 5-API threshold was derived using the following logic:
- A human operator manually checking resources in the console typically generates 5–20 calls per session
- Automated tooling that is not in a suppression lookup would need to be investigated
- Legitimate high-volume tooling (CSPM) must be suppressed via `automation_role_arns.csv`

Review and adjust thresholds based on 30 days of baseline measurement in your environment.

## Example Alert Output

```
detection_id          : CDET-008
severity              : medium
principal_arn         : arn:aws:iam::123456789012:user/new-employee-alice
enumeration_intensity : high
total_calls           : 312
unique_api_calls      : 18
services_enumerated   : 9
api_calls_sample      : ListUsers, ListRoles, ListBuckets, DescribeInstances, ListFunctions...
regions_touched       : 3
event_source_ip       : 203.0.113.55
```

## Investigation Guidance

1. Determine whether this principal should be making these calls — check their job function and AWS permissions
2. Check timing — did this burst occur immediately after a `ConsoleLogin` event? (Indicates interactive enumeration)
3. Correlate with CDET-004, CDET-005 — privilege escalation followed by enumeration is a common attack chain
4. Check if the enumeration was followed by write operations (CreateUser, RunInstances, PutBucketPolicy)
5. If the principal is a human user, contact them to verify the activity
