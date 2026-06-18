# CDET-012 — Cross-Account AssumeRole Chain

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-012 |
| **Severity** | High (Critical if chained + multiple targets) |
| **Confidence** | Medium |
| **Tactic** | Lateral Movement |
| **Technique** | T1550.001 — Use Alternate Authentication Material |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 30 minutes |

## Detection Logic

Cross-account role assumption (`sts:AssumeRole`) is the primary lateral movement mechanism in multi-account AWS environments. An attacker who compromises credentials in Account A can use any overly-permissive trust relationship to pivot into Account B, and from there to Account C — a "role chain" that quickly traverses an entire AWS Organization.

The detection flags `AssumeRole` calls that target accounts not in the `approved_aws_accounts` lookup, with the following escalation logic:

| Condition | Severity |
|-----------|----------|
| Chained assumption (AssumedRole pivoting) targeting 2+ unapproved accounts | Critical |
| Chained assumption to any unapproved account | High |
| 3+ distinct unapproved target accounts from a single principal | High |
| Single unapproved target account | High |

The **chained assumption** signal is the most reliable: an `AssumedRole` session (already a temporary credential) calling `AssumeRole` again into another account that is not approved. Legitimate pipeline chaining is suppressed via both `automation_role_arns` and `session_issuer_arn` lookup checks.

## Key Fields

| Field | Description |
|-------|-------------|
| `is_chained_assumption` | `true` if the calling principal is already an `AssumedRole` session |
| `distinct_target_accounts` | Number of unique unapproved accounts targeted by this principal |
| `target_accounts_str` | Comma-separated list of unapproved target account IDs |
| `session_issuer_arn` | The source role if this is a chained session |

## Example Alert Output

```
detection_id             : CDET-012
severity                 : critical
is_chained_assumption    : true
principal_arn            : arn:aws:sts::111111111111:assumed-role/DevRole/session
session_issuer_arn       : arn:aws:iam::111111111111:role/DevRole
distinct_target_accounts : 3
target_accounts_str      : 222222222222, 333333333333, 444444444444
target_roles_str         : arn:aws:iam::222222222222:role/AdminRole | ...
event_source_ip          : 198.51.100.44
region                   : us-east-1
```

## Investigation Guidance

1. Identify the originating principal and review all `AssumeRole` calls in the last 24 hours
2. For each target account ID: cross-reference against the AWS Organization member list
3. Determine what the assumed role permitted — pull the IAM role policy from the target account
4. Check CloudTrail in the target accounts for actions performed with the assumed role session
5. Determine if the trust policy on the target role is overly permissive (e.g., `"Principal": {"AWS": "*"}`)

## Containment Guidance

1. Revoke all active sessions for the compromised principal using `aws iam create-service-specific-credential` approach or by rotating the access key
2. In each target account, review and tighten the trust policy on the accessed roles
3. If a chained role was accessed, check for any resources created or modified in the target accounts
4. Engage account owners for all `target_accounts_str` accounts
