# CDET-004 — Admin Policy Attached to IAM Principal

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-004 |
| **Severity** | High |
| **Confidence** | High |
| **Tactic** | Privilege Escalation |
| **Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 15 minutes |

## Detection Logic

Attaching an administrative policy to a controlled IAM principal is the most direct privilege escalation path in AWS. An adversary who has write access to IAM policies can instantly elevate any principal to full administrative access. This detection covers both managed policy attachments (`AttachUserPolicy`, `AttachRolePolicy`) and inline policy creation (`PutUserPolicy`, `PutRolePolicy`).

For managed policies, the detection consults the `admin_policy_arns.csv` lookup which must include `arn:aws:iam::aws:policy/AdministratorAccess` and any custom admin-equivalent policies in the environment.

For inline policies, the detection scans the `policyDocument` request parameter for indicators of wildcard permissions (`Action: "*"`, `iam:*`).

## Required Lookups

**`admin_policy_arns.csv`** (must be populated before the detection is effective):
```csv
policy_arn,description
arn:aws:iam::aws:policy/AdministratorAccess,AWS managed full admin
arn:aws:iam::aws:policy/IAMFullAccess,Full IAM access (can escalate to admin)
arn:aws:iam::123456789012:policy/CustomAdminPolicy,Custom organizational admin policy
```

## Example Alert Output

```
detection_id    : CDET-004
alert_title     : [CDET-004] Admin Policy Attached to IAM Principal
severity        : high
eventName       : AttachUserPolicy
creator_arn     : arn:aws:iam::123456789012:user/junior-dev
target_principal: ops-service-account
policy_arn      : arn:aws:iam::aws:policy/AdministratorAccess
is_inline_policy: false
region          : us-east-1
```

## Investigation Guidance

1. Identify whether the creator principal (`creator_arn`) is expected to manage IAM policies
2. Check when the target principal (`target_principal`) was created — very new + immediately admin is high-risk
3. Review access key activity for the target principal since the policy was attached
4. Correlate with CDET-001: if the target user was recently created (within same session), escalate immediately
5. Verify whether the creator's original permissions include `iam:AttachUserPolicy` — if not, investigate how they obtained it
