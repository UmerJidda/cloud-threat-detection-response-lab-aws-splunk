# CDET-004 — Admin Policy Attached to IAM Principal

## Technique
**Tactic:** Privilege Escalation  
**MITRE Technique:** T1078.004 — Valid Accounts: Cloud Accounts  
**Severity:** High | Risk Score: 78

---

## Threat Actor Perspective

### Why AdministratorAccess Is the Goal

In AWS, permissions are not binary — they exist on a spectrum from zero to full administrative control. An adversary who starts with a limited-privilege initial access vector (e.g., a developer IAM user with only `s3:GetObject`, or a Lambda execution role) must escalate privileges before they can achieve their real objectives: exfiltration, persistence, or destruction.

The ultimate target is the `AdministratorAccess` managed policy (`arn:aws:iam::aws:policy/AdministratorAccess`), which grants `"*"` on `"*"` — every action on every resource. With this policy, an adversary can:
- Create or modify any IAM principal (persistence)
- Access any data store (S3, RDS, DynamoDB, Secrets Manager)
- Stop or delete security services (GuardDuty, Config, CloudTrail)
- Exfiltrate data at any scale
- Launch arbitrary compute resources (cryptomining, C2 infrastructure)

Even without reaching `AdministratorAccess`, certain granular permissions can be individually leveraged for escalation — the "pass-role" chain described below.

### Inline vs. Managed Policy: The Evasion Difference

**AWS Managed Policies** (e.g., `AdministratorAccess`, `AmazonS3FullAccess`):
- Identified by a stable ARN (`arn:aws:iam::aws:policy/...`)
- Appear in `aws iam list-attached-user-policies`
- CloudTrail event: `AttachUserPolicy` with `requestParameters.policyArn`
- Visible in the IAM console under "Attached policies"
- Easy to detect: the policy ARN is a clear signal

**Customer Inline Policies** (via `PutUserPolicy`):
- Embedded directly in the user's policy document
- Do NOT appear in `list-attached-user-policies` — require `list-user-policies` + `get-user-policy`
- CloudTrail event: `PutUserPolicy` with `requestParameters.policyDocument`
- Harder to detect: requires parsing the policy document JSON for wildcards
- An inline policy with `"Effect": "Allow", "Action": "*", "Resource": "*"` grants the same permissions as `AdministratorAccess` but is less visible in standard IAM reviews

The key difference in detection: `AttachUserPolicy` with `policyArn` containing `AdministratorAccess` is trivial to detect. `PutUserPolicy` with an arbitrary wildcard policy document requires the SIEM to parse JSON fields within the CloudTrail event.

### The "Pass-Role" Privilege Escalation Chain

`iam:PassRole` is one of the most dangerous individual permissions. It allows a user to attach an IAM role to AWS services (EC2, Lambda, ECS, etc.). An adversary with `iam:PassRole` + the ability to create/invoke a Lambda function can escalate to any role's permissions:

```
1. Attacker has: iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction
2. Attacker identifies: arn:aws:iam::123456789012:role/AdminRole (has AdministratorAccess)
3. Attacker creates Lambda function with AdminRole attached
4. Attacker invokes Lambda to call sts:AssumeRole or directly make privileged API calls
5. Result: Attacker achieves administrative access without ever calling AttachUserPolicy
```

This chain generates no `AttachUserPolicy` or `PutUserPolicy` events — only `CreateFunction`, `InvokeFunction`, and `PassRole`. CDET-004 does not cover this variant; it requires separate detection logic.

### Common IAM Misconfiguration Paths

**Path 1: Over-permissive CI/CD roles**  
CI/CD pipeline roles often have `iam:*` permissions for "convenience." An adversary who compromises a CI/CD pipeline (via a malicious PR, supply chain attack, or stolen deployment credentials) inherits these permissions and can attach admin policies to newly created or existing users.

**Path 2: The IAM break-glass account**  
Many organizations have a manually managed "break-glass" IAM user with admin access for emergencies. If this user's credentials are compromised (e.g., stored in a password manager that gets breached), the adversary immediately has `AdministratorAccess`.

**Path 3: Policy confusion (trust policy vs. permission policy)**  
Developers who confuse role trust policies with permission policies sometimes create roles that trust all AWS principals in the account (`"AWS": "arn:aws:iam::ACCOUNT:root"`) with admin permissions. Any authenticated principal in the account can assume this role.

**Path 4: Permissions boundary bypass**  
Users with `iam:CreatePolicyVersion` can replace an existing policy's content, potentially removing any permissions boundary restrictions and granting themselves broader access.

---

## Detection Context (CDET-004)

The CDET-004 detection fires on:
1. `AttachUserPolicy` / `AttachRolePolicy` where `requestParameters.policyArn` matches admin policy patterns
2. `PutUserPolicy` / `PutRolePolicy` where the policy document contains wildcard actions or resources

The detection has a moderate false positive rate for organizations that use Terraform/CloudFormation for legitimate policy management — these tools generate identical events. Filtering by `userIdentity.arn` matching approved automation roles reduces false positives.
