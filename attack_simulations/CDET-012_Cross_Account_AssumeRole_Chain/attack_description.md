# CDET-012 — Cross-Account AssumeRole Chain

**Tactic:** Lateral Movement  
**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material: Application Access Token  
**Severity:** Critical  
**Data Source:** AWS CloudTrail

---

## Technique Overview

Cross-account role chaining is a lateral movement technique where an attacker uses one set of AWS temporary credentials to obtain another set in a different AWS account, enabling them to traverse multiple accounts within an AWS Organization without ever obtaining static long-term credentials. Each "hop" in the chain uses the credentials from the previous hop to assume a new role, extending the attacker's reach across organizational boundaries.

This technique is particularly dangerous in organizations using AWS Organizations, where trust relationships between accounts are commonly pre-configured for operational convenience.

---

## AWS Organizations and the OrganizationAccountAccessRole

AWS Organizations is the AWS service for managing multiple accounts under a single billing and governance structure. When an administrator creates a new member account using the Organizations console or API, AWS automatically creates a role named **`OrganizationAccountAccessRole`** in that member account.

This role:
- Has an **AdministratorAccess** managed policy attached (full admin to the member account)
- Trusts the **management (master) account** to assume it
- Is created automatically without requiring any security review
- Is present in every account created via Organizations (unless explicitly deleted)

An attacker who compromises any role in the management account with `sts:AssumeRole` permissions can assume `OrganizationAccountAccessRole` in **every member account** in the organization. This grants administrative access to potentially hundreds of accounts from a single initial compromise.

---

## The Breadth-First Traversal Pattern

Sophisticated attackers enumerate the entire organization and attempt parallel role assumption:

**Step 1 — Enumerate accounts**: Use `organizations:ListAccounts` to get a list of all account IDs and names. This reveals the full scope of the organization (may be hundreds of accounts).

**Step 2 — Attempt AssumeRole in each account**: For each account, attempt to assume common target role names:
- `OrganizationAccountAccessRole` — the default admin role
- `AWSControlTowerExecution` — AWS Control Tower's cross-account role
- `AdminRole` — common human-named admin role
- `SecurityAuditRole` — common read-access role
- `TerraformExecutionRole` — infrastructure-as-code roles often have broad permissions

**Step 3 — Identify successful assumptions**: Track which accounts accepted the role assumption. These become the attacker's lateral movement footprint.

**Step 4 — Operate within each account**: Use the assumed credentials for enumeration (T1580), resource creation (T1496), or data access (T1537).

---

## How Chained AssumedRole Sessions Appear in CloudTrail

Role chaining produces a distinctive pattern in CloudTrail that reveals the full attack path. Each successful AssumeRole event in a destination account contains a `userIdentity.sessionIssuer` block that traces the credential chain:

**First hop** (Management account → Account A):
```json
{
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEUSER",
    "arn": "arn:aws:iam::MGMT_ACCOUNT:user/compromised-user"
  }
}
```

**Second hop** (Account A credentials → Account B):
```json
{
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLEROLE:session-name",
    "arn": "arn:aws:sts::ACCOUNT_A:assumed-role/OrganizationAccountAccessRole/session",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "principalId": "AROAEXAMPLEROLE",
        "arn": "arn:aws:iam::ACCOUNT_A:role/OrganizationAccountAccessRole",
        "accountId": "ACCOUNT_A",
        "userName": "OrganizationAccountAccessRole"
      }
    }
  }
}
```

The `sessionContext.sessionIssuer` field is the forensic trail. When `type` is `AssumedRole` (not `IAMUser`), the call was made using temporary credentials derived from a role assumption — indicating chaining.

Key detection logic: if `userIdentity.type == "AssumedRole"` AND `sessionContext.sessionIssuer.accountId != recipientAccountId` in an AssumeRole event, this is a cross-account role chain.

---

## Session Token Lifetime Constraints

AWS temporary credentials (STS tokens) have a maximum lifetime:
- Credentials obtained via `AssumeRole`: 1 hour (default) to 12 hours (maximum, configurable per role)
- Credentials obtained via chaining (AssumedRole assuming another Role): maximum **1 hour** regardless of the target role's `MaxSessionDuration` setting

This 1-hour hard limit on chained sessions means an attacker must periodically refresh credentials. Repeated AssumeRole calls at regular intervals (every 45–60 minutes) from the same session context indicate ongoing chained access.

---

## Common Target Roles

| Role Name | Typically In | Common Permissions |
|-----------|-------------|-------------------|
| `OrganizationAccountAccessRole` | All org member accounts | AdministratorAccess |
| `AWSControlTowerExecution` | Control Tower-managed accounts | AdministratorAccess |
| `AWSReservedSSO_*` | SSO-enabled accounts | Varies by permission set |
| `AdminRole` / `administrator` | Common human-named role | AdministratorAccess |
| `TerraformRole` / `DeployRole` | Infrastructure accounts | Broad resource creation |
| `SecurityAuditRole` | All accounts (compliance) | ReadOnlyAccess + SecurityAudit |
| `DataAccessRole` | Data/analytics accounts | S3, RDS, Athena access |

---

## Defense Implications

Organizations should:
1. Audit and restrict `OrganizationAccountAccessRole` — consider removing or tightly scoping it
2. Enable SCPs (Service Control Policies) that require `aws:PrincipalOrgID` conditions on cross-account trust policies
3. Alert on any cross-account AssumeRole where the destination is not in an approved list
4. Monitor for `organizations:ListAccounts` calls, especially from non-automation principals

---

## References

- MITRE ATT&CK T1550.001: https://attack.mitre.org/techniques/T1550/001/
- AWS Organizations: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html
- OrganizationAccountAccessRole: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html
- STS AssumeRole chaining limits: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html
