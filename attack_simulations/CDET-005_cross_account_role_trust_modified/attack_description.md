# CDET-005 — Cross-Account Role Trust Relationship Modified

## Technique
**Tactic:** Privilege Escalation  
**MITRE Technique:** T1484.002 — Domain or Tenant Policy Modification: Trust Modification  
**Severity:** High | Risk Score: 65

---

## Threat Actor Perspective

### How Modifying Role Trust Policies Enables Cross-Account Access

Every IAM role has two separate policy components:
1. **Permission policy** — what actions the role can perform (e.g., `s3:GetObject`, `ec2:DescribeInstances`)
2. **Trust policy** (assume role policy) — who is *allowed to assume* this role

By default, a role's trust policy specifies which principals in the **same account** can assume it. An adversary who has `iam:UpdateAssumeRolePolicy` or `iam:CreateRole` on a highly privileged role can modify the trust policy to allow a principal in their own external account to assume that role. This effectively creates a permanent backdoor that:

- **Requires no new IAM users or access keys in the victim account** — the compromise lives entirely in the trust relationship
- **Survives incident response actions** that focus on users and access keys
- **Can be leveraged from any time zone, IP address, or device** the attacker controls in their source account
- **Grants the full permissions of the role** — if the target role has `AdministratorAccess`, the attacker has full admin access to the victim account whenever they choose

### Creating a New Role with External Trust vs. Modifying an Existing Role

**Approach 1: Create a new role with external trust (higher noise)**  
The attacker creates a new role (e.g., `SupportAccess` or `MonitoringRole`) with `AdministratorAccess` and a trust policy pointing to their external account. This generates a `CreateRole` event. Detection is CDET-001-adjacent (new principal created outside pipeline).

**Approach 2: Modify existing role's trust policy (stealthier)**  
The attacker identifies an existing high-privilege role and modifies its trust policy using `UpdateAssumeRolePolicy`. This approach is significantly stealthier because:
- The role already exists — no new principals appear in `iam list-roles`
- The change is in the trust policy, which most IAM audits focus on less than permission policies
- The `UpdateAssumeRolePolicy` event name is less prominent in detection rules than `CreateUser` or `AttachUserPolicy`
- The role continues functioning normally for all legitimate principals — the attacker's access is additive

### Why This Technique Is Particularly Powerful

**No credential material in the victim account**  
Unlike creating an IAM user with access keys, trust policy modification creates no credential material in the victim account. There is no `AccessKeyId` to revoke, no login profile to disable. The "credential" is the attacker's own IAM principal in their source account, which the victim organization has no control over.

**Persistence through multiple incident response rounds**  
During an IR engagement, responders typically:
1. Rotate compromised user credentials
2. Disable suspicious IAM users
3. Review access key creation events

They may not review role trust policies unless specifically looking for them. A trust policy modification can survive multiple rounds of IR actions until the responders specifically audit trust relationships.

**Lateral movement across accounts in an AWS Organization**  
In AWS Organizations environments, a compromised management account can modify trust policies in member accounts, and vice versa if Organization-level SCPs are misconfigured. An adversary who compromises one account in an organization can use trust policy modifications to create access paths to sibling accounts.

### Identifying High-Value Target Roles

Attackers enumerate roles before deciding which ones to target for trust policy modification:

```bash
# List roles and their descriptions (high-privilege roles often have revealing descriptions)
aws iam list-roles --query 'Roles[].{Name:RoleName, Arn:Arn, Description:Description}' --output table

# Find roles with admin-level policies
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  policies=$(aws iam list-attached-role-policies --role-name "$role" \
    --query 'AttachedPolicies[?contains(PolicyName, `Admin`)].PolicyName' --output text)
  [ -n "$policies" ] && echo "HIGH VALUE: $role -> $policies"
done
```

**Ideal targets:**
- Roles with `AdministratorAccess` that are assumed by automation (broad trust conditions)
- Cross-account roles with permissive `sts:AssumeRole` conditions (no External ID requirement)
- Break-glass emergency access roles
- Roles with overly permissive trust policies (`"AWS": "arn:aws:iam::ACCOUNT:root"`)

### Trust Policy Construction

The minimal trust policy modification to grant external access:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

A more targeted version that only allows a specific attacker IAM user:
```json
{
  "Principal": {
    "AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:user/attacker-user"
  }
}
```

An even stealthier version using a condition that would be difficult to notice in a trust policy review:
```json
{
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "attacker-controlled-secret-value"
    }
  }
}
```

---

## Detection Context (CDET-005)

The CDET-005 detection fires on `CreateRole` or `UpdateAssumeRolePolicy` events where the `requestParameters.policyDocument` contains an AWS account ID that is not in the organization's approved account list. The key field is parsing the trust policy JSON within the CloudTrail event to identify external account IDs.
