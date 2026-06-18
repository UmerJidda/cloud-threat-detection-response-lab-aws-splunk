# CDET-005 — Cross-Account Role Trust Relationship Created or Modified

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-005 |
| **Severity** | High |
| **Confidence** | Medium |
| **Tactic** | Privilege Escalation |
| **Technique** | T1484.002 — Domain or Tenant Policy Modification: Trust Modification |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 15 minutes |

## Detection Logic

Cross-account role trust modifications are the mechanism by which an adversary creates a persistent backdoor from an attacker-controlled AWS account into the victim account. By modifying a role's trust policy to allow an external account ID to call `AssumeRole`, the attacker can re-enter the environment with fresh credentials even after the original access method is revoked.

The detection extracts all 12-digit AWS account IDs from the `assumeRolePolicyDocument` request parameter using regex, then checks each against the `approved_aws_accounts.csv` lookup. Any account ID not in the approved list generates an alert.

AWS service principals (ending in `.amazonaws.com`) are explicitly excluded — these are normal and common in service role trust policies.

## Required Lookups

**`approved_aws_accounts.csv`** (must be populated for the detection to be effective):
```csv
account_id,account_alias,owner,relationship,date_added
123456789012,security-tooling,SecOps,Hub account - CSPM tooling,2024-01-01
234567890123,log-archive,CloudOps,Centralized log archive account,2024-01-01
```

## Example Alert Output

```
detection_id      : CDET-005
alert_title       : [CDET-005] Cross-Account Role Trust Relationship Created or Modified
severity          : high
eventName         : UpdateAssumeRolePolicy
role_name         : DataAccessRole
trust_principal   : arn:aws:iam::999888777666:root
external_account_id: 999888777666
creator_arn       : arn:aws:iam::123456789012:user/alice
region            : us-east-1
```

## Investigation Guidance

1. Look up the external account ID (`trust_account_id`) — is it a known partner, vendor, or service?
2. Verify with the role owner (`creator_arn`) whether the trust modification was authorized
3. Check AWS Organizations for whether the account ID is a member of your organization
4. Review what permissions are attached to the modified role — a high-privilege role with external trust is critical risk
5. Search for subsequent `AssumeRole` calls from the external account to this role
