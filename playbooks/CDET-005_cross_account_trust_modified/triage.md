---
detection_id: CDET-005
detection_name: Cross-Account Trust Modified
tactic: Privilege Escalation
technique: T1484.002
last_updated: 2026-06-18
---

# CDET-005 — Cross-Account Trust Modified: Triage Playbook

**Audience:** Tier-2 SOC Analyst  
**Time budget:** 5–10 minutes  
**Goal:** Determine whether this alert is a genuine privilege escalation attempt or a benign false positive, and decide whether to escalate immediately.

---

## Step 1 — Confirm the Alert is Not Test Data (1 min)

1. Check the `userAgent` field in the triggering CloudTrail event.
   - Known test/pipeline agents: `aws-sdk-java/test`, `Terraform`, `CloudFormation`, `aws-cli/cicd-pipeline`, `aws-sdk-python/botocore` from the CI account.
   - If the agent matches a known automation actor, proceed to Step 2 before closing.
2. Confirm the event timestamp is within the last 24 hours. Replayed or late-arriving events from log aggregators can trigger stale alerts.
3. Verify `eventName` is exactly `UpdateAssumeRolePolicy` — not a read-only simulation or a dry-run.

---

## Step 2 — Check Against Known-Good Lookup CSVs (2 min)

Cross-reference the following lookup tables in `splunk/lookups/`:

| Lookup File | Field to Match | Purpose |
|---|---|---|
| `approved_iam_admins.csv` | `userIdentity.arn` | Authorized IAM admins allowed to modify trust policies |
| `approved_cross_account_roles.csv` | `requestParameters.roleName` | Roles whose trust policies are routinely managed |
| `approved_external_accounts.csv` | Principal AWS account ID extracted from new trust policy | Whitelisted external accounts |
| `ci_cd_pipeline_principals.csv` | `userIdentity.principalId` | CI/CD service accounts that legitimately update roles |

**If ALL three match (actor, role, and target account are all whitelisted):** Mark as benign FP, document the match, close with note.  
**If ANY one does NOT match:** Continue triage — do not close.

---

## Step 3 — Examine Key Alert Fields (2 min)

Pull the raw CloudTrail event and verify the following fields:

```
eventName:               UpdateAssumeRolePolicy
eventSource:             iam.amazonaws.com
userIdentity.type:       (IAMUser | AssumedRole | Root — Root is immediately critical)
userIdentity.arn:        <who made the change>
userIdentity.accountId:  <source account>
requestParameters.roleName:        <role being modified>
requestParameters.policyDocument:  <new trust policy — examine Principal field>
sourceIPAddress:         <calling IP — is it internal, AWS service, or external?>
userAgent:               <client used>
errorCode:               (absent = success; present = attempted but failed)
```

**Critical indicators — escalate immediately if any are true:**

- `userIdentity.type` is `Root`
- `sourceIPAddress` is an external, non-AWS IP not associated with known admin bastion hosts
- `requestParameters.policyDocument` contains a `Principal` with `"AWS": "*"` (wildcard)
- The modified role has `AdministratorAccess` or equivalent attached policies
- The new trust principal is an account ID not in `approved_external_accounts.csv`
- The calling principal itself is not in `approved_iam_admins.csv`

---

## Step 4 — Urgency and Escalation Decision (1 min)

| Condition | Action |
|---|---|
| Root caller, wildcard principal, or unknown external account | Escalate to IR lead immediately — do not wait |
| Unknown actor modifying a high-privilege role | Escalate within 15 minutes |
| Known actor but unknown target account | Investigate further before escalating |
| All lookups match and no critical indicators | Document as FP, close alert |

---

## Step 5 — PASS / FAIL Criteria

**PASS — Real Alert (proceed to investigation.md):**
- Actor is not in `approved_iam_admins.csv`, OR
- Target role is not in `approved_cross_account_roles.csv`, OR
- New trust principal account is not in `approved_external_accounts.csv`, OR
- Any critical indicator from Step 3 is present

**FAIL — Benign FP (close alert):**
- Actor, role, and target account ALL match approved lookup CSVs
- Change matches a known scheduled automation job (verify against change management records)
- `errorCode` is present (change was attempted but failed — lower urgency, still log)

---

## Quick Reference — Splunk Triage Query

```spl
index=aws_cloudtrail eventName=UpdateAssumeRolePolicy earliest=-1h
| table _time, userIdentity.arn, userIdentity.accountId, requestParameters.roleName,
         requestParameters.policyDocument, sourceIPAddress, userAgent, errorCode
| lookup approved_iam_admins.csv userIdentity.arn OUTPUT is_approved_admin
| lookup approved_cross_account_roles.csv requestParameters.roleName OUTPUT is_approved_role
```

---

*Next step if escalating or investigating: proceed to `investigation.md`.*
