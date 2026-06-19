---
detection_id: CDET-005
detection_name: Cross-Account Trust Modified
tactic: Privilege Escalation
technique: T1484.002
last_updated: 2026-06-18
---

# CDET-005 — Cross-Account Trust Modified: Containment Playbook

**Audience:** Tier-2 SOC Analyst  
**Prerequisite:** Evidence preserved per `investigation.md`. Blast radius assessed.  
**Goal:** Stop active or potential adversary access without destroying evidence or causing service outages.

---

## Approval Requirements

| Action | Approval Required From |
|---|---|
| Disable an IAM access key | IR Lead or Security Manager |
| Revert a role trust policy | IR Lead — must have the original policy document ready |
| Attach an explicit deny policy to a role | IR Lead |
| Delete an IAM user or role | Security Manager + Service Owner |
| Revoke all active sessions for a role (via permission boundary) | IR Lead + Service Owner |
| Any action affecting a production role with active workloads | Service Owner must be notified before action |

**Do not proceed to destructive actions without documented approval in the case ticket.**

---

## Containment Actions — Priority Order

### Action 1 — Revert the Trust Policy (Highest Priority)

This stops the external principal from being able to assume the role. Do this before disabling the actor, so that any active external session cannot re-modify the trust policy.

Obtain the original trust policy from one of:
- The preserved evidence collected in `investigation.md` (prior CloudTrail `GetRole` response)
- Your organization's IaC repository (Terraform/CloudFormation state)
- A known-good backup in S3 or AWS Config

```bash
# Write the original trust policy to a file first
cat > /tmp/original_trust_policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ORIGINAL_TRUSTED_ACCOUNT>:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Revert the trust policy (no hardcoded credentials — uses aws configure / instance profile)
aws iam update-assume-role-policy \
    --role-name "<ROLE_NAME>" \
    --policy-document file:///tmp/original_trust_policy.json
```

Verify the revert succeeded:

```bash
aws iam get-role \
    --role-name "<ROLE_NAME>" \
    --query "Role.AssumeRolePolicyDocument" \
    --output json
```

---

### Action 2 — Attach an Explicit Deny Boundary to the Modified Role

As an additional safeguard while investigation continues, attach a permission boundary that denies all actions. This prevents any active session under the role from doing further damage.

```bash
# Create an explicit-deny policy (do this once; reuse policy ARN afterward)
aws iam create-policy \
    --policy-name "IR-ExplicitDeny-CDET005" \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Deny",
          "Action": "*",
          "Resource": "*"
        }
      ]
    }'

# Attach as permission boundary to the modified role
aws iam put-role-permissions-boundary \
    --role-name "<ROLE_NAME>" \
    --permissions-boundary "arn:aws:iam::<ACCOUNT_ID>:policy/IR-ExplicitDeny-CDET005"
```

**Note:** Permission boundaries affect the role itself. Any currently active session tokens issued before this boundary was applied will continue to work until expiry (max 12 hours for role sessions). If an active session is confirmed, proceed to Action 3.

---

### Action 3 — Disable the Actor's Access Key

Suspend (do not delete) the access key used to make the change. Suspending preserves audit trail; deletion removes evidence.

```bash
# Disable the access key — does NOT delete it
aws iam update-access-key \
    --user-name "<ACTOR_USERNAME>" \
    --access-key-id "<ACCESS_KEY_ID>" \
    --status Inactive
```

If the actor is an assumed-role session (not a static IAM user key), the session cannot be directly revoked, but the source role's trust policy or the source user's key can be disabled. Confirm the source from `userIdentity.sessionContext.sessionIssuer.arn`.

---

### Action 4 — Revoke Active Sessions on the Modified Role (If Breach Confirmed)

If query 3c in `investigation.md` confirmed an external `AssumeRole` call was made, active sessions may exist. Revoking requires attaching an inline deny policy conditioned on session issue time.

```bash
# Revoke all sessions issued before now
REVOKE_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

aws iam put-role-policy \
    --role-name "<ROLE_NAME>" \
    --policy-name "RevokeOldSessions" \
    --policy-document "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Effect\": \"Deny\",
          \"Action\": \"*\",
          \"Resource\": \"*\",
          \"Condition\": {
            \"DateLessThan\": {
              \"aws:TokenIssueTime\": \"${REVOKE_TIME}\"
            }
          }
        }
      ]
    }"
```

---

### Action 5 — Block the External Account at the SCP Level (If Applicable)

If your organization uses AWS Organizations, add a Service Control Policy to deny `sts:AssumeRole` from the malicious external account ID.

```bash
# This requires Organizations admin permissions — run from the management account
aws organizations create-policy \
    --name "Block-Malicious-Account-CDET005" \
    --type SERVICE_CONTROL_POLICY \
    --description "Block cross-account AssumeRole from compromised account - CDET-005" \
    --content "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Effect\": \"Deny\",
          \"Action\": \"sts:AssumeRole\",
          \"Resource\": \"*\",
          \"Condition\": {
            \"StringEquals\": {
              \"aws:PrincipalAccount\": \"<MALICIOUS_ACCOUNT_ID>\"
            }
          }
        }
      ]
    }"
```

---

## What NOT to Do

- **Do NOT delete the IAM access key** of the actor before forensic review — deletion removes the key ID from audit trails and may break automated lookups.
- **Do NOT delete the IAM role** that was modified — this destroys the evidence of what policies it had, and may break dependent workloads.
- **Do NOT rotate all IAM credentials in the account indiscriminately** without a scoped blast-radius assessment — this causes service outages and alert fatigue.
- **Do NOT detach production-critical policies from a role** without service owner approval — this will cause application failures.
- **Do NOT delete CloudTrail logs or disable logging** in an attempt to "clean up" — this is evidence destruction.
- **Do NOT modify the malicious external account** if you have access to it (shared org scenario) — treat it as evidence.

---

## Rollback Steps (If Containment Action Was Applied to a FP)

If post-containment review shows this was a legitimate change:

### Rollback: Revert the trust policy back to the (now-confirmed legitimate) modified version

```bash
aws iam update-assume-role-policy \
    --role-name "<ROLE_NAME>" \
    --policy-document file:///tmp/approved_new_trust_policy.json
```

### Rollback: Remove the permission boundary

```bash
aws iam delete-role-permissions-boundary \
    --role-name "<ROLE_NAME>"
```

### Rollback: Remove the session-revocation inline policy

```bash
aws iam delete-role-policy \
    --role-name "<ROLE_NAME>" \
    --policy-name "RevokeOldSessions"
```

### Rollback: Re-enable the access key

```bash
aws iam update-access-key \
    --user-name "<ACTOR_USERNAME>" \
    --access-key-id "<ACCESS_KEY_ID>" \
    --status Active
```

Document all rollback actions in the case ticket with the approval chain.

---

*Next step: proceed to `recovery.md` once the immediate threat is contained.*
