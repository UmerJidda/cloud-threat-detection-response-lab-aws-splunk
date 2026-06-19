---
detection_id: CDET-008
detection_name: API Enumeration Reconnaissance
tactic: Discovery
technique: T1580
last_updated: 2026-06-18
---

# CDET-008 — API Enumeration Reconnaissance: Containment

**Role: Tier-2 SOC Analyst**
**Prerequisites: Investigation complete, evidence preserved, incident ticket updated**

---

## Approval Requirements

| Action | Approval Required |
|---|---|
| Disable access key (IAM user) | SOC Lead or IR Manager |
| Revoke active IAM role sessions | SOC Lead or IR Manager |
| Detach IAM policies from role/user | IR Manager + affected team lead |
| Delete access key | IR Manager (destructive — see notes) |
| Modify SCPs or permission boundaries | CISO or Security Architect |
| Notify affected data owners (secrets accessed) | IR Manager |

**Do not perform any action below Tier 1 without the required approval.**

---

## Priority-Ordered Containment Steps

### Step 1 — Revoke Active Sessions for the Compromised Identity (Immediate)

This invalidates all existing temporary credentials issued from the role or user, cutting off the attacker's active access without deleting any evidence.

**For an IAM Role:**

```bash
# Attach an inline deny policy to revoke all sessions issued before now
# This uses the AWSRevokeOlderSessions pattern (no credential deletion)
POLICY_DOC=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "<INSERT_CURRENT_UTC_TIMESTAMP>"
        }
      }
    }
  ]
}
EOF
)

aws iam put-role-policy \
    --role-name <ROLE_NAME> \
    --policy-name CDET008_EmergencyRevoke \
    --policy-document "$POLICY_DOC" \
    --profile <containment-profile>
```

Replace `<INSERT_CURRENT_UTC_TIMESTAMP>` with the current UTC time in ISO 8601 format (e.g., `2026-06-18T14:30:00Z`).

**For an IAM User (access key):**

```bash
# Disable the specific access key — preserves key ID in logs, allows rollback
aws iam update-access-key \
    --user-name <USERNAME> \
    --access-key-id <KEY_ID> \
    --status Inactive \
    --profile <containment-profile>
```

---

### Step 2 — Block the Source IP at the Network Layer (If External IP Confirmed Malicious)

Only apply if the source IP is confirmed external and not shared infrastructure (NAT gateway, VPN endpoint).

```bash
# Create a NACL deny rule on affected VPCs (does not affect CloudTrail logging)
aws ec2 create-network-acl-entry \
    --network-acl-id <NACL_ID> \
    --rule-number 1 \
    --protocol -1 \
    --rule-action deny \
    --cidr-block <ATTACKER_IP>/32 \
    --ingress \
    --region <REGION> \
    --profile <containment-profile>
```

Alternatively, use AWS WAF if the activity originated via API Gateway:

```bash
aws wafv2 create-ip-set \
    --name "CDET008-BlockList" \
    --scope REGIONAL \
    --ip-address-version IPV4 \
    --addresses "<ATTACKER_IP>/32" \
    --region <REGION> \
    --profile <containment-profile>
```

---

### Step 3 — Rotate Exposed Secrets (If GetSecretValue or GetParameter Was Observed)

If investigation confirmed data access to secrets:

```bash
# Rotate a Secrets Manager secret immediately
aws secretsmanager rotate-secret \
    --secret-id <SECRET_NAME_OR_ARN> \
    --profile <containment-profile>

# If no rotation lambda is configured, update the secret value manually
aws secretsmanager update-secret \
    --secret-id <SECRET_NAME_OR_ARN> \
    --secret-string '{"key":"<NEW_VALUE>"}' \
    --profile <containment-profile>
```

Notify the application team that owns each rotated secret so they can update their configurations.

---

### Step 4 — Attach a Permission Boundary to Limit Blast Radius (If Role Cannot Be Fully Disabled)

If the role is used by production workloads and cannot be fully disabled:

```bash
# Create a restrictive permission boundary
aws iam put-role-permissions-boundary \
    --role-name <ROLE_NAME> \
    --permissions-boundary arn:aws:iam::aws:policy/AWSReadOnlyAccess \
    --profile <containment-profile>
# This allows existing workloads to read but blocks write/destructive calls
```

This is a less disruptive alternative to Step 1 when availability is a concern.

---

### Step 5 — Enable Enhanced CloudTrail Logging for the Account (If Not Already Active)

Ensure data events are captured to track any further access to S3 objects or Lambda functions:

```bash
aws cloudtrail put-event-selectors \
    --trail-name <TRAIL_NAME> \
    --event-selectors '[
      {
        "ReadWriteType": "All",
        "IncludeManagementEvents": true,
        "DataResources": [
          {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]},
          {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}
        ]
      }
    ]' \
    --profile <containment-profile>
```

---

## What NOT To Do

- **Do NOT delete the access key** before forensic evidence is fully preserved. Deletion removes the key from IAM history and hinders root cause analysis.
- **Do NOT delete the IAM user or role** — this destroys policy history and may break dependent services.
- **Do NOT terminate EC2 instances** that the attacker may have enumerated unless you have confirmed active code execution on them (that is a separate escalation path, not CDET-008 scope).
- **Do NOT rotate all credentials org-wide** without IR Manager approval — this can trigger widespread outages and alert the attacker that they have been detected prematurely.
- **Do NOT remove CloudTrail logging or modify the trail** while an active investigation is open.
- **Do NOT notify the identity owner** before confirming the account is not under adversary control (the owner may be the attacker, or their email may be compromised).

---

## Rollback / Undo Steps (If Containment Was a FP)

If investigation concludes this was a benign actor, reverse containment actions in this order:

### Undo Step 1a — Remove Emergency Session Revocation Policy from Role

```bash
aws iam delete-role-policy \
    --role-name <ROLE_NAME> \
    --policy-name CDET008_EmergencyRevoke \
    --profile <containment-profile>
```

### Undo Step 1b — Re-Enable Disabled Access Key

```bash
aws iam update-access-key \
    --user-name <USERNAME> \
    --access-key-id <KEY_ID> \
    --status Active \
    --profile <containment-profile>
```

### Undo Step 2 — Remove NACL Deny Rule

```bash
aws ec2 delete-network-acl-entry \
    --network-acl-id <NACL_ID> \
    --rule-number 1 \
    --ingress \
    --region <REGION> \
    --profile <containment-profile>
```

### Undo Step 4 — Remove Permission Boundary

```bash
aws iam delete-role-permissions-boundary \
    --role-name <ROLE_NAME> \
    --profile <containment-profile>
```

After rollback, document the FP in the incident ticket, update the triage playbook accordingly, and file a suppression request per the recovery playbook.
