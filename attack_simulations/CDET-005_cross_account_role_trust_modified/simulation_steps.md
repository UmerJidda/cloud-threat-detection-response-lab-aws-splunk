# CDET-005 — Simulation Steps: Cross-Account Role Trust Modified

## Prerequisites

### Required AWS Permissions
- `iam:ListRoles` — to enumerate target roles
- `iam:GetRole` — to read current trust policy
- `iam:UpdateAssumeRolePolicy` — to modify trust policy (primary simulation)
- `iam:CreateRole` — for new role variant
- `iam:DeleteRole` — for cleanup

### Important Notes
- You need a **second AWS account ID** to use as the "attacker account" in the trust policy
- This can be any valid 12-digit account ID — it does not need to be a real account you control (for detection testing purposes only)
- If you use a real external account ID, someone with access to that account could actually assume the role while it is in the modified state

### Pre-flight Check
```bash
# Verify identity
aws sts get-caller-identity
export VICTIM_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# Simulated attacker account ID (use a fake/test account ID)
export ATTACKER_ACCOUNT="999999999999"  # Replace with a real test account if available

# Check iam:UpdateAssumeRolePolicy permission
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names iam:UpdateAssumeRolePolicy iam:GetRole \
  --resource-arns "arn:aws:iam::${VICTIM_ACCOUNT}:role/TestRole" \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table
```

---

## Step 1: Identify or Create a Target Role

### Option A: Use an existing test role
```bash
# List roles and find a suitable test role
aws iam list-roles \
  --query 'Roles[].{Name:RoleName, Created:CreateDate}' \
  --output table

export TARGET_ROLE="YourExistingTestRole"  # Choose a test role

# Read the current trust policy (SAVE THIS FOR CLEANUP)
aws iam get-role \
  --role-name "$TARGET_ROLE" \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json > /tmp/original_trust_policy.json

cat /tmp/original_trust_policy.json
echo "Original trust policy saved to /tmp/original_trust_policy.json"
```

### Option B: Create a new simulation role
```bash
export TARGET_ROLE="cdet005-simulation-target-role"

# Create a minimal trust policy allowing current account's root
cat > /tmp/initial_trust_policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${VICTIM_ACCOUNT}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name "$TARGET_ROLE" \
  --assume-role-policy-document file:///tmp/initial_trust_policy.json \
  --description "CDET-005 simulation target role — safe to delete"

# Save for cleanup
cp /tmp/initial_trust_policy.json /tmp/original_trust_policy.json

echo "Created simulation role: $TARGET_ROLE"
```

**CloudTrail event generated (Option B)**: `CreateRole`

---

## Step 2: Construct the Modified Trust Policy

```bash
# Build the modified trust policy that adds an external account principal
# This preserves the existing trust statements AND adds the attacker's account
ORIGINAL_TRUST=$(cat /tmp/original_trust_policy.json)

cat > /tmp/modified_trust_policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${VICTIM_ACCOUNT}:root"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "ExternalAccessBackdoor",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ATTACKER_ACCOUNT}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

echo "Modified trust policy prepared:"
cat /tmp/modified_trust_policy.json
```

---

## Step 3: Apply the Modified Trust Policy

```bash
# WARNING: This modifies the role's trust policy to allow an external account to assume it.
# If ATTACKER_ACCOUNT is a real AWS account, anyone with permissions in that account
# can assume this role while this policy is active.
aws iam update-assume-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-document file:///tmp/modified_trust_policy.json

# Expected output: (no output on success — exit code 0)

# Verify the change
aws iam get-role \
  --role-name "$TARGET_ROLE" \
  --query 'Role.AssumeRolePolicyDocument'

# Expected: Trust policy shows both the original principal AND the new external account principal
```

**CloudTrail event generated**: `UpdateAssumeRolePolicy`

---

## Step 4: Verify Detection Trigger

```bash
# Query CloudTrail for the UpdateAssumeRolePolicy event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[].CloudTrailEvent' | head -5

# Also check CreateRole if Option B was used
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --output table
```

The CDET-005 detection rule in Splunk should fire because the trust policy document contains account ID `999999999999` which is not in the approved account list.

---

## Step 5: Cleanup

```bash
# Restore original trust policy
aws iam update-assume-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-document file:///tmp/original_trust_policy.json

echo "Trust policy restored to original for role: $TARGET_ROLE"

# Verify restoration
aws iam get-role \
  --role-name "$TARGET_ROLE" \
  --query 'Role.AssumeRolePolicyDocument'

# If you created a simulation role (Option B), delete it
# WARNING: This permanently deletes the role
aws iam delete-role \
  --role-name "cdet005-simulation-target-role" 2>/dev/null && \
  echo "Simulation role deleted" || echo "Role not found (already deleted or not created)"

# Cleanup temp files
rm -f /tmp/original_trust_policy.json /tmp/modified_trust_policy.json /tmp/initial_trust_policy.json
```
