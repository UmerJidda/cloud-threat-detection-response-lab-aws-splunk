# CDET-012 — Simulation Steps: Cross-Account AssumeRole Chain

**WARNING**: These steps perform real cross-account role assumptions. Only run in AWS Organizations you control. Ensure test roles exist before running. Attempting to assume roles in accounts you do not own is unauthorized access.

---

## Prerequisites

- AWS CLI configured with management account credentials
- A test member account in your AWS Organization
- Test IAM role in the member account that trusts the management account
- IAM permissions: `sts:AssumeRole`, `organizations:ListAccounts`

---

## Phase 1: Enumerate the Organization

```bash
# List all accounts in the organization (attacker reconnaissance)
# This is the first step — identify all potential lateral movement targets
aws organizations list-accounts \
  --query 'Accounts[*].[Id,Name,Status]' \
  --output table

# Save account IDs for scripted traversal
aws organizations list-accounts \
  --query 'Accounts[?Status==`ACTIVE`].Id' \
  --output text > /tmp/org-accounts.txt

cat /tmp/org-accounts.txt
echo "Total accounts: $(wc -l < /tmp/org-accounts.txt)"

# Get organizational units (reveals account groupings — useful for targeting)
aws organizations list-roots
ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
aws organizations list-organizational-units-for-parent --parent-id "$ROOT_ID"
```

---

## Phase 2: Single AssumeRole (First Hop)

```bash
# Variables
MGMT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
TARGET_ACCOUNT="111111111111"  # Replace with your test member account ID
TARGET_ROLE="OrganizationAccountAccessRole"  # Or your test role name

# First hop: assume role in member account using management account IAM user credentials
aws sts assume-role \
  --role-arn "arn:aws:iam::${TARGET_ACCOUNT}:role/${TARGET_ROLE}" \
  --role-session-name "cdet012-hop1-$(date +%s)" \
  --duration-seconds 3600

# Capture credentials for the next hop
CREDS=$(aws sts assume-role \
  --role-arn "arn:aws:iam::${TARGET_ACCOUNT}:role/${TARGET_ROLE}" \
  --role-session-name "cdet012-test" \
  --query 'Credentials' \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo $CREDS | python3 -c "import sys,json; print(json.load(sys.stdin)['SessionToken'])")

# Confirm identity using first-hop credentials
aws sts get-caller-identity
# Expected: ARN contains arn:aws:sts::TARGET_ACCOUNT:assumed-role/OrganizationAccountAccessRole/cdet012-test
```

---

## Phase 3: Role Chaining (Second Hop)

```bash
# Using credentials from Phase 2, assume a role in a SECOND member account
# This is role chaining — AssumedRole credentials assuming another role
SECOND_TARGET_ACCOUNT="222222222222"  # Second test account
SECOND_TARGET_ROLE="OrganizationAccountAccessRole"

# THE DETECTION EVENT — second hop with AssumedRole principal
aws sts assume-role \
  --role-arn "arn:aws:iam::${SECOND_TARGET_ACCOUNT}:role/${SECOND_TARGET_ROLE}" \
  --role-session-name "cdet012-hop2-$(date +%s)" \
  --duration-seconds 3600

# Note: maximum duration for chained sessions is 1 hour (cannot exceed)
# Even if target role allows 12h sessions, chaining caps at 1h

# Confirm the chain is visible in the identity
aws sts get-caller-identity
# The userIdentity.type in CloudTrail will be "AssumedRole"
# sessionContext.sessionIssuer.arn will point back to the hop-1 role
```

---

## Phase 4: Breadth-First Account Traversal (Automated)

```bash
# Attempt role assumption in every account (attacker breadth-first scan)
# This generates multiple AssumeRole events — the bulk pattern that triggers CDET-012

TARGET_ROLE="OrganizationAccountAccessRole"
SUCCESSFUL_ACCOUNTS=()

while IFS= read -r account_id; do
  ROLE_ARN="arn:aws:iam::${account_id}:role/${TARGET_ROLE}"
  echo -n "Attempting assume-role in $account_id... "

  RESULT=$(aws sts assume-role \
    --role-arn "$ROLE_ARN" \
    --role-session-name "cdet012-scan" \
    --duration-seconds 900 \
    --query 'Credentials.AccessKeyId' \
    --output text 2>/dev/null)

  if [ $? -eq 0 ] && [ -n "$RESULT" ]; then
    echo "SUCCESS ($RESULT)"
    SUCCESSFUL_ACCOUNTS+=("$account_id")
  else
    echo "FAILED (AccessDenied or role not found)"
  fi
done < /tmp/org-accounts.txt

echo "Accessible accounts: ${SUCCESSFUL_ACCOUNTS[*]}"
```

---

## Phase 5: Using Chained Credentials

```bash
# Using the second-hop credentials, perform read-only reconnaissance
# (demonstrating that the attacker has lateral access)

# Unset environment variables and use a profile instead
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Or continue with the env vars set in Phase 2/3
aws s3api list-buckets  # Enumerate S3 in the second account
aws iam list-roles       # Enumerate IAM in the second account
```

---

## CloudTrail Visibility

To observe the chain in CloudTrail after the test:

```bash
# In the management account — look for AssumeRole calls made BY assumed-role principals
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?contains(CloudTrailEvent, `AssumedRole`)]' \
  --output json | python3 -m json.tool

# Look for the chain pattern:
# 1st event: userIdentity.type = "IAMUser" calling AssumeRole in account A
# 2nd event: userIdentity.type = "AssumedRole" calling AssumeRole in account B
#   sessionContext.sessionIssuer.accountId = account A (different from recipientAccountId B)
```

---

## Cleanup

No persistent resources are created. Temporary credentials expire automatically.

```bash
# Clear environment variables
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Verify you're back to original credentials
aws sts get-caller-identity
```
