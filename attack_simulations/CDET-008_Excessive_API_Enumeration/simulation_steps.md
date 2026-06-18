# CDET-008 — Simulation Steps: Excessive API Enumeration

**WARNING**: These steps are for use in isolated AWS test accounts only. Running enumeration against production accounts without authorization may violate your organization's security policies.

---

## Prerequisites

- AWS CLI configured with valid credentials (`aws configure`)
- IAM permissions: ReadOnlyAccess or SecurityAudit managed policy
- Test AWS account (not production)

---

## Phase 1: Identity Confirmation (Warm-Up)

These initial calls establish the caller identity and are the first thing any automated tool performs.

```bash
# Confirm current identity
aws sts get-caller-identity

# Get account summary
aws iam get-account-summary

# Check account password policy
aws iam get-account-password-policy
```

---

## Phase 2: IAM Enumeration

```bash
# List all IAM users
aws iam list-users --output json

# List all IAM roles
aws iam list-roles --output json

# List all IAM groups
aws iam list-groups --output json

# List all IAM policies (customer managed)
aws iam list-policies --scope Local --output json

# List attached policies for each user (loop)
aws iam list-users --query 'Users[*].UserName' --output text | \
  tr '\t' '\n' | while read user; do
    echo "=== $user ==="
    aws iam list-attached-user-policies --user-name "$user"
    aws iam list-user-policies --user-name "$user"
  done

# Enumerate role trust policies (reveals cross-account access)
aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]' --output json
```

---

## Phase 3: S3 Enumeration

```bash
# List all S3 buckets
aws s3api list-buckets --output json

# For each bucket, check public access, encryption, versioning
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read bucket; do
    echo "=== $bucket ==="
    aws s3api get-bucket-location --bucket "$bucket" 2>/dev/null
    aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null
    aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null
    aws s3api get-bucket-versioning --bucket "$bucket" 2>/dev/null
    aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null
    aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null
  done
```

---

## Phase 4: EC2 and Networking Enumeration

```bash
# List all EC2 instances across all regions
aws ec2 describe-instances --output json

# List all security groups — look for 0.0.0.0/0 ingress rules
aws ec2 describe-security-groups --output json

# List VPCs
aws ec2 describe-vpcs --output json

# List subnets
aws ec2 describe-subnets --output json

# List key pairs
aws ec2 describe-key-pairs --output json

# List snapshots owned by the account (data exfil target)
aws ec2 describe-snapshots --owner-ids self --output json

# List AMIs owned by the account
aws ec2 describe-images --owners self --output json

# List Elastic IPs
aws ec2 describe-addresses --output json
```

---

## Phase 5: Lambda Enumeration

```bash
# List all Lambda functions
aws lambda list-functions --output json

# Get configuration for each function (reveals env vars with secrets)
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | while read fn; do
    echo "=== $fn ==="
    aws lambda get-function-configuration --function-name "$fn"
    aws lambda get-policy --function-name "$fn" 2>/dev/null
  done
```

---

## Phase 6: RDS Enumeration

```bash
# List all RDS instances
aws rds describe-db-instances --output json

# List all RDS clusters (Aurora)
aws rds describe-db-clusters --output json

# List snapshots (exfil path via snapshot sharing)
aws rds describe-db-snapshots --include-shared --output json
```

---

## Phase 7: Additional Service Enumeration

```bash
# CloudTrail — where are the logs?
aws cloudtrail describe-trails --output json

# KMS — what encryption keys exist?
aws kms list-keys --output json
aws kms list-aliases --output json

# SSM Parameter Store — find stored credentials
aws ssm describe-parameters --output json

# Secrets Manager — list secret names
aws secretsmanager list-secrets --output json

# EKS clusters
aws eks list-clusters --output json

# ECS clusters
aws ecs list-clusters --output json

# SNS topics
aws sns list-topics --output json

# SQS queues
aws sqs list-queues --output json
```

---

## CDET-008 Trigger Sequence

The following condensed sequence reliably triggers CDET-008 (≥50 calls, ≥5 unique APIs, within 2 hours):

```bash
#!/bin/bash
# Run all of the above in sequence — this generates ~80-120 API calls
# across IAM, S3, EC2, Lambda, RDS, CloudTrail, KMS, SSM, Secrets Manager

aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local
aws s3api list-buckets
aws ec2 describe-instances
aws ec2 describe-security-groups
aws ec2 describe-vpcs
aws ec2 describe-subnets
aws ec2 describe-key-pairs
aws ec2 describe-snapshots --owner-ids self
aws ec2 describe-images --owners self
aws ec2 describe-addresses
aws lambda list-functions
aws rds describe-db-instances
aws rds describe-db-clusters
aws cloudtrail describe-trails
aws kms list-keys
aws kms list-aliases
aws ssm describe-parameters
aws secretsmanager list-secrets
aws eks list-clusters 2>/dev/null || true
aws ecs list-clusters 2>/dev/null || true
aws sns list-topics
aws sqs list-queues
aws iam get-account-summary
aws iam get-account-password-policy
```

Expected result: 28+ direct API calls above, plus pagination calls, total exceeds 50. Spans IAM, S3, EC2, Lambda, RDS, CloudTrail, KMS, SSM, SecretsManager — well over 5 unique APIs.

---

## Cleanup

No cleanup required — all steps are read-only. No resources are created or modified.

---

## Verification

After running, confirm CloudTrail recorded the events:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=$(aws sts get-caller-identity --query UserId --output text) \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventName,EventSource]' \
  --output table
```
