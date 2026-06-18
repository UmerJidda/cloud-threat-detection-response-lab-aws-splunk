# CDET-008 — Expected CloudTrail Events: Excessive API Enumeration

**Detection Logic**: ≥50 API calls AND ≥5 unique eventNames within a 2-hour sliding window for a single IAM principal.

---

## Event Inventory

All events share the following characteristics:
- `eventType`: `AwsApiCall`
- `readOnly`: `true`
- `errorCode`: absent (successful calls) or `AccessDenied` (if permissions missing)
- No `requestParameters` that modify resources

| # | eventSource | eventName | Notes |
|---|-------------|-----------|-------|
| 1 | `sts.amazonaws.com` | `GetCallerIdentity` | First call by every automated tool |
| 2 | `iam.amazonaws.com` | `ListUsers` | Enumerate all IAM users |
| 3 | `iam.amazonaws.com` | `ListRoles` | Enumerate all IAM roles (reveals trust policies) |
| 4 | `iam.amazonaws.com` | `ListGroups` | Enumerate all IAM groups |
| 5 | `iam.amazonaws.com` | `ListPolicies` | List customer-managed policies |
| 6 | `iam.amazonaws.com` | `GetAccountSummary` | Account-wide IAM statistics |
| 7 | `iam.amazonaws.com` | `GetAccountPasswordPolicy` | Password strength configuration |
| 8 | `iam.amazonaws.com` | `ListAttachedUserPolicies` | Per-user policy attachments |
| 9 | `iam.amazonaws.com` | `ListUserPolicies` | Inline policies per user |
| 10 | `iam.amazonaws.com` | `ListAttachedRolePolicies` | Per-role policy attachments |
| 11 | `s3.amazonaws.com` | `ListBuckets` | All S3 buckets in account |
| 12 | `s3.amazonaws.com` | `GetBucketPublicAccessBlock` | Per-bucket public access setting |
| 13 | `s3.amazonaws.com` | `GetBucketEncryption` | Per-bucket encryption config |
| 14 | `s3.amazonaws.com` | `GetBucketVersioning` | Versioning status (ransomware relevance) |
| 15 | `s3.amazonaws.com` | `GetBucketAcl` | ACL grants (reveals public access) |
| 16 | `s3.amazonaws.com` | `GetBucketPolicy` | Bucket resource policy |
| 17 | `ec2.amazonaws.com` | `DescribeInstances` | All EC2 instances, IPs, instance types |
| 18 | `ec2.amazonaws.com` | `DescribeSecurityGroups` | All SG rules — attacker maps network exposure |
| 19 | `ec2.amazonaws.com` | `DescribeVpcs` | VPC CIDR ranges |
| 20 | `ec2.amazonaws.com` | `DescribeSubnets` | Subnet layout |
| 21 | `ec2.amazonaws.com` | `DescribeKeyPairs` | SSH key names |
| 22 | `ec2.amazonaws.com` | `DescribeSnapshots` | EBS snapshots (exfil via snapshot share) |
| 23 | `ec2.amazonaws.com` | `DescribeImages` | Custom AMIs owned by account |
| 24 | `ec2.amazonaws.com` | `DescribeAddresses` | Elastic IPs |
| 25 | `lambda.amazonaws.com` | `ListFunctions` | All Lambda functions |
| 26 | `lambda.amazonaws.com` | `GetFunctionConfiguration` | Env vars, runtime, role ARN |
| 27 | `lambda.amazonaws.com` | `GetPolicy` | Lambda resource policies |
| 28 | `rds.amazonaws.com` | `DescribeDBInstances` | RDS instances, public accessibility flag |
| 29 | `rds.amazonaws.com` | `DescribeDBClusters` | Aurora clusters |
| 30 | `rds.amazonaws.com` | `DescribeDBSnapshots` | RDS snapshots |
| 31 | `cloudtrail.amazonaws.com` | `DescribeTrails` | Where audit logs are stored |
| 32 | `kms.amazonaws.com` | `ListKeys` | KMS key IDs |
| 33 | `kms.amazonaws.com` | `ListAliases` | Human-readable key names |
| 34 | `ssm.amazonaws.com` | `DescribeParameters` | Parameter Store path listing |
| 35 | `secretsmanager.amazonaws.com` | `ListSecrets` | Secret names (reveals credential locations) |
| 36 | `eks.amazonaws.com` | `ListClusters` | EKS cluster names |
| 37 | `ecs.amazonaws.com` | `ListClusters` | ECS cluster ARNs |
| 38 | `sns.amazonaws.com` | `ListTopics` | SNS topic ARNs |
| 39 | `sqs.amazonaws.com` | `ListQueues` | SQS queue URLs |

---

## Sample CloudTrail Event Structure

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEUSER123",
    "arn": "arn:aws:iam::123456789012:user/attacker-user",
    "accountId": "123456789012",
    "accessKeyId": "AKIAEXAMPLE"
  },
  "eventTime": "2026-06-16T14:23:41Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "ListRoles",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.42",
  "userAgent": "aws-cli/2.15.0 Python/3.11.0",
  "readOnly": true,
  "requestParameters": {
    "maxItems": 100
  },
  "responseElements": null,
  "requestID": "a1b2c3d4-0000-1111-2222-example",
  "eventID": "deadbeef-0000-1111-2222-example",
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012"
}
```

---

## Detection Notes

### Pagination Multiplier
Automated tools call `ListRoles`, receive a `NextToken`, and call `ListRoles` again. A single logical enumeration of IAM roles may generate 3–10 API calls depending on role count. The 50-call threshold is easily exceeded by pagination alone.

### userAgent Indicators
Common userAgent strings from attack tools:
- Pacu: `Boto3/1.x.x Python/3.x.x` (indistinguishable from legitimate boto3, but check call volume)
- ScoutSuite: `python-requests/2.x.x` or custom scout user agent
- CloudMapper: `Boto3/1.x.x Python/3.x.x`
- Manual attacker: `aws-cli/2.x.x`

A legitimate AWS Console session will show `AWS Internal` as the user agent for most calls.

### Source IP Anomaly
Enumeration tools run from:
- EC2 instances in unexpected regions
- Cloud VM providers (AWS, GCP, Azure, DigitalOcean IP ranges)
- VPN/Tor exit nodes (unusual for legitimate admin activity)
- IP addresses not matching the user's normal geolocation

### AccessDenied Patterns
Automated tools attempt calls regardless of permissions. A burst of `AccessDenied` errors on enumeration APIs from a single principal indicates attempted reconnaissance even if the attacker lacks permissions to succeed.

---

## Correlated Detections

CDET-008 often precedes:
- CDET-009 (S3 Replication) — after finding valuable S3 buckets
- CDET-011 (Unauthorized Compute) — after mapping IAM permissions sufficient to launch instances
- CDET-012 (Cross-Account Role Chain) — after finding cross-account trust relationships
- CDET-013 (Security Group Modification) — after identifying exposed instances
