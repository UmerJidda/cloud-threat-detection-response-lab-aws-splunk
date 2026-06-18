# CDET-009 — Expected CloudTrail Events: S3 Replication to External Account

**Primary Detection Event**: `PutBucketReplication`

---

## Primary Detection Event

### PutBucketReplication

This is the single most important event for CDET-009. It is a management plane event (managementEvent: true) that appears immediately upon the attacker configuring replication.

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEATTACKER",
    "arn": "arn:aws:iam::123456789012:user/compromised-user",
    "accountId": "123456789012",
    "accessKeyId": "AKIAEXAMPLEKEY"
  },
  "eventTime": "2026-06-16T02:14:33Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketReplication",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "bucketName": "victim-prod-data-bucket",
    "ReplicationConfiguration": {
      "role": "arn:aws:iam::123456789012:role/cdet009-replication-role",
      "rules": [
        {
          "id": "replicate-all-to-external",
          "status": "Enabled",
          "filter": { "prefix": "" },
          "destination": {
            "bucket": "arn:aws:s3:::attacker-exfil-bucket",
            "account": "999999999999",
            "accessControlTranslation": {
              "owner": "Destination"
            }
          },
          "deleteMarkerReplication": { "status": "Enabled" }
        }
      ]
    }
  },
  "responseElements": null,
  "requestID": "EXAMPLEREQID123",
  "eventID": "exampleeventid-0000",
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012"
}
```

**Critical detection field**: `requestParameters.ReplicationConfiguration.rules[].destination.account`  
When this value (`999999999999`) differs from `recipientAccountId` (`123456789012`), the replication is cross-account — a high-fidelity indicator of exfiltration.

---

## Supporting Events

### CreateRole — Attacker creates the replication IAM role

```json
{
  "eventName": "CreateRole",
  "eventSource": "iam.amazonaws.com",
  "requestParameters": {
    "roleName": "cdet009-replication-role",
    "assumeRolePolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"s3.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
  }
}
```

### PutRolePolicy — Attacker grants the role S3 replication permissions

```json
{
  "eventName": "PutRolePolicy",
  "eventSource": "iam.amazonaws.com",
  "requestParameters": {
    "roleName": "cdet009-replication-role",
    "policyName": "s3-replication-permissions"
  }
}
```

---

## Contextual Events (Reconnaissance Phase)

These events typically precede the replication configuration and indicate the attacker was enumerating S3 to find valuable buckets:

| eventName | eventSource | Significance |
|-----------|-------------|--------------|
| `ListBuckets` | `s3.amazonaws.com` | Attacker enumerating all buckets |
| `GetBucketLocation` | `s3.amazonaws.com` | Checking bucket region |
| `GetBucketVersioning` | `s3.amazonaws.com` | Confirming versioning (required for replication) |
| `GetBucketPolicy` | `s3.amazonaws.com` | Reviewing current policies |
| `GetBucketAcl` | `s3.amazonaws.com` | Checking access controls |
| `ListObjectsV2` | `s3.amazonaws.com` | Assessing bucket contents / value |
| `GetBucketEncryption` | `s3.amazonaws.com` | Checking encryption (may need KMS key) |

---

## Replication Activity Events (Post-Configuration)

After replication is configured, the **S3 service itself** generates these events — not the attacker. These are data plane events and only visible if S3 data event logging is enabled.

| eventName | eventSource | Principal | Notes |
|-----------|-------------|-----------|-------|
| `ReplicateObject` | `s3.amazonaws.com` | `s3.amazonaws.com` | Per-object copy event |
| `PutObject` | `s3.amazonaws.com` | `s3.amazonaws.com` | Object written to destination |

Note: The principal for replication events is the S3 service (`s3.amazonaws.com`), not an IAM user. This is why the configuration event (`PutBucketReplication`) is the primary detection point.

---

## What the External Account Field Reveals

The destination `account` field in the replication configuration contains the destination AWS account ID. Detection logic should:

1. Extract `requestParameters.ReplicationConfiguration.rules[].destination.account`
2. Compare against `recipientAccountId` (source account)
3. Compare against known trusted accounts list (e.g., org member accounts)
4. Alert if the destination account is unknown / outside the organization

A replication rule without an explicit `account` field is same-account (less suspicious but should still be reviewed for unexpected destination buckets).

---

## Cleanup Event (Remediation Indicator)

```json
{
  "eventName": "DeleteBucketReplication",
  "eventSource": "s3.amazonaws.com",
  "requestParameters": {
    "bucketName": "victim-prod-data-bucket"
  }
}
```

If `DeleteBucketReplication` follows a `PutBucketReplication` by a different IAM principal within a short time window, this may indicate the security team has begun remediation.
