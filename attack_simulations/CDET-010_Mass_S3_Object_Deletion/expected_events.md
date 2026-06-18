# CDET-010 — Expected CloudTrail Events: Mass S3 Object Deletion

**Primary Detection Events**: `DeleteObjects`, `DeleteObject`

---

## Primary Detection Event: DeleteObjects (Batch)

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
  "eventTime": "2026-06-16T03:45:11Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteObjects",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "bucketName": "victim-prod-data-bucket",
    "delete": {
      "quiet": false,
      "objects": [
        { "key": "data/customer-records-2025-01.csv" },
        { "key": "data/customer-records-2025-02.csv" },
        { "key": "data/customer-records-2025-03.csv" },
        { "key": "backups/db-backup-20260101.sql.gz" }
      ]
    }
  },
  "responseElements": {
    "DeleteResult": {
      "Deleted": [
        { "key": "data/customer-records-2025-01.csv" },
        { "key": "data/customer-records-2025-02.csv" }
      ],
      "Error": []
    }
  },
  "eventType": "AwsApiCall",
  "managementEvent": false,
  "readOnly": false
}
```

**Note**: `DeleteObjects` is a **data event**. To capture it in CloudTrail, S3 data events must be enabled for the bucket. Without data event logging, only management events (like `DeleteBucket`) are recorded by default.

---

## DeleteObject (Single Object Deletion)

```json
{
  "eventName": "DeleteObject",
  "eventSource": "s3.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "bucketName": "victim-prod-data-bucket",
    "key": "sensitive-file.docx"
  },
  "responseElements": null
}
```

---

## DeleteObject with VersionId (Versioning Bypass — Permanent Destruction)

```json
{
  "eventName": "DeleteObject",
  "eventSource": "s3.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "bucketName": "victim-versioned-bucket",
    "key": "important-data.csv",
    "versionId": "example-version-id-abc123"
  },
  "responseElements": {
    "x-amz-version-id": "example-version-id-abc123",
    "x-amz-delete-marker": "true"
  }
}
```

When `versionId` is present in `requestParameters`, the deletion is permanent and bypasses versioning protection.

---

## DeleteBucket (Entire Bucket Destruction)

```json
{
  "eventName": "DeleteBucket",
  "eventSource": "s3.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "bucketName": "victim-prod-data-bucket"
  },
  "responseElements": null,
  "managementEvent": true
}
```

`DeleteBucket` is a management event and is always recorded in CloudTrail regardless of data event configuration.

---

## Event Table

| eventName | eventSource | readOnly | managementEvent | Data Events Required |
|-----------|-------------|----------|-----------------|---------------------|
| `DeleteObject` | `s3.amazonaws.com` | false | false | YES |
| `DeleteObjects` | `s3.amazonaws.com` | false | false | YES |
| `DeleteObjectVersion` | `s3.amazonaws.com` | false | false | YES |
| `DeleteBucket` | `s3.amazonaws.com` | false | true | NO |
| `DeleteBucketReplication` | `s3.amazonaws.com` | false | true | NO |
| `DeleteBucketLifecycle` | `s3.amazonaws.com` | false | true | NO |
| `ListObjectVersions` | `s3.amazonaws.com` | true | false | YES (if logging data events) |

---

## Key requestParameters Fields for Detection

| Field | Detection Significance |
|-------|----------------------|
| `delete.objects` array length | Number of objects deleted in one batch. Length > 100 is high-fidelity signal |
| `versionId` in delete request | Explicit version deletion — bypasses versioning, permanent |
| `quiet: false` | Attacker requested confirmation of each deletion |
| `bucketName` | Cross-reference against known high-value buckets |

---

## Reconnaissance Events (Preceding Deletion)

These events indicate the attacker was assessing the bucket before deleting:

| eventName | eventSource | Notes |
|-----------|-------------|-------|
| `ListObjectsV2` | `s3.amazonaws.com` | Enumerate objects to delete |
| `ListObjectVersions` | `s3.amazonaws.com` | Check for versioning — indicates intent to bypass it |
| `GetBucketVersioning` | `s3.amazonaws.com` | Check versioning status |
| `GetObjectLockConfiguration` | `s3.amazonaws.com` | Check if Object Lock is enabled |
| `HeadBucket` | `s3.amazonaws.com` | Verify bucket existence |

---

## Detection Thresholds

CDET-010 triggers on:
- `DeleteObjects` with `delete.objects` count >= 50 in a single call, OR
- >= 100 `DeleteObject` events from a single principal within 10 minutes, OR
- `DeleteBucket` on any bucket with active data

---

## CloudTrail Data Events Configuration

To capture `DeleteObject` and `DeleteObjects` events, you must enable S3 data event logging:

```bash
# Enable data events for all S3 buckets on a trail
aws cloudtrail put-event-selectors \
  --trail-name my-cloudtrail \
  --event-selectors '[{
    "ReadWriteType": "WriteOnly",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::"]
    }]
  }]'
```

Without this configuration, `DeleteObject` and `DeleteObjects` events will NOT appear in CloudTrail, and CDET-010 will only trigger on `DeleteBucket`.
