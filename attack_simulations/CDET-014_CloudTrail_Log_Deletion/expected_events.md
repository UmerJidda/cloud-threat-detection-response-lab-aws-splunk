# CDET-014 — Expected CloudTrail Events: CloudTrail Log File Deleted from S3

**Primary Detection Event**: `DeleteObject` on an S3 bucket storing CloudTrail logs

---

## Primary Detection Event: DeleteObject on CloudTrail Log Bucket

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
  "eventTime": "2026-06-16T07:55:00Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "bucketName": "my-org-cloudtrail-logs",
    "key": "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/16/123456789012_CloudTrail_us-east-1_20260616T0700Z_AbCdEfGhIjKl.json.gz"
  },
  "responseElements": null,
  "resources": [
    {
      "ARN": "arn:aws:s3:::my-org-cloudtrail-logs/AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/16/123456789012_CloudTrail_us-east-1_20260616T0700Z_AbCdEfGhIjKl.json.gz",
      "accountId": "123456789012",
      "type": "AWS::S3::Object"
    }
  ],
  "eventType": "AwsApiCall",
  "managementEvent": false,
  "readOnly": false,
  "recipientAccountId": "123456789012"
}
```

---

## CloudTrail Log Key Format

The `requestParameters.key` field contains the S3 object key of the deleted log. CloudTrail log files always follow this exact pattern:

```
AWSLogs/{account-id}/CloudTrail/{region}/{year}/{month}/{day}/{account-id}_CloudTrail_{region}_{timestamp}_{unique-id}.json.gz
```

**Example keys**:
```
AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/16/123456789012_CloudTrail_us-east-1_20260616T0000Z_AbCdEfGh.json.gz
AWSLogs/123456789012/CloudTrail/us-west-2/2026/06/16/123456789012_CloudTrail_us-west-2_20260616T0015Z_IjKlMnOp.json.gz
```

**Digest files** (log file integrity validation) also appear in CloudTrail deletion attacks:
```
AWSLogs/{account-id}/CloudTrail-Digest/{region}/{year}/{month}/{day}/{account-id}_CloudTrail-Digest_{region}_{trail-name}_{region}_{timestamp}.json.gz
```

---

## Detection Logic

The detection signature is:
1. `eventName = DeleteObject` (or `DeleteObjects`)
2. `requestParameters.bucketName` matches the known CloudTrail log bucket
3. `requestParameters.key` matches the pattern `AWSLogs/*/CloudTrail/*`

OR (if bucket name is unknown but key pattern is sufficient):
1. `eventName = DeleteObject`
2. `requestParameters.key` matches regex: `AWSLogs/[0-9]{12}/CloudTrail/`

---

## Batch Deletion: DeleteObjects

```json
{
  "eventName": "DeleteObjects",
  "eventSource": "s3.amazonaws.com",
  "requestParameters": {
    "bucketName": "my-org-cloudtrail-logs",
    "delete": {
      "quiet": false,
      "objects": [
        { "key": "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/16/123456789012_CloudTrail_us-east-1_20260616T0000Z_abc.json.gz" },
        { "key": "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/16/123456789012_CloudTrail_us-east-1_20260616T0015Z_def.json.gz" },
        { "key": "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/15/123456789012_CloudTrail_us-east-1_20260615T2345Z_ghi.json.gz" }
      ]
    }
  }
}
```

Multiple log files deleted in a single `DeleteObjects` call is higher severity — indicates targeted, automated log destruction rather than accidental single-file deletion.

---

## Related Events: Disabling CloudTrail Logging

These events are alternative or companion techniques to S3 log deletion:

### StopLogging — Disables CloudTrail trail

```json
{
  "eventName": "StopLogging",
  "eventSource": "cloudtrail.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-org-trail"
  },
  "responseElements": null
}
```

### DeleteTrail — Permanently removes the trail

```json
{
  "eventName": "DeleteTrail",
  "eventSource": "cloudtrail.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-org-trail"
  }
}
```

### UpdateTrail — Redirects logs to attacker-controlled bucket

```json
{
  "eventName": "UpdateTrail",
  "eventSource": "cloudtrail.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "name": "my-org-trail",
    "s3BucketName": "attacker-controlled-bucket"
  }
}
```

`UpdateTrail` to change the S3 bucket is a stealthy variant — new logs go to the attacker's bucket (where the attacker can see them and control access), while the SIEM stops receiving new events.

---

## Detection Data Requirements

CDET-014 requires S3 data events to be logged in CloudTrail:

| Log Type | `DeleteObject` Visible | `DeleteObjects` Visible | `DeleteBucket` Visible |
|----------|----------------------|------------------------|----------------------|
| Management events only | NO | NO | YES |
| S3 data events (Write) | YES | YES | YES |
| S3 data events (Read + Write) | YES | YES | YES |

**Configuration verification**:
```bash
aws cloudtrail get-event-selectors --trail-name my-trail
# Look for DataResources with Type: AWS::S3::Object
# and ReadWriteType: WriteOnly or All
```

---

## Self-Referential Paradox

An important nuance: CloudTrail is configured to log S3 events IN THE SAME TRAIL whose logs are being deleted. This means:

1. Attacker deletes log file X from the CloudTrail bucket
2. This deletion generates a new CloudTrail event (let's call it event Y)
3. Event Y is delivered to the same CloudTrail bucket
4. If the attacker then deletes event Y, that generates event Z...

The practical result: the deletion of CloudTrail logs is itself logged in CloudTrail (if S3 data events are enabled), creating a self-documenting record of the tampering attempt. The attacker cannot delete the record of the deletion without creating another record, ad infinitum.

This is why CDET-014 is such a high-fidelity detection — even a successful log deletion creates undeniable evidence of tampering.
