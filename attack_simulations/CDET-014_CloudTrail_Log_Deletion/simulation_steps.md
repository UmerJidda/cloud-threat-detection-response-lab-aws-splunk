# CDET-014 — Simulation Steps: CloudTrail Log File Deleted from S3

**CRITICAL WARNING**: Deleting CloudTrail log files destroys forensic evidence. These steps should ONLY be performed in isolated test accounts with no production workloads or compliance requirements. These steps should NEVER be performed on production CloudTrail log buckets under any circumstances. Unauthorized log deletion may violate compliance requirements (SOC 2, PCI DSS, HIPAA, FedRAMP) and could be evidence tampering.

---

## Prerequisites

- AWS CLI configured with an isolated test account
- IAM permissions: `s3:DeleteObject`, `s3:ListBucket`, `s3:GetObject`
- CloudTrail must be enabled and delivering to an S3 bucket

---

## Phase 1: Identify CloudTrail Log Buckets

```bash
# List all CloudTrail trails and their S3 destinations
aws cloudtrail describe-trails \
  --query 'trailList[*].[Name,S3BucketName,IsMultiRegionTrail,HasCustomEventSelectors]' \
  --output table

# Save trail details
aws cloudtrail describe-trails \
  --include-shadow-trails \
  --output json

# Get the primary trail's S3 bucket
TRAIL_BUCKET=$(aws cloudtrail describe-trails \
  --query 'trailList[0].S3BucketName' \
  --output text)

echo "CloudTrail log bucket: $TRAIL_BUCKET"
```

---

## Phase 2: Enumerate Log Files

CloudTrail log files follow a predictable key structure:

```
AWSLogs/{account-id}/CloudTrail/{region}/{year}/{month}/{day}/
{account-id}_CloudTrail_{region}_{timestamp}_{unique-id}.json.gz
```

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "us-east-1")

# List log files for today
YEAR=$(date +%Y)
MONTH=$(date +%m)
DAY=$(date +%d)

LOG_PREFIX="AWSLogs/${ACCOUNT_ID}/CloudTrail/${REGION}/${YEAR}/${MONTH}/${DAY}/"

echo "Listing CloudTrail logs with prefix: $LOG_PREFIX"
aws s3api list-objects-v2 \
  --bucket "$TRAIL_BUCKET" \
  --prefix "$LOG_PREFIX" \
  --query 'Contents[*].[Key,Size,LastModified]' \
  --output table

# Count total log files in bucket
echo "Total objects in bucket:"
aws s3api list-objects-v2 \
  --bucket "$TRAIL_BUCKET" \
  --query 'KeyCount'
```

---

## Phase 3: Verify Bucket Protections

Before attempting deletion, check protections:

```bash
# Check Object Lock
aws s3api get-object-lock-configuration \
  --bucket "$TRAIL_BUCKET" 2>/dev/null || \
  echo "Object Lock NOT configured — bucket is VULNERABLE to permanent deletion"

# Check versioning
aws s3api get-bucket-versioning --bucket "$TRAIL_BUCKET"

# Check bucket policy (look for explicit deny on DeleteObject)
aws s3api get-bucket-policy --bucket "$TRAIL_BUCKET" 2>/dev/null || \
  echo "No bucket policy configured"

# Check MFA delete
aws s3api get-bucket-versioning \
  --bucket "$TRAIL_BUCKET" \
  --query 'MFADelete'
```

---

## Phase 4: Delete a Single Log File (THE DETECTION EVENT)

**ONLY run this in an isolated test account with no production data.**

```bash
# Find one specific log file to target
TARGET_KEY=$(aws s3api list-objects-v2 \
  --bucket "$TRAIL_BUCKET" \
  --prefix "$LOG_PREFIX" \
  --query 'Contents[0].Key' \
  --output text)

echo "Target log file: $TARGET_KEY"
echo "Key format example: AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/16/123456789012_CloudTrail_us-east-1_20260616T0000Z_abc123.json.gz"

# THE DETECTION EVENT — delete a CloudTrail log file
aws s3api delete-object \
  --bucket "$TRAIL_BUCKET" \
  --key "$TARGET_KEY"

echo "DeleteObject event generated for CloudTrail log: $TARGET_KEY"
echo "CDET-014 should fire based on the key pattern matching AWSLogs/*/CloudTrail/*"
```

---

## Phase 5: Bulk Log Deletion (High-Impact Variant)

```bash
# Build delete request for all logs from today
aws s3api list-objects-v2 \
  --bucket "$TRAIL_BUCKET" \
  --prefix "$LOG_PREFIX" \
  --query 'Contents[*].Key' \
  --output json | \
  python3 -c "
import json, sys
keys = json.load(sys.stdin)
if keys:
    payload = {'Objects': [{'Key': k} for k in keys], 'Quiet': False}
    print(json.dumps(payload))
else:
    print('No log files found for today')
    exit(1)
" > /tmp/ct-delete-request.json

# This deletes ALL of today's CloudTrail logs in one batch
# (ONLY IN ISOLATED TEST ACCOUNT)
aws s3api delete-objects \
  --bucket "$TRAIL_BUCKET" \
  --delete file:///tmp/ct-delete-request.json
```

---

## Phase 6: Disable CloudTrail Logging (Related Technique)

The most aggressive anti-forensic variant disables CloudTrail entirely rather than deleting individual files:

```bash
# Get trail name
TRAIL_ARN=$(aws cloudtrail describe-trails \
  --query 'trailList[0].TrailARN' --output text)

# Disable logging (ONLY IN ISOLATED TEST ACCOUNT)
# This generates a StopLogging event in CloudTrail (if any logging is still active elsewhere)
aws cloudtrail stop-logging --name "$TRAIL_ARN"

# This is detected by CDET-014's related detection for StopLogging events
# Re-enable immediately
aws cloudtrail start-logging --name "$TRAIL_ARN"
```

---

## Cleanup and Verification

```bash
# Verify the deletion was recorded (ironically, in CloudTrail)
# Note: The deletion event itself is recorded IF S3 data events are enabled
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
  --start-time $(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,CloudTrailEvent]' \
  --output json

# The detection paradox: the DeleteObject event for CloudTrail logs
# is itself a CloudTrail event — recorded in the same trail
# (This only works if S3 data events are enabled)
```

---

## Important Note on Detection

The `DeleteObject` on a CloudTrail log file is detected via:
1. **S3 data events** in CloudTrail (must be enabled)
2. **Amazon GuardDuty** (S3Protection feature detects suspicious S3 deletions)
3. **CloudWatch Events / EventBridge** rules on S3 bucket events

If S3 data events are NOT enabled on the CloudTrail trail that monitors this bucket, the `DeleteObject` events will NOT appear in CloudTrail. This is itself a configuration gap detected by CDET-014's `simulate.py` assessment mode.
