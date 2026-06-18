# CDET-010 — Simulation Steps: Mass S3 Object Deletion

**CRITICAL WARNING**: These steps PERMANENTLY DELETE S3 objects. Data deleted from unversioned buckets CANNOT be recovered. Only run against dedicated test buckets with no real data. NEVER run against production buckets.

---

## Prerequisites

- AWS CLI configured (`aws configure`)
- A dedicated test S3 bucket with test objects only
- IAM permissions: `s3:DeleteObject`, `s3:DeleteObjects`, `s3:ListBucket`

---

## Phase 0: Create Test Environment

Create a disposable test bucket with test data:

```bash
# Create test bucket with a unique name
TEST_BUCKET="cdet010-test-deletion-$(date +%s)"
REGION="us-east-1"

aws s3api create-bucket \
  --bucket "$TEST_BUCKET" \
  --region "$REGION"

# Block all public access (security best practice even for test buckets)
aws s3api put-public-access-block \
  --bucket "$TEST_BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create some test objects
for i in $(seq 1 20); do
  echo "Test object $i — this would be real data" | \
    aws s3 cp - "s3://${TEST_BUCKET}/testdata/object-${i}.txt"
done

echo "Test bucket ready: $TEST_BUCKET with 20 test objects"
```

---

## Phase 1: Reconnaissance (Assessing Bucket Defenses)

Before deletion, an attacker checks protections:

```bash
# Check if versioning is enabled (determines attack approach)
aws s3api get-bucket-versioning --bucket "$TEST_BUCKET"
# Expected for unprotected bucket: {} (empty — versioning not configured)

# Check Object Lock status
aws s3api get-object-lock-configuration --bucket "$TEST_BUCKET" 2>/dev/null || \
  echo "Object Lock NOT configured — bucket is vulnerable to permanent deletion"

# Count objects (scope the attack)
aws s3api list-objects-v2 \
  --bucket "$TEST_BUCKET" \
  --query 'KeyCount'
```

---

## Phase 2: Single Object Deletion (DeleteObject)

Single object deletion — the simplest form:

```bash
# Delete a single object
# NOTE: Without versioning, this is permanent and irreversible
aws s3api delete-object \
  --bucket "$TEST_BUCKET" \
  --key "testdata/object-1.txt"

# Confirm deletion
aws s3api get-object \
  --bucket "$TEST_BUCKET" \
  --key "testdata/object-1.txt" \
  /dev/null 2>&1 || echo "Object successfully deleted"
```

---

## Phase 3: Batch Deletion (DeleteObjects — up to 1000 per call)

This is the attack's primary destruction vector:

```bash
# List all objects and build delete request
aws s3api list-objects-v2 \
  --bucket "$TEST_BUCKET" \
  --query 'Contents[*].Key' \
  --output json | \
  python3 -c "
import json, sys
keys = json.load(sys.stdin)
delete_payload = {
    'Objects': [{'Key': k} for k in keys],
    'Quiet': False
}
print(json.dumps(delete_payload))
" > /tmp/delete-request.json

cat /tmp/delete-request.json

# Execute batch deletion (THE DETECTION EVENT)
aws s3api delete-objects \
  --bucket "$TEST_BUCKET" \
  --delete file:///tmp/delete-request.json

echo "Batch deletion complete"
```

---

## Phase 4: Versioned Deletion (Bypassing Versioning Protection)

If the bucket has versioning enabled, an attacker uses this approach to permanently destroy data:

```bash
# Enable versioning on test bucket (to demonstrate the bypass)
aws s3api put-bucket-versioning \
  --bucket "$TEST_BUCKET" \
  --versioning-configuration Status=Enabled

# Write new versioned objects
for i in $(seq 1 5); do
  echo "Versioned test data $i" | \
    aws s3 cp - "s3://${TEST_BUCKET}/versioned/obj-${i}.txt"
done

# A naive delete creates DeleteMarkers (data still exists under the hood)
aws s3api delete-object \
  --bucket "$TEST_BUCKET" \
  --key "versioned/obj-1.txt"
# This only adds a DeleteMarker — does NOT destroy data

# Attacker approach: list ALL versions and delete them with version IDs
aws s3api list-object-versions \
  --bucket "$TEST_BUCKET" \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
  --output json

# Build combined delete request (versions + delete markers)
aws s3api list-object-versions \
  --bucket "$TEST_BUCKET" \
  --query 'Versions[*].{Key:Key,VersionId:VersionId}' \
  --output json | \
  python3 -c "
import json, sys
versions = json.load(sys.stdin) or []
payload = {'Objects': [{'Key': v['Key'], 'VersionId': v['VersionId']} for v in versions], 'Quiet': False}
print(json.dumps(payload))
" > /tmp/versioned-delete.json

# THIS IS THE PERMANENT, IRREVERSIBLE DELETION
# Each DeleteObjects call with explicit VersionId permanently destroys that version
aws s3api delete-objects \
  --bucket "$TEST_BUCKET" \
  --delete file:///tmp/versioned-delete.json
```

---

## Phase 5: Delete Entire Bucket (DeleteBucket)

After destroying all objects, an attacker may delete the bucket itself:

```bash
# Buckets must be empty before deletion
# (Force delete with AWS CLI recursive option)
aws s3 rm "s3://${TEST_BUCKET}" --recursive

aws s3api delete-bucket --bucket "$TEST_BUCKET"
echo "Bucket $TEST_BUCKET deleted"
```

---

## Cleanup

If you stop before deleting the bucket:

```bash
# Remove all objects (safe cleanup)
aws s3 rm "s3://${TEST_BUCKET}" --recursive

# Delete all versions if versioning was enabled
aws s3api list-object-versions \
  --bucket "$TEST_BUCKET" \
  --output json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
versions = data.get('Versions', []) + data.get('DeleteMarkers', [])
if versions:
    payload = {'Objects': [{'Key': v['Key'], 'VersionId': v['VersionId']} for v in versions], 'Quiet': True}
    print(json.dumps(payload))
" > /tmp/cleanup.json

[ -s /tmp/cleanup.json ] && \
  aws s3api delete-objects --bucket "$TEST_BUCKET" --delete file:///tmp/cleanup.json

aws s3api delete-bucket --bucket "$TEST_BUCKET"
```

---

## Detection Note

The critical events for CDET-010 are `DeleteObjects` (batch) calls with high `requestParameters.delete.objects` counts, and `DeleteBucket`. A single `DeleteObjects` call deleting 100+ objects is a high-fidelity signal of destructive activity.
