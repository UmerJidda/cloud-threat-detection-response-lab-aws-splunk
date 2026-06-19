---
detection_id: CDET-009
detection_name: S3 Replication to External Account
tactic: Exfiltration
technique: T1537
last_updated: 2026-06-18
---

# CDET-009 — Recovery Playbook
## S3 Replication to External Account

**Prerequisite:** Containment playbook completed. Attacker access revoked and replication removed.  
**Goal:** Restore normal operations safely, verify the environment is clean, harden against recurrence, and tune detection.

---

## 1. Verify the Threat Has Been Fully Removed

Before restoring any services, confirm all attacker artifacts are gone.

### 1a. Confirm replication is removed from all affected buckets

```bash
# For each bucket identified during investigation:
aws s3api get-bucket-replication --bucket <bucket_name>
# Expected: ReplicationConfigurationNotFoundError

# Broad check across all buckets in the account
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  result=$(aws s3api get-bucket-replication --bucket "$bucket" 2>&1)
  if [[ "$result" != *"ReplicationConfigurationNotFoundError"* ]]; then
    echo "REPLICATION FOUND: $bucket"
    echo "$result"
  fi
done
```

### 1b. Confirm no new unauthorized replication has been configured since containment

```spl
index=aws_cloudtrail eventName=PutBucketReplication
| where _time >= "<containment_timestamp>"
| table _time, userIdentity.arn, requestParameters.bucketName, requestParameters.replicationConfiguration
```

If any results appear, re-enter the containment phase immediately.

### 1c. Confirm attacker credentials are fully disabled

```bash
# IAM user access key
aws iam list-access-keys --user-name <username> \
  --query 'AccessKeyMetadata[*].{Key:AccessKeyId,Status:Status}'
# All keys used by attacker must show Status=Inactive

# Confirm the role trust policy blocks all assumptions
aws iam get-role --role-name <compromised_role_name> \
  --query 'Role.AssumeRolePolicyDocument'
```

### 1d. Confirm no additional backdoors were created

Check for IAM resources created by the attacker that may still be active:

```bash
# Users created during attack window
aws iam list-users --query "Users[?CreateDate>=\`<attack_start_time>\`]"

# Roles created during attack window
aws iam list-roles --query "Roles[?CreateDate>=\`<attack_start_time>\`]"

# Access keys created during attack window
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I {} aws iam list-access-keys --user-name {} \
  --query "AccessKeyMetadata[?CreateDate>=\`<attack_start_time>\`].{User:'{}',Key:AccessKeyId,Status:Status}"
```

---

## 2. Restore Normal Operations

### 2a. Restore legitimate replication (if applicable)

If the affected bucket had an authorized replication configuration before the incident, restore it from the pre-incident backup or from a known-good configuration in your IaC repository (Terraform/CloudFormation).

```bash
# From IaC — preferred approach (re-apply via your deployment pipeline)
# This ensures the restored config matches the approved, version-controlled state

# Manual fallback only if IaC is unavailable:
aws s3api put-bucket-replication \
  --bucket <bucket_name> \
  --replication-configuration file:///tmp/approved_replication_config.json
```

### 2b. Remove the temporary incident deny policies

After confirming the attacker has no active sessions (session tokens expire; max 12 hours):

```bash
# Remove the incident revocation inline policy from affected roles
aws iam delete-role-policy \
  --role-name <compromised_role_name> \
  --policy-name INCIDENT_REVOCATION_CDET009

aws iam delete-role-policy \
  --role-name <replication_role_name> \
  --policy-name INCIDENT_REVOCATION_CDET009
```

### 2c. Re-attach policies to service roles that were stripped during containment

Restore from your IaC repository rather than manually reconstructing policies:

```bash
# Re-attach managed policies
aws iam attach-role-policy \
  --role-name <service_role_name> \
  --policy-arn <policy_arn>
```

### 2d. Remove or revise the temporary bucket deny policy

Replace the incident-specific deny with a permanent, minimal-privilege policy drawn from your IaC:

```bash
# Apply the permanent, approved bucket policy from IaC
aws s3api put-bucket-policy \
  --bucket <bucket_name> \
  --policy file://approved_bucket_policy.json

# OR remove the policy entirely if no policy was present before
aws s3api delete-bucket-policy --bucket <bucket_name>
```

---

## 3. Data Exposure Assessment

### 3a. Determine what data was replicated

Working with the data owner and legal/compliance:

1. Enumerate all objects written to the bucket between the `PutBucketReplication` event time and the `DeleteBucketReplication` containment time.
2. Classify the sensitivity of those objects (PII, secrets, financial, IP).
3. Determine if any regulatory breach notification obligations apply (GDPR 72-hour window, HIPAA, PCI DSS).

```bash
# Objects written during the exposure window
aws s3api list-objects-v2 \
  --bucket <bucket_name> \
  --query "Contents[?LastModified>=\`<replication_start>\` && LastModified<=\`<containment_time>\`].{Key:Key,Size:Size,LastModified:LastModified}" \
  --output json > /tmp/CDET-009_exposed_objects_<incident_id>.json
```

### 3b. Check whether secrets were stored in the bucket

```bash
# Scan object keys for common secret file naming patterns
aws s3api list-objects-v2 \
  --bucket <bucket_name> \
  --query 'Contents[*].Key' --output text | \
  grep -iE '\.(env|pem|key|pfx|p12|crt|secrets|credentials|config)$|secrets|private|password|token'
```

If secrets are identified, rotate them immediately (separate runbook).

---

## 4. Hardening Steps to Prevent Recurrence

Apply these controls to reduce the risk of future CDET-009 incidents.

### 4a. Enforce a Service Control Policy (SCP) restricting cross-account replication

Apply at the AWS Organization or OU level:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyReplicationToUnauthorizedAccounts",
      "Effect": "Deny",
      "Action": "s3:PutReplicationConfiguration",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "<your_org_id>"
        }
      }
    }
  ]
}
```

Deploy via AWS Organizations:
```bash
aws organizations create-policy \
  --name "DenyS3ReplicationToExternalAccounts" \
  --type SERVICE_CONTROL_POLICY \
  --content file://scp_deny_external_replication.json

aws organizations attach-policy \
  --policy-id <policy_id> \
  --target-id <ou_id>
```

### 4b. Apply least-privilege IAM for S3 service roles

Remove `s3:PutReplicationConfiguration` and `iam:PassRole` from all roles that do not explicitly require them. Use IAM Access Analyzer to identify over-permissive policies:

```bash
aws accessanalyzer list-findings \
  --analyzer-arn <analyzer_arn> \
  --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]}}'
```

### 4c. Enable S3 Block Public Access and Object Lock for sensitive buckets

```bash
aws s3api put-public-access-block \
  --bucket <bucket_name> \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 4d. Enable AWS Config rule for continuous monitoring

```bash
# Ensure aws-config rule 's3-bucket-replication-enabled' is monitored
# Create a custom Config rule or use AWS Security Hub S3 controls:
aws securityhub enable-standards \
  --standards-subscription-requests '[{"StandardsArn":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"}]'
```

### 4e. Enforce CloudTrail and S3 access logging on all buckets

```bash
aws s3api put-bucket-logging \
  --bucket <bucket_name> \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "<log-bucket>",
      "TargetPrefix": "<bucket_name>/"
    }
  }'
```

---

## 5. Detection Tuning Recommendations

### Suppress known-good pipelines (reduce FP rate)

Update `splunk/lookups/known_pipeline_actors.csv` with the verified pipeline IAM roles that legitimately call `PutBucketReplication`. Coordinate with the detection engineer.

Add a suppression in the Splunk alert for CDET-009:
```spl
index=aws_cloudtrail eventName=PutBucketReplication
| lookup splunk/lookups/known_pipeline_actors.csv userArn AS userIdentity.arn OUTPUT is_approved
| lookup splunk/lookups/trusted_aws_accounts.csv account_id AS dest_account_id OUTPUT is_authorized
| where NOT (is_approved="true" AND is_authorized="true")
```

### Enrich alerts with destination account metadata

Modify the CDET-009 Splunk alert to automatically join against `trusted_aws_accounts.csv` and include `account_label`, `is_authorized`, and `data_classification` in the alert payload sent to the SIEM/SOAR. This gives the first responder context before they open the playbook.

### Add a secondary correlated alert

Create a follow-on detection (`CDET-009b`) that fires when:
- `PutBucketReplication` is followed within 30 minutes by `PutObject` or `CompleteMultipartUpload` on the same bucket
- The replication destination remains unauthorized

This catches active exfiltration after the replication rule is set.

### Consider alerting on `GetBucketReplication` chains

An unusual number of `GetBucketReplication` calls before a `PutBucketReplication` indicates an attacker enumerating existing rules before modifying them. Add this pattern to the reconnaissance detection backlog.

---

## 6. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

**Timeline and scope:**
- [ ] Full attack timeline documented from first attacker action to containment
- [ ] All affected buckets, IAM roles, and access keys identified and documented
- [ ] Total data exposure estimate completed (object count, size, classification)
- [ ] Regulatory notification obligations assessed and documented

**Root cause:**
- [ ] How did the attacker obtain credentials with `s3:PutReplicationConfiguration`?
- [ ] Was this a compromised human identity or a compromised CI/CD secret?
- [ ] Were the IAM permissions overly broad? Which policy granted `s3:PutReplicationConfiguration`?
- [ ] Was there a detection gap (e.g., the replication ran for an extended period before alerting)?

**Process improvements:**
- [ ] IaC updated to enforce least-privilege S3 IAM policies
- [ ] SCP deployed to restrict cross-account replication (if not already done)
- [ ] Lookup CSVs updated: `trusted_aws_accounts.csv`, `known_pipeline_actors.csv`
- [ ] Detection CDET-009 alert tuning applied (suppression and/or enrichment)
- [ ] CDET-009b correlated follow-on alert created or backlogged
- [ ] Runbook gaps identified and addressed (update triage/investigation/containment/recovery as needed)

**Lessons learned:**
- [ ] PIR (Post-Incident Review) meeting held with Cloud Security, IAM team, and bucket owner
- [ ] Action items tracked in the team backlog with owners and due dates
- [ ] Incident summary shared with security leadership (no PII/sensitive data in summary)
- [ ] CDET-009 detection coverage rated against MITRE ATT&CK T1537 sub-techniques
