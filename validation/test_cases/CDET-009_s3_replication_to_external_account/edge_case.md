# CDET-009 — Edge Case

**Purpose:** Verify detection behavior when the replication rule does not include an explicit Account field (destination account inferred from bucket ARN) or when multiple rules include a mix of internal and external destinations.

## Scenario: Replication Rule Without Explicit Account Field

### Background
Some S3 replication configurations specify only the destination bucket ARN without an explicit Account field. The destination account must be inferred by parsing the ARN.

### Event Details
- eventName: PutBucketReplication
- requestParameters.ReplicationConfiguration.Rule.Destination:
  - Bucket: "arn:aws:s3:::999888777666-exfil-bucket" (bucket named with external account ID prefix, but no Account field)
  - No explicit Account field in the rule

### Expected Result
- Detection behavior depends on SPL parsing logic
- If SPL extracts account from the bucket ARN: detection fires (correct behavior)
- If SPL only checks the Account field: detection does NOT fire (detection gap — document this)
- Verify and document which extraction method is used

## Scenario: Multiple Replication Rules — One Internal, One External

### Event Details
- eventName: PutBucketReplication
- ReplicationConfiguration contains two rules:
  - Rule 1: Destination Account = 123456789012 (same account, internal)
  - Rule 2: Destination Account = 999888777666 (external)

### Expected Result
- Detection fires: YES (because at least one rule has an external destination)
- Verify SPL correctly handles multi-rule configurations and fires on any external destination
- destination_account_id should reflect the external account (999888777666)

## Scenario: Replication to External Account Previously Approved but Recently Removed from Lookup

### Event Details
- eventName: PutBucketReplication
- Destination Account: 555444333222
- 555444333222 WAS in approved_replication_accounts but was removed yesterday

### Expected Result
- Detection fires: YES (account is no longer in the approved lookup)
- Verify lookup is current and removal takes effect on the next detection run
- This tests the operational process of maintaining suppression lookups

## Pass Criteria
- Document SPL behavior for missing Account field in replication rule
- Confirm detection fires when any rule in a multi-rule config has an external destination
- Confirm detection fires for accounts removed from the approved lookup
- Update SPL to extract account from bucket ARN if not already implemented
