---
detection_id: CDET-006
detection_name: Root Account Activity Detected
tactic: Initial Access
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-006 — Root Account Activity Detected: Recovery

> **Audience:** Tier-2 SOC analyst with AWS experience.
> **Prerequisites:** Containment complete; all immediate threats neutralized.
> **Credential rule:** Use the boto3 default credential chain only (`aws configure` / IAM role / environment). Never hardcode credentials.

---

## 1. Verify the Threat Has Been Fully Removed

Complete each verification step and record results in the incident ticket before declaring recovery.

### 1a. Confirm No Root Access Keys Exist

```bash
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
```

Expected: `0`. Any other value requires immediate escalation.

### 1b. Confirm Root MFA Is Enabled

```bash
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```

Expected: `1`.

### 1c. Confirm No Adversary-Created IAM Entities Remain Active

For each IAM user or role identified during investigation as adversary-created:

```bash
# Check user still has no active keys
aws iam list-access-keys --user-name <USERNAME> \
  --query 'AccessKeyMetadata[*].[AccessKeyId,Status]' --output table

# Confirm no console login profile exists or password is randomized
aws iam get-login-profile --user-name <USERNAME>

# Confirm no policies are attached
aws iam list-attached-user-policies --user-name <USERNAME>
aws iam list-user-policies --user-name <USERNAME>
```

### 1d. Confirm CloudTrail Is Running and Intact

```bash
# Verify all expected trails are active and logging
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]' \
  --output table

# Check logging status for each trail
aws cloudtrail get-trail-status --name <TRAIL_NAME> \
  --query '[IsLogging,LatestDeliveryTime,LatestDeliveryError]'
```

### 1e. Confirm No New Root Activity After Containment

```spl
index=aws_cloudtrail userIdentity.type=Root
  earliest=<CONTAINMENT_TIMESTAMP> latest=now
| stats count by eventName, sourceIPAddress, awsRegion
```

Expected: zero events, or only the containment actions performed by your team.

### 1f. Verify No Unauthorized Data Exfiltration (Spot Check)

```bash
# Check S3 data transfer for anomalous GetObject volume
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "<INCIDENT_START>" \
  --end-time "<CONTAINMENT_TIMESTAMP>" \
  --output json | python3 -m json.tool | grep -c "eventName"
```

Review the count and bucket names. Escalate if sensitive buckets show unexpected access.

---

## 2. Restore Normal Operations

1. Remove any temporary deny policies or SCPs applied solely for containment (if the permanent SCP in `containment.md` Step 7 was not intended as permanent).
2. Re-enable any AWS services or integrations that were paused during containment (e.g., Lambda functions, EventBridge rules).
3. Notify the Account Owner and relevant stakeholders that containment is complete.
4. If legitimate automation or pipelines were disrupted by key rotation or user disablement, work with the owning team to issue new credentials through approved channels (AWS Secrets Manager rotation, not ad hoc).
5. Update `splunk/lookups/trusted_ips.csv` if the investigation revealed a legitimate IP that was not previously listed. Do this only after full confirmation that the IP is genuinely trusted.

---

## 3. Hardening Steps to Prevent Recurrence

Implement the following controls. Prioritize by order listed.

### 3a. Enforce Hardware MFA on Root (Immediate)

- Replace any virtual MFA with a hardware token (e.g., YubiKey).
- Store the hardware MFA device in a physically secured location with dual-person access.
- Document the device location and custodians in the secrets vault.

### 3b. Delete Root Access Keys (Permanent Policy)

Root access keys should never exist in a production account:

```bash
# Confirm deletion and add to account baseline check
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
```

Add this check to your automated compliance scanning (AWS Config rule: `root-account-hardware-mfa-enabled`, `iam-root-access-key-check`).

### 3c. Enable AWS Config Rules for Root

```bash
# Deploy via AWS Config (console or CloudFormation):
# - root-account-mfa-enabled
# - root-account-hardware-mfa-enabled
# - iam-root-access-key-check
```

These rules will alert continuously if the root account configuration drifts from the secure baseline.

### 3d. Apply SCP to Block Root API Calls Organization-Wide

If not done during containment, apply the SCP from `containment.md` Step 7 to all member accounts in AWS Organizations. Test in a non-production OU first.

### 3e. Secure the Root Account Email Address

- Change the root account email to a shared team mailbox (not a personal address).
- Enable MFA on the email provider.
- Implement email forwarding rules to alert the security team on any AWS account emails (password reset, MFA change, billing alerts).

### 3f. Rotate All Privileged IAM Credentials

For any IAM user or role that may have been observed or accessed during the incident:

```bash
# For each IAM user with admin-level access:
aws iam list-access-keys --user-name <ADMIN_USER>
aws iam create-access-key --user-name <ADMIN_USER>
# Update all consumers with the new key, then delete the old key
aws iam delete-access-key --user-name <ADMIN_USER> --access-key-id <OLD_KEYID>
```

### 3g. Enable GuardDuty Root Activity Finding

Confirm that GuardDuty is enabled in all regions and that the `Policy:IAMUser/RootCredentialUsage` finding type is active and routed to your SIEM:

```bash
aws guardduty list-detectors
aws guardduty get-detector --detector-id <DETECTOR_ID> \
  --query 'Status'
```

---

## 4. Detection Tuning Recommendations (CDET-006)

### Suppression (Use Sparingly)

Only suppress if ALL of the following are true:
- The Root activity is from a known, approved automation pipeline.
- The source IP is documented in `splunk/lookups/trusted_ips.csv`.
- The action is read-only (e.g., `GetAccountSummary`, `ListBuckets`).
- MFA is used.

Add the suppression as a lookup-based filter in the Splunk detection rule, not as a blanket exclusion. Log all suppressions and review them quarterly.

### Enrichment (Preferred Over Suppression)

Enrich the CDET-006 alert with:
- **IP geolocation** — add country and ASN to alert context automatically.
- **Account classification** — join with `splunk/lookups/aws_account_inventory.csv` to surface account type (prod/dev).
- **Previous Root activity baseline** — calculate days since last Root login; surface in alert if > 90 days (anomalous).
- **MFA status at time of event** — pull from `additionalEventData.MFAUsed` and flag prominently if `No`.

### Alert Tuning SPL Example

```spl
index=aws_cloudtrail userIdentity.type=Root
| lookup trusted_ips.csv sourceIPAddress AS sourceIPAddress OUTPUT is_trusted, actor_name
| lookup aws_account_inventory.csv recipientAccountId AS recipientAccountId OUTPUT account_type, account_name
| eval is_read_only=if(match(eventName,"^(Get|List|Describe|Head)"), "true", "false")
| eval mfa_used='additionalEventData.MFAUsed'
| eval suppress=if(is_trusted="true" AND is_read_only="true" AND mfa_used="Yes" AND account_type!="production", "true", "false")
| where suppress!="true"
| eval alert_severity=case(
    mfa_used="No" AND match(eventName,"ConsoleLogin"), "CRITICAL",
    match(eventName,"CreateAccessKey|CreateUser|AttachUserPolicy|DeleteTrail"), "CRITICAL",
    account_type="production", "HIGH",
    true(), "MEDIUM"
  )
| table _time, alert_severity, recipientAccountId, account_name, eventName,
         sourceIPAddress, mfa_used, actor_name, awsRegion
```

---

## 5. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Full incident timeline documented in the ticket with all `eventID` references (CDET-006 reference included).
- [ ] Root cause identified: how did the adversary obtain root credentials? (phishing, credential exposure, weak password, no MFA)
- [ ] All adversary-created IAM entities confirmed deleted or permanently disabled.
- [ ] CloudTrail integrity verified across all regions; log gaps identified and documented.
- [ ] AWS Config compliance report run post-containment; all root-related rules show COMPLIANT.
- [ ] Hardening steps from Section 3 completed and tracked to closure.
- [ ] Detection tuning changes (Section 4) implemented and tested in Splunk.
- [ ] `splunk/lookups/trusted_ips.csv` reviewed and updated if applicable.
- [ ] `splunk/lookups/aws_account_inventory.csv` reviewed for accuracy.
- [ ] Stakeholder notification sent (internal and, if required, to customers or regulators).
- [ ] Lessons learned documented; recurring action items assigned to owners.
- [ ] Tabletop exercise scheduled if root account process gaps were identified.
- [ ] CDET-006 playbook reviewed for accuracy based on this incident; update `last_updated` date if changes are made.
