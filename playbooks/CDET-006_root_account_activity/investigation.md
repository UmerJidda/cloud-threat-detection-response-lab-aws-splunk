---
detection_id: CDET-006
detection_name: Root Account Activity Detected
tactic: Initial Access
technique: T1078.004
last_updated: 2026-06-18
---

# CDET-006 — Root Account Activity Detected: Investigation

> **Audience:** Tier-2 SOC analyst with AWS experience.
> **Prerequisites:** Triage complete; alert classified as a real event (FAIL criteria met).

---

## 1. Understand the Attack Pattern for T1078.004

**Valid Accounts: Cloud Accounts (T1078.004)** — adversaries obtain and abuse existing cloud credentials, including the AWS root account, to maintain persistence and escalate privileges. The root account bypasses all IAM permission boundaries and SCPs. A typical attack chain:

```
Credential theft / phishing root email
  → Root console login (no MFA)
    → Create new IAM access key for root (or new admin user)
      → Establish persistent backdoor (new user, role, or OIDC provider)
        → Disable logging / delete CloudTrail trails
          → Exfiltrate data or deploy resources
```

Key indicators of a full attack chain:
- `ConsoleLogin` followed quickly by `CreateAccessKey`.
- `CreateUser` + `AttachUserPolicy` (AdministratorAccess) by Root.
- `DeleteTrail` or `StopLogging` — evidence tampering.
- `CreateVirtualMFADevice` / `EnableMFADevice` for new accounts.
- Cross-region activity (adversary exploring all regions).
- `AssumeRole` with newly created role immediately after root session.

---

## 2. Collect the Triggering Event

1. Pull the full raw JSON for the triggering CloudTrail event.
2. Preserve it as evidence immediately (copy to ticket or evidence store).
3. Record:
   - `eventID` — unique identifier; include in all evidence references.
   - `eventTime` (UTC).
   - `requestID`.
   - `sourceIPAddress` and `userAgent`.
   - `requestParameters` and `responseElements` in full.

---

## 3. CloudTrail Fields to Examine (CDET-006 Specific)

| Field | What to Look For |
|---|---|
| `userIdentity.type` | Must be `Root` to be in scope |
| `userIdentity.accountId` | Confirm this is the expected production account |
| `eventSource` | `signin.amazonaws.com` = console; `iam.amazonaws.com` = API |
| `eventName` | See sensitive event list below |
| `sourceIPAddress` | Geo-lookup; compare to prior Root login history |
| `userAgent` | `signin.amazonaws.com` = console; raw CLI/SDK strings = API key used |
| `additionalEventData.MFAUsed` | `No` = critical finding |
| `additionalEventData.LoginTo` | Destination URL if console login |
| `errorCode` + `errorMessage` | `AuthFailure` = failed attempt (could indicate brute force) |
| `requestParameters` | Key material requested; policy docs attached |
| `responseElements` | Contains new `AccessKeyId` if key was created |
| `tlsDetails.tlsVersion` | Outdated TLS may indicate legacy client |

**High-sensitivity `eventName` values for Root:**

```
ConsoleLogin
CreateAccessKey
DeleteAccessKey
UpdateAccessKey
CreateVirtualMFADevice
DeactivateMFADevice
DeleteVirtualMFADevice
CreateUser
AttachUserPolicy
PutUserPolicy
CreateRole
AttachRolePolicy
CreateLoginProfile
UpdateLoginProfile
DeleteTrail
StopLogging
UpdateTrail
PutBucketPolicy (on CloudTrail S3 bucket)
DeleteAccountPasswordPolicy
UpdateAccountPasswordPolicy
```

---

## 4. Splunk SPL Pivot Queries

All queries use `index=aws_cloudtrail`. Adjust `earliest`/`latest` to bracket the incident window.

### 4a. Full Root Session Timeline

```spl
index=aws_cloudtrail userIdentity.type=Root
  earliest=-24h latest=now
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table event_time, recipientAccountId, awsRegion, eventSource, eventName,
         sourceIPAddress, userAgent, errorCode, requestParameters, responseElements,
         additionalEventData.MFAUsed, eventID
| sort +_time
```

### 4b. Sensitive Actions Only (High-Signal)

```spl
index=aws_cloudtrail userIdentity.type=Root
  eventName IN (
    "ConsoleLogin","CreateAccessKey","DeleteAccessKey","CreateUser",
    "AttachUserPolicy","PutUserPolicy","CreateRole","AttachRolePolicy",
    "DeleteTrail","StopLogging","UpdateTrail","DeactivateMFADevice",
    "CreateLoginProfile","DeleteAccountPasswordPolicy"
  )
  earliest=-7d latest=now
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table event_time, recipientAccountId, awsRegion, eventName, sourceIPAddress,
         userAgent, errorCode, additionalEventData.MFAUsed, eventID
| sort +_time
```

### 4c. Activity by Source IP (Pivot on Attacker IP)

Replace `<ATTACKER_IP>` with the IP from the triggering event:

```spl
index=aws_cloudtrail sourceIPAddress="<ATTACKER_IP>"
  earliest=-7d latest=now
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| stats count by event_time, userIdentity.type, userIdentity.arn, eventName,
         recipientAccountId, awsRegion, errorCode
| sort +event_time
```

### 4d. Post-Root New IAM Entities (Persistence Check)

Look for IAM entities created shortly after the Root event:

```spl
index=aws_cloudtrail
  eventName IN ("CreateUser","CreateRole","CreateGroup","CreateAccessKey","CreateLoginProfile")
  earliest=-24h latest=now
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table event_time, userIdentity.type, userIdentity.arn, eventName,
         requestParameters, responseElements, sourceIPAddress, recipientAccountId
| sort +_time
```

### 4e. Logging Tampering (Evidence Destruction Check)

```spl
index=aws_cloudtrail
  eventName IN ("DeleteTrail","StopLogging","UpdateTrail","PutBucketPolicy",
                "DeleteBucket","PutBucketAcl","DeleteBucketPolicy")
  earliest=-24h latest=now
| eval event_time=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
| table event_time, userIdentity.type, userIdentity.arn, eventName,
         awsRegion, sourceIPAddress, requestParameters, errorCode
| sort +_time
```

### 4f. Cross-Region Activity Check

```spl
index=aws_cloudtrail userIdentity.type=Root
  earliest=-24h latest=now
| stats count by awsRegion, eventName
| sort -count
```

---

## 5. IAM and Resource Context (AWS CLI)

Use the boto3 default credential chain (`aws configure` / environment / instance profile). Do NOT hardcode credentials.

### 5a. Check Current Root Access Keys

```bash
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
```

A value of `1` means a root access key exists — this should normally be `0`.

### 5b. List All Access Keys on the Account (Including Root)

```bash
# Root access keys are not listed per IAM user; check via:
aws iam list-access-keys
# If this returns keys for root, note AccessKeyId and Status
```

### 5c. Check Account Password Policy

```bash
aws iam get-account-password-policy
```

Note whether it was recently changed (`UpdateAccountPasswordPolicy` in CloudTrail).

### 5d. List Recent IAM Users Created

```bash
aws iam list-users \
  --query 'Users[?CreateDate>=`2026-06-11`].[UserName,UserId,CreateDate,Arn]' \
  --output table
```

Adjust the date to 7 days before the incident.

### 5e. List Admin-Level Policies Attached to Suspicious Users

Replace `<USERNAME>` with any user found in step 5d:

```bash
aws iam list-attached-user-policies --user-name <USERNAME>
aws iam list-user-policies --user-name <USERNAME>
aws iam list-groups-for-user --user-name <USERNAME>
```

### 5f. Check MFA Status for Root

```bash
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```

`0` = MFA disabled on root — critical finding.

### 5g. Enumerate CloudTrail Status (Detect Tampering)

```bash
aws cloudtrail describe-trails --include-shadow-trails
aws cloudtrail get-trail-status --name <TRAIL_NAME>
```

### 5h. List Active Sessions / Roles Assumed

```bash
# Check for unusual role sessions created around the incident time via CloudTrail:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "2026-06-17T00:00:00Z" \
  --end-time "2026-06-19T00:00:00Z" \
  --query 'Events[*].CloudTrailEvent' \
  --output text | python3 -m json.tool
```

---

## 6. Evidence to Collect and Preserve

For each finding, record the following in the incident ticket:

| Evidence Item | Where to Find | Format |
|---|---|---|
| Triggering event full JSON | CloudTrail / Splunk | Raw JSON |
| `eventID` of each sensitive action | CloudTrail event field | String |
| Source IP(s) and geolocation | Alert + IP lookup service | IP, country, ASN |
| User agent string(s) | CloudTrail `userAgent` field | String |
| New `AccessKeyId` (if created) | `responseElements` | String — do NOT log secret |
| New IAM users/roles created | IAM API + CloudTrail | ARNs, creation times |
| Policies attached | IAM API | Policy ARNs and documents |
| CloudTrail trail integrity status | `get-trail-status` | JSON output |
| S3 log bucket ACL/policy (if changed) | S3 API | JSON policy document |
| Timeline of all Root events in window | Splunk query 4a | CSV export |

Export Splunk query results as CSV and attach to the ticket. Do not rely solely on SIEM data — retrieve raw CloudTrail JSON from the S3 bucket as an independent source.

---

## 7. Timeline Reconstruction

1. Identify the earliest Root event in the investigation window (query 4a).
2. Anchor T=0 to the first suspicious event (e.g., `ConsoleLogin`).
3. For each subsequent event, calculate delta from T=0.
4. Map events to the attack chain phases:

```
T=0       ConsoleLogin (Root, no MFA, foreign IP)
T+2m      GetAccountSummary (reconnaissance)
T+5m      CreateAccessKey (persistence — new key for Root)
T+7m      CreateUser "backup-admin" (secondary persistence)
T+8m      AttachUserPolicy "backup-admin" + AdministratorAccess
T+10m     StopLogging (evidence tampering)
T+12m     ListBuckets (data discovery)
```

5. Note any gaps in the timeline that could indicate activity in uncovered regions or services (e.g., if CloudTrail is not enabled in all regions).
6. Record final timeline in the ticket with all `eventID` references.
