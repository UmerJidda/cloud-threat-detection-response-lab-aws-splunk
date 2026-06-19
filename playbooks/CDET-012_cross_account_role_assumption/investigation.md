---
detection_id: CDET-012
detection_name: Cross-Account Role Assumption
tactic: Lateral Movement
technique: T1550.001
last_updated: 2026-06-18
---

# CDET-012 — Investigation Playbook
**Cross-Account Role Assumption**

> **Audience:** Tier-2 SOC Analyst with AWS and Splunk access
> **Prerequisites:** Triage complete; alert assessed as FAIL (real alert). Incident ticket open.

---

## 1. Understand the Technique

**T1550.001 — Use Alternate Authentication Material: Application Access Token (STS AssumeRole)**

In a cross-account role assumption attack, an adversary who has compromised credentials in Account A calls `sts:AssumeRole` to obtain temporary credentials (access key ID, secret access key, session token) scoped to a role in Account B. The trust policy on the target role is the gate; if it was misconfigured or intentionally backdoored (see CDET-005), the assumption succeeds. The adversary then operates in Account B using those temporary credentials, making forensics harder because CloudTrail events in Account B will show the assumed-role session ARN — not the original compromised identity.

A full attack chain typically looks like:

1. Initial access or credential theft in Account A (IAM user or role credential).
2. Reconnaissance: `sts:GetCallerIdentity`, `iam:ListRoles`, `iam:GetRole` calls in Account A.
3. Discovery of a cross-account role whose trust policy permits the compromised principal.
4. `sts:AssumeRole` call from Account A targeting the role in Account B — this is the CDET-012 trigger.
5. Actions in Account B using the temporary session: data access, privilege escalation, persistence (new IAM user, backdoor role, etc.).
6. Possible chaining: from Account B, the adversary assumes another role in Account C.

---

## 2. Key CloudTrail Event Fields to Examine

For the triggering `AssumeRole` event, extract and document:

| Field path | Significance |
|---|---|
| `userIdentity.arn` | Original caller — the compromised principal |
| `userIdentity.accountId` | Source account |
| `userIdentity.sessionContext.sessionIssuer.arn` | If caller is itself an assumed role, this is the original role |
| `userIdentity.sessionContext.attributes.creationDate` | When the caller's own session was issued — a very recent session could mean fresh credential theft |
| `requestParameters.roleArn` | Destination role — confirms which account and role were targeted |
| `requestParameters.roleSessionName` | Attacker-chosen; random strings or impersonation names (e.g., `s3access`, `lambda-exec`) are IOCs |
| `requestParameters.durationSeconds` | Requested session lifetime; maximum value (3600–43200) suggests attacker wants long-lived creds |
| `requestParameters.externalId` | If absent when the role trust policy requires one, the assumption should have failed — investigate why it succeeded |
| `responseElements.assumedRoleUser.arn` | Full ARN of the resulting session (`arn:aws:sts::<accountB>:assumed-role/<role>/<sessionName>`) |
| `responseElements.credentials.expiration` | When the temporary credentials expire |
| `sourceIPAddress` | Must be correlated with caller infrastructure |
| `userAgent` | `aws-cli`, `Boto3`, `curl` without a recognised SDK pattern are all worth noting |
| `eventTime` | Anchor for timeline reconstruction |

---

## 3. Splunk SPL Investigation Queries

Replace `<CALLER_ARN>`, `<TARGET_ROLE_ARN>`, `<SOURCE_ACCOUNT>`, `<DEST_ACCOUNT>`, and `<SESSION_ARN>` with values from the alert.

### 3a. Confirm the triggering event and retrieve full context

```spl
index=aws_cloudtrail eventName=AssumeRole
  requestParameters.roleArn="<TARGET_ROLE_ARN>"
  earliest=-2h latest=+15m
| table eventTime, userIdentity.arn, userIdentity.accountId,
        requestParameters.roleArn, requestParameters.roleSessionName,
        requestParameters.durationSeconds,
        responseElements.assumedRoleUser.arn,
        sourceIPAddress, userAgent, errorCode
| sort eventTime
```

### 3b. Find all AssumeRole attempts by the caller in the last 24 hours (role enumeration / chaining)

```spl
index=aws_cloudtrail eventName=AssumeRole
  userIdentity.arn="<CALLER_ARN>"
  earliest=-24h latest=now
| stats count BY requestParameters.roleArn, errorCode, eventTime
| sort eventTime
```

Look for a burst of `AccessDenied` results followed by a success — this is classic role enumeration.

### 3c. Pre-assumption reconnaissance in the source account

```spl
index=aws_cloudtrail userIdentity.arn="<CALLER_ARN>"
  earliest=-2h latest=now
  eventName IN (GetCallerIdentity, ListRoles, GetRole, ListPolicies,
                GetPolicy, ListAttachedRolePolicies, ListUsers,
                ListBuckets, DescribeInstances, ListFunctions)
| table eventTime, eventName, requestParameters, sourceIPAddress
| sort eventTime
```

### 3d. Activity in the destination account using the assumed-role session

This query must be run against CloudTrail data **from Account B**. If both accounts ship to the same Splunk index, filter by `recipientAccountId`:

```spl
index=aws_cloudtrail recipientAccountId="<DEST_ACCOUNT>"
  userIdentity.arn="<SESSION_ARN>"
  earliest=-24h latest=now
| table eventTime, eventName, requestParameters, responseElements,
        sourceIPAddress, userAgent, errorCode
| sort eventTime
```

### 3e. Detect chaining — further AssumeRole calls from the destination-account session

```spl
index=aws_cloudtrail eventName=AssumeRole
  userIdentity.arn="<SESSION_ARN>"
  earliest=-24h latest=now
| table eventTime, requestParameters.roleArn, requestParameters.roleSessionName,
        responseElements.assumedRoleUser.arn, sourceIPAddress, errorCode
| sort eventTime
```

### 3f. Identify all accounts involved across a full role-chaining path

```spl
index=aws_cloudtrail eventName=AssumeRole
  sourceIPAddress="<SOURCE_IP>"
  earliest=-24h latest=now
| table eventTime, userIdentity.accountId, recipientAccountId,
        userIdentity.arn, requestParameters.roleArn,
        requestParameters.roleSessionName, errorCode
| sort eventTime
```

### 3g. Assess blast radius — what did the assumed session touch?

```spl
index=aws_cloudtrail recipientAccountId="<DEST_ACCOUNT>"
  userIdentity.sessionContext.sessionIssuer.arn="<TARGET_ROLE_ARN>"
  earliest=-24h latest=now
| stats count BY eventName, errorCode
| sort - count
```

---

## 4. IAM and Resource Context — AWS CLI Commands

All commands use the boto3/AWS CLI default credential chain (`aws configure` profile). Do **not** hardcode credentials.

### 4a. Inspect the target role's trust policy

```bash
aws iam get-role \
  --role-name <ROLE_NAME_FROM_ARN> \
  --profile <ACCOUNT_B_PROFILE> \
  --output json
```

Look at `AssumeRolePolicyDocument`. Check:
- Which principals are trusted (`Principal.AWS`, `Principal.Service`, `Principal.Federated`).
- Whether `sts:ExternalId` condition is present and enforced.
- Whether `aws:PrincipalOrgID` restricts the trust to your organisation.
- Any wildcard (`*`) in the principal — this is a critical misconfiguration.

### 4b. List permissions attached to the target role

```bash
aws iam list-attached-role-policies \
  --role-name <ROLE_NAME_FROM_ARN> \
  --profile <ACCOUNT_B_PROFILE> \
  --output json

aws iam list-role-policies \
  --role-name <ROLE_NAME_FROM_ARN> \
  --profile <ACCOUNT_B_PROFILE> \
  --output json
```

### 4c. Retrieve the inline policy content

```bash
aws iam get-role-policy \
  --role-name <ROLE_NAME_FROM_ARN> \
  --policy-name <POLICY_NAME> \
  --profile <ACCOUNT_B_PROFILE> \
  --output json
```

### 4d. Determine when the trust policy was last modified

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy \
  --start-time "2026-01-01T00:00:00Z" \
  --profile <ACCOUNT_B_PROFILE> \
  --output json | python -m json.tool
```

### 4e. Check for active sessions using the assumed role

```bash
# List recent access advisor data for the role (shows last service use)
aws iam generate-service-last-accessed-details \
  --arn <TARGET_ROLE_ARN> \
  --profile <ACCOUNT_B_PROFILE> \
  --output json
```

Then poll:

```bash
aws iam get-service-last-accessed-details \
  --job-id <JOB_ID_FROM_ABOVE> \
  --profile <ACCOUNT_B_PROFILE> \
  --output json
```

### 4f. Identify any new IAM resources created by the session in Account B

```bash
aws iam list-users \
  --profile <ACCOUNT_B_PROFILE> \
  --output json | python -m json.tool

aws iam list-roles \
  --profile <ACCOUNT_B_PROFILE> \
  --output json | python -m json.tool
```

Sort by `CreateDate` and flag any resources created after the `AssumeRole` event time.

---

## 5. Evidence to Collect and Preserve

Record the following before taking any containment actions:

1. **Full CloudTrail event JSON** for the triggering `AssumeRole` event — copy raw JSON from Splunk or from the CloudTrail console.
2. **`eventID`** (CloudTrail's unique event identifier) for the triggering event and all pivot events.
3. **All event timestamps (UTC)** for the attacker's activity timeline.
4. **Source IP address** and any additional IPs observed in subsequent activity.
5. **`requestParameters.roleSessionName`** — this string appears in all subsequent CloudTrail events from Account B and is your key pivot field.
6. **`responseElements.assumedRoleUser.arn`** — the session ARN used in Account B.
7. **`responseElements.credentials.expiration`** — note when temporary credentials expire so you know the containment window.
8. **Output of `aws iam get-role`** for the target role (trust policy snapshot).
9. **Full list of actions performed in Account B** during the session (from query 3d above) — export to CSV.
10. **Screenshot or JSON export** of any new IAM users, roles, access keys, or policies created in Account B.

Store all evidence in the incident ticket with timestamps. Do not modify any IAM resources until evidence is captured.

---

## 6. Timeline Reconstruction

Build a chronological event list with the following columns:

| Time (UTC) | Account | Event | Principal / Session | Source IP | Notes |
|---|---|---|---|---|---|

Populate it in this order:

1. First event by the compromised principal (earliest Splunk hit from query 3c).
2. Reconnaissance events (`ListRoles`, `GetCallerIdentity`, etc.).
3. Failed `AssumeRole` attempts (if any — query 3b, `errorCode=AccessDenied`).
4. Successful `AssumeRole` — the CDET-012 trigger event.
5. All actions taken in Account B under the assumed session (query 3d).
6. Any further role-chaining events (query 3e).
7. Last observed event from the attacker's session.

The timeline informs both the blast-radius assessment and the scope of IAM cleanup required in containment.
