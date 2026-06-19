---
detection_id: CDET-005
detection_name: Cross-Account Trust Modified
tactic: Privilege Escalation
technique: T1484.002
last_updated: 2026-06-18
---

# CDET-005 — Cross-Account Trust Modified: Investigation Playbook

**Audience:** Tier-2 SOC Analyst  
**Prerequisite:** Triage determined this is a real alert (PASS criteria met).  
**Goal:** Reconstruct the full attack chain, gather evidence, and determine blast radius.

---

## 1 — Understanding T1484.002 in the AWS Context

In T1484.002 (Domain Policy Modification: Trust Modification), an adversary modifies an IAM role's trust policy (`AssumeRolePolicy`) to add a new principal — typically an account or role they control in a separate AWS account. This allows them to call `sts:AssumeRole` from their controlled account and obtain credentials with the permissions of the modified role, without needing any credentials in the victim account beyond the initial write access to IAM.

**Typical attack chain:**

1. Adversary compromises an IAM principal with `iam:UpdateAssumeRolePolicy` permission (e.g., via stolen access key, SSRF metadata credential theft, or a misconfigured Lambda execution role).
2. Adversary modifies the trust policy of a high-privilege role (e.g., a role with `AdministratorAccess`) to add their external account or role as a trusted principal.
3. From their own account, adversary calls `sts:AssumeRole` targeting the victim role — this generates a new `AssumeRole` CloudTrail event in the victim account.
4. Adversary uses the assumed-role session to perform actions (data exfiltration, persistence, lateral movement) that appear to originate from the legitimate victim role.

---

## 2 — CloudTrail Fields to Examine

For the triggering `UpdateAssumeRolePolicy` event, capture and analyze:

| Field | What to Look For |
|---|---|
| `userIdentity.arn` | Is this a known admin? Is it a role session (AssumedRole) — if so, trace the parent role |
| `userIdentity.sessionContext.sessionIssuer.arn` | For assumed-role callers: what role issued the session? |
| `userIdentity.accessKeyId` | Note for cross-referencing with prior events |
| `requestParameters.roleName` | The role whose trust was modified — check its attached policies |
| `requestParameters.policyDocument` | Decode the JSON; examine `Statement[].Principal` for new external principals |
| `sourceIPAddress` | Geolocation, ASN — is this an AWS datacenter, VPN, or residential IP? |
| `userAgent` | CLI version, SDK, Terraform? Automated vs. manual? |
| `eventTime` | Is this business hours in the actor's expected timezone? |
| `requestID` | Use for exact event correlation |
| `errorCode` / `errorMessage` | If absent, change succeeded |

---

## 3 — Splunk SPL Investigation Queries

All queries use `index=aws_cloudtrail`. Adjust time ranges as needed.

### 3a — Retrieve the full triggering event

```spl
index=aws_cloudtrail eventName=UpdateAssumeRolePolicy
    requestParameters.roleName="<ROLE_NAME_FROM_ALERT>"
| eval policy=urldecode('requestParameters.policyDocument')
| table _time, userIdentity.arn, userIdentity.accountId, requestParameters.roleName,
         policy, sourceIPAddress, userAgent, requestID, errorCode
| sort -_time
```

### 3b — Find all IAM actions by the same actor in the past 7 days

```spl
index=aws_cloudtrail eventSource=iam.amazonaws.com
    (userIdentity.arn="<ACTOR_ARN>" OR userIdentity.accessKeyId="<ACCESS_KEY_ID>")
    earliest=-7d
| table _time, eventName, requestParameters.roleName, requestParameters.userName,
         requestParameters.policyArn, sourceIPAddress, errorCode
| sort -_time
```

### 3c — Check if the modified role was subsequently assumed (cross-account AssumeRole)

```spl
index=aws_cloudtrail eventName=AssumeRole
    requestParameters.roleArn="arn:aws:iam::<VICTIM_ACCOUNT>:role/<ROLE_NAME>"
    earliest=<MODIFY_EVENT_TIME>
| table _time, userIdentity.arn, userIdentity.accountId, requestParameters.roleArn,
         requestParameters.roleSessionName, sourceIPAddress, userAgent
| sort -_time
```

### 3d — Actions taken under the assumed role session after trust modification

```spl
index=aws_cloudtrail
    userIdentity.sessionContext.sessionIssuer.arn="arn:aws:iam::<VICTIM_ACCOUNT>:role/<ROLE_NAME>"
    earliest=<ASSUME_ROLE_EVENT_TIME>
| table _time, eventName, eventSource, userIdentity.arn, userIdentity.accountId,
         sourceIPAddress, requestParameters, responseElements, errorCode
| sort -_time
```

### 3e — Detect reconnaissance preceding the modification (last 24h before alert)

```spl
index=aws_cloudtrail
    (userIdentity.arn="<ACTOR_ARN>" OR userIdentity.accessKeyId="<ACCESS_KEY_ID>")
    eventName IN ("GetRole","ListRoles","ListAttachedRolePolicies","GetPolicy",
                  "GetPolicyVersion","SimulatePrincipalPolicy","ListRolePolicies")
    earliest=-24h@h latest=<MODIFY_EVENT_TIME>
| table _time, eventName, requestParameters, sourceIPAddress
| sort -_time
```

### 3f — Enumerate all trust policy changes in the account (last 30 days)

```spl
index=aws_cloudtrail eventName=UpdateAssumeRolePolicy earliest=-30d
| stats count by userIdentity.arn, requestParameters.roleName, _time
| sort -_time
```

---

## 4 — AWS CLI / Boto3 Context Gathering

All commands use the boto3 default credential chain (`aws configure` / instance profile / environment). Do not hardcode credentials.

### 4a — Inspect the current trust policy of the modified role

```bash
aws iam get-role \
    --role-name "<ROLE_NAME>" \
    --query "Role.{Arn:Arn, TrustPolicy:AssumeRolePolicyDocument, Created:CreateDate}" \
    --output json
```

### 4b — List all policies attached to the modified role (assess blast radius)

```bash
aws iam list-attached-role-policies \
    --role-name "<ROLE_NAME>" \
    --output json

aws iam list-role-policies \
    --role-name "<ROLE_NAME>" \
    --output json
```

### 4c — Check inline policies for the modified role

```bash
aws iam get-role-policy \
    --role-name "<ROLE_NAME>" \
    --policy-name "<POLICY_NAME>" \
    --output json
```

### 4d — Inspect the actor's own permissions

```bash
# If actor is an IAM user
aws iam list-attached-user-policies --user-name "<USERNAME>"
aws iam list-user-policies --user-name "<USERNAME>"
aws iam list-groups-for-user --user-name "<USERNAME>"

# If actor is a role
aws iam list-attached-role-policies --role-name "<ACTOR_ROLE_NAME>"
```

### 4e — Pull CloudTrail event directly by requestID

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventId,AttributeValue="<REQUEST_ID>" \
    --output json
```

### 4f — Check for active sessions under the modified role

```bash
# List recent activity via CloudTrail (last 1 hour)
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue="<ROLE_NAME>" \
    --start-time "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --output json
```

---

## 5 — Evidence to Collect and Preserve

Capture and store the following before any containment actions:

- [ ] Full raw JSON of the `UpdateAssumeRolePolicy` CloudTrail event (include `requestID`, `eventTime`)
- [ ] Full raw JSON of any subsequent `AssumeRole` events referencing the modified role
- [ ] All CloudTrail events by the actor principal in the preceding 24 hours
- [ ] Output of `aws iam get-role` for the modified role (current trust policy)
- [ ] Output of `aws iam list-attached-role-policies` for the modified role
- [ ] Actor's IAM user/role policy summary
- [ ] Source IP geolocation and ASN lookup result
- [ ] Access key creation date for the actor's key (`aws iam list-access-keys`)
- [ ] Screenshot or JSON export of Splunk query results (queries 3a–3f above)

Store all evidence in the case management system with CDET-005 and the incident ID as tags.

---

## 6 — Timeline Reconstruction

Build a chronological timeline covering at least 72 hours before the triggering event:

1. **T-72h to T-24h:** Any initial access indicators — failed logins, unusual `GetCallerIdentity` calls, credential generation events (`CreateAccessKey`, `CreateLoginProfile`).
2. **T-24h to T-1h:** Reconnaissance phase — `GetRole`, `ListRoles`, `ListAttachedRolePolicies`, `SimulatePrincipalPolicy` calls by the actor.
3. **T-0:** The `UpdateAssumeRolePolicy` event itself.
4. **T+0 to T+present:** Any `AssumeRole` calls from the new trusted principal, and subsequent actions under the assumed session.

Use Splunk query 3b and 3e to populate T-72h through T-0. Use queries 3c and 3d for T+0 onward.

---

*Next step: proceed to `containment.md` once evidence is preserved and blast radius is understood.*
