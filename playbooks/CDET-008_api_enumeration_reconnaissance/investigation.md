---
detection_id: CDET-008
detection_name: API Enumeration Reconnaissance
tactic: Discovery
technique: T1580
last_updated: 2026-06-18
---

# CDET-008 — API Enumeration Reconnaissance: Investigation

**Role: Tier-2 SOC Analyst**
**Prerequisites: Triage complete, incident ticket open**

---

## 1. Understand What T1580 Looks Like

MITRE T1580 (Cloud Infrastructure Discovery) covers adversaries calling cloud provider APIs to map out the target environment before moving to exploitation or privilege escalation. In AWS, this manifests as:

- Rapid sequential calls to `Describe*`, `List*`, `Get*` across multiple services (EC2, IAM, S3, Lambda, RDS, SSM, SecretsManager, etc.)
- Low error rate initially (attacker uses valid credentials), with `AccessDenied` errors appearing as they probe the permission boundary
- Cross-service pivoting: start with `iam:ListRoles` → `iam:GetRolePolicy` → `s3:ListBuckets` → `ec2:DescribeInstances`
- Use of automated tooling (Pacu, ScoutSuite, enumerate-iam) produces highly regular inter-event timing

A genuine attack chain typically follows this pattern:
1. **Identity discovery:** `iam:GetCallerIdentity`, `iam:ListUsers`, `iam:ListRoles`
2. **Permission enumeration:** `iam:ListAttachedUserPolicies`, `iam:ListRolePolicies`, `iam:GetPolicy`, `iam:SimulatePrincipalPolicy`
3. **Resource inventory:** `ec2:DescribeInstances`, `s3:ListBuckets`, `lambda:ListFunctions`, `rds:DescribeDBInstances`
4. **Secrets/config hunting:** `ssm:DescribeParameters`, `secretsmanager:ListSecrets`, `secretsmanager:GetSecretValue`
5. **Network mapping:** `ec2:DescribeVpcs`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSubnets`

---

## 2. CloudTrail Event Fields to Examine

For every event associated with CDET-008, capture and analyze:

| Field | Significance |
|---|---|
| `eventTime` | Build the timeline; look for sub-second inter-event timing (tool automation) |
| `eventSource` | Which AWS service; track unique count across the session |
| `eventName` | Specific API call; group by prefix (Describe/List/Get) |
| `userIdentity.arn` | Full actor identity |
| `userIdentity.accessKeyId` | Key ID; check if recently created or rotated |
| `userIdentity.sessionContext.creationDate` | When the session/role was assumed |
| `sourceIPAddress` | Origin; resolve to ASN and geolocation |
| `userAgent` | SDK/tool identifier |
| `requestParameters` | Specific resource targets (bucket names, role names, etc.) |
| `responseElements` | What was returned (present on successful calls) |
| `errorCode` | `AccessDenied` indicates permission probing |
| `errorMessage` | Detailed denial reason |
| `awsRegion` | Single vs. multi-region activity increases severity |
| `resources` | Resource ARNs affected |

---

## 3. Splunk SPL Investigation Queries

All queries use `index=aws_cloudtrail`. Replace `<ACTOR_ARN>` with the ARN from triage.

### 3a. Full Activity Timeline for the Actor (Last 24 Hours)

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    earliest=-24h latest=now
| table _time, eventSource, eventName, sourceIPAddress, userAgent, errorCode, awsRegion
| sort _time
```

### 3b. Enumerate API Call Spread Across Services

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    eventName IN ("Describe*","List*","Get*")
    earliest=-24h
| stats count by eventSource, eventName
| sort -count
```

### 3c. Identify Access Denied Errors (Permission Probing)

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    errorCode="AccessDenied"
    earliest=-24h
| table _time, eventSource, eventName, requestParameters, errorMessage
| sort _time
```

### 3d. Detect Tool-Like Timing (Sub-Second Bursts)

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    eventName IN ("Describe*","List*","Get*")
    earliest=-24h
| streamstats current=f last(_time) as prev_time by userIdentity.arn
| eval inter_event_sec = _time - prev_time
| where inter_event_sec < 1
| table _time, inter_event_sec, eventSource, eventName
```

### 3e. Multi-Region Activity Check

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    earliest=-24h
| stats dc(awsRegion) as region_count, values(awsRegion) as regions by userIdentity.arn
| where region_count > 2
```

### 3f. Secrets and Parameter Store Access

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    eventSource IN ("secretsmanager.amazonaws.com","ssm.amazonaws.com","kms.amazonaws.com")
    earliest=-24h
| table _time, eventSource, eventName, requestParameters, errorCode
| sort _time
```

### 3g. Correlate with Other Principals from Same Source IP

```splunk
index=aws_cloudtrail sourceIPAddress="<SOURCE_IP>"
    earliest=-24h
| stats dc(userIdentity.arn) as unique_arns, values(userIdentity.arn) as arns by sourceIPAddress
| where unique_arns > 1
```

### 3h. Check for Subsequent Privilege Escalation Attempts

```splunk
index=aws_cloudtrail userIdentity.arn="<ACTOR_ARN>"
    eventName IN ("CreateAccessKey","AttachUserPolicy","AttachRolePolicy","PutUserPolicy",
                  "PutRolePolicy","CreateLoginProfile","UpdateLoginProfile","AddUserToGroup",
                  "PassRole","AssumeRole")
    earliest=-24h
| table _time, eventName, requestParameters, errorCode
| sort _time
```

---

## 4. IAM and Resource Context via AWS CLI

Use the boto3 default credential chain (`aws configure` profile). Do NOT hardcode credentials.

### 4a. Identify What the Actor's Credentials Can Actually Do

```bash
# Get caller identity to confirm the role/user in question
aws sts get-caller-identity --profile <investigation-profile>

# List policies attached to the suspicious IAM user
aws iam list-attached-user-policies \
    --user-name <USERNAME> \
    --profile <investigation-profile>

# List policies attached to the suspicious role
aws iam list-attached-role-policies \
    --role-name <ROLENAME> \
    --profile <investigation-profile>

# Get inline policies
aws iam list-user-policies --user-name <USERNAME> --profile <investigation-profile>
aws iam list-role-policies --role-name <ROLENAME> --profile <investigation-profile>
```

### 4b. Check Access Key Age and Status

```bash
aws iam list-access-keys \
    --user-name <USERNAME> \
    --profile <investigation-profile>
# Note: CreateDate, Status (Active/Inactive), LastUsedDate
```

### 4c. Check CloudTrail for Key Last Use

```bash
aws iam get-access-key-last-used \
    --access-key-id <KEY_ID> \
    --profile <investigation-profile>
```

### 4d. Enumerate Active Sessions for the Role

```bash
# List recent role assumption events
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time $(date -d '24 hours ago' --utc +%Y-%m-%dT%H:%M:%SZ) \
    --profile <investigation-profile> \
    | jq '.Events[] | select(.CloudTrailEvent | fromjson | .requestParameters.roleArn | contains("<ROLE_ARN>"))'
```

### 4e. Identify Resources Enumerated

```bash
# Check what S3 buckets were listed
aws s3api list-buckets --profile <investigation-profile>

# Check EC2 instances visible to this role's region
aws ec2 describe-instances \
    --region <REGION> \
    --profile <investigation-profile> \
    --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags]'
```

---

## 5. Evidence to Collect and Preserve

Before any containment action, document and preserve:

- [ ] Full actor ARN, access key ID, and session token (if assumed role)
- [ ] Source IP address(es) — capture all unique IPs used during the session
- [ ] Complete list of event IDs (`eventID` field) from all CDET-008 triggering events
- [ ] Timestamps of first and last observed event in the session
- [ ] Full `requestParameters` for any `GetSecretValue`, `GetParameter`, or `GetObject` calls (data accessed)
- [ ] `userAgent` string verbatim
- [ ] All `errorCode: AccessDenied` events with their `errorMessage`
- [ ] Screenshot or export of Splunk dashboard for the investigation period
- [ ] CloudTrail S3 export of raw logs for the affected time window and account (for chain-of-custody)

Export raw CloudTrail events to preserve evidence:

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME_OR_ROLE> \
    --start-time <FIRST_EVENT_TIME> \
    --end-time <LAST_EVENT_TIME> \
    --profile <investigation-profile> \
    --output json > cdet008_evidence_$(date +%Y%m%d_%H%M%S).json
```

---

## 6. Timeline Reconstruction Approach

1. **Anchor point:** Identify the earliest event in the session using `eventTime` sorted ascending.
2. **Session boundary:** Group by `userIdentity.accessKeyId` + `userIdentity.sessionContext.creationDate` to isolate a single credential session.
3. **Phase mapping:** Label events by phase (identity discovery, IAM enumeration, resource inventory, secrets access) using the T1580 pattern from Section 1.
4. **Gap analysis:** Note any gaps > 5 minutes in the timeline — may indicate manual review pauses or tool waiting on throttling.
5. **Pivots:** Check if any `AssumeRole` events occurred after the enumeration, indicating lateral movement from recon to execution.
6. **Data exposure assessment:** For each successful `GetSecretValue`, `GetParameter`, `GetObject`, or `DescribeSecret` call, determine what data was returned and its sensitivity classification.
7. **Parallel sessions:** Re-run queries scoped to the source IP (not just the ARN) to detect if multiple credentials were in use simultaneously from the same host.
