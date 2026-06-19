---
detection_id: CDET-007
detection_name: EC2 Metadata Credential Abuse
tactic: Credential Access
technique: T1552.005
last_updated: 2026-06-18
---

# CDET-007 — EC2 Metadata Credential Abuse: Investigation

**Audience:** Tier-2 SOC analyst with AWS experience  
**Prerequisites:** Triage complete; alert confirmed FAIL (real alert)

---

## 1. Understand the Attack Chain for T1552.005

In this technique an adversary has gained code execution on (or network access to) an EC2 instance and queries the Instance Metadata Service (IMDS) to steal the temporary credentials attached to the instance's IAM role:

```
1. Attacker reaches EC2 (via RCE, SSRF, or direct network access)
2. GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
   → returns AccessKeyId, SecretAccessKey, Token, Expiration
3. Attacker calls sts:AssumeRole or makes direct API calls from an EXTERNAL IP
   using those stolen credentials
4. Reconnaissance: GetCallerIdentity, ListBuckets, DescribeInstances, ListRoles
5. Lateral movement / data exfiltration
```

The triggering event for CDET-007 is step 3: `AssumeRole` sourced from a non-EC2 IP using an EC2 instance role's credentials.

---

## 2. Identify the Affected EC2 Instance and Role

1. Extract the instance profile ARN from the triggering CloudTrail event:

```
userIdentity.sessionContext.sessionIssuer.arn
```

2. Map the instance profile to an EC2 instance ID:

```bash
# Find instance(s) using this profile
aws iam list-instance-profiles-for-role \
  --role-name <role-name-from-arn> \
  --query 'InstanceProfiles[*].InstanceProfileName'

aws ec2 describe-instances \
  --filters "Name=iam-instance-profile.arn,Values=<instance-profile-arn>" \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,LaunchTime:LaunchTime,SubnetId:SubnetId,VpcId:VpcId}' \
  --output table
```

3. Record: `InstanceId`, `PublicIpAddress`, `PrivateIpAddress`, `LaunchTime`, `SubnetId`, `VpcId`.

---

## 3. CloudTrail Fields to Examine for This Technique

For the triggering `AssumeRole` event, capture and preserve these fields:

| Field | Significance |
|---|---|
| `eventID` | Unique identifier — preserve for evidence |
| `eventTime` | Attack start timestamp (UTC) |
| `sourceIPAddress` | Attacker's exfiltration IP |
| `userAgent` | Tool used by attacker (e.g., `curl`, `Boto3`, custom) |
| `userIdentity.accessKeyId` | The stolen temporary access key |
| `userIdentity.sessionContext.sessionIssuer.arn` | The EC2 role that was abused |
| `requestParameters.roleArn` | Role the attacker tried to pivot to |
| `requestParameters.roleSessionName` | Session name chosen by attacker |
| `responseElements.credentials.accessKeyId` | Newly issued key from the pivot |
| `responseElements.credentials.expiration` | When the new credential expires |
| `tlsDetails.clientProvidedHostHeader` | May reveal proxied request |

---

## 4. Splunk SPL Pivot Queries

All queries use index `aws_cloudtrail`. Substitute `<stolen_access_key_id>` and `<attacker_ip>` from the triggering event.

### 4a. Find all API calls made with the stolen temporary credential

```spl
index=aws_cloudtrail userIdentity.accessKeyId="<stolen_access_key_id>"
| table _time, eventName, eventSource, sourceIPAddress, userAgent, awsRegion, errorCode, requestParameters
| sort _time
```

### 4b. Find reconnaissance activity following the AssumeRole

```spl
index=aws_cloudtrail sourceIPAddress="<attacker_ip>"
  earliest=-1h latest=+6h
  (eventName=GetCallerIdentity OR eventName=ListBuckets OR eventName=DescribeInstances
   OR eventName=ListRoles OR eventName=ListUsers OR eventName=GetAccountAuthorizationDetails
   OR eventName=DescribeSecurityGroups OR eventName=ListFunctions)
| table _time, eventName, eventSource, userIdentity.arn, awsRegion, errorCode
| sort _time
```

### 4c. Look for IMDS access patterns on the EC2 instance (VPC Flow Logs)

```spl
index=aws_vpcflow dstaddr=169.254.169.254 srcaddr="<ec2_private_ip>"
  earliest=-24h
| table _time, srcaddr, dstaddr, dstport, action, bytes
| sort _time
```

### 4d. Determine full scope of roles assumed from the attacker IP

```spl
index=aws_cloudtrail eventName=AssumeRole sourceIPAddress="<attacker_ip>"
  earliest=-7d
| stats count, min(_time) as first_seen, max(_time) as last_seen by requestParameters.roleArn, userAgent
| sort -count
```

### 4e. Check whether the newly assumed role was used (downstream pivot)

```spl
index=aws_cloudtrail userIdentity.accessKeyId="<new_access_key_from_responseElements>"
| table _time, eventName, eventSource, sourceIPAddress, awsRegion, errorCode
| sort _time
```

### 4f. Baseline — how often does this role AssumeRole from external IPs (FP check)

```spl
index=aws_cloudtrail eventName=AssumeRole
  userIdentity.sessionContext.sessionIssuer.arn="<ec2_role_arn>"
  earliest=-30d
| iplocation sourceIPAddress
| stats count by sourceIPAddress, Country, Region
| sort -count
```

---

## 5. IAM and Resource Context — AWS CLI Commands

Use the `boto3` default credential chain (`aws configure` / instance profile / environment variables). Do NOT hardcode credentials.

### 5a. Get the full policy attached to the abused EC2 role

```bash
ROLE_NAME="<role-name>"

# List attached managed policies
aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].{Name:PolicyName,Arn:PolicyArn}' --output table

# List inline policies
aws iam list-role-policies --role-name "$ROLE_NAME"

# Get inline policy document
aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "<policy-name>"
```

### 5b. Check if the role has sts:AssumeRole permission (enables lateral movement)

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::<account-id>:role/<role-name>" \
  --action-names "sts:AssumeRole" \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}'
```

### 5c. List active sessions for the stolen credential

```bash
# STS cannot list active sessions, but you can check if the key is still valid:
aws sts get-caller-identity \
  --profile <profile-or-use-env-vars>
# If this returns an ARN, the credential is still live — treat as active threat
```

### 5d. Pull recent CloudTrail events for the EC2 instance's role (last 1 hour)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="<role-name>" \
  --start-time "$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[*].{Time:EventTime,Name:EventName,Source:EventSource,AccessKey:AccessKeyId}' \
  --output table
```

### 5e. Check EC2 instance metadata access mode (IMDSv1 vs IMDSv2)

```bash
aws ec2 describe-instances \
  --instance-ids "<instance-id>" \
  --query 'Reservations[*].Instances[*].MetadataOptions' \
  --output json
```

If `HttpTokens` is `optional`, IMDSv1 is enabled — credential theft via unauthenticated SSRF/IMDS request is trivially possible.

### 5f. Get Security Group rules for the affected instance

```bash
aws ec2 describe-security-groups \
  --group-ids $(aws ec2 describe-instances --instance-ids "<instance-id>" \
    --query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' \
    --output text) \
  --query 'SecurityGroups[*].{ID:GroupId,Inbound:IpPermissions,Outbound:IpPermissionsEgress}' \
  --output json
```

---

## 6. Evidence to Collect and Preserve

Preserve the following before any containment action:

| # | Evidence Item | Where / How |
|---|---|---|
| 1 | Full CloudTrail JSON for the triggering `AssumeRole` event | S3 CloudTrail bucket or CloudWatch Logs |
| 2 | All CloudTrail events for `stolen_access_key_id` (last 24h) | Splunk query 4a output — export as CSV |
| 3 | All CloudTrail events from `attacker_ip` (last 7d) | Splunk query 4d output — export as CSV |
| 4 | VPC Flow Logs for the EC2 instance (last 24h) | S3 or CloudWatch Logs |
| 5 | EC2 instance SSM session logs or CloudWatch agent logs | CloudWatch Log Group for the instance |
| 6 | IAM role policy documents at time of incident | Capture via AWS CLI (step 5a) |
| 7 | EC2 instance metadata options (step 5e output) | Capture JSON to file |
| 8 | Timeline spreadsheet (see section 7) | Build locally |

**Storage:** Write all exported evidence to a case folder named `CDET-007_<date>_<instance-id>/` in the designated IR S3 bucket. Ensure the folder has a bucket policy preventing deletion (Object Lock or Governance mode).

---

## 7. Timeline Reconstruction

1. Set T=0 as the `eventTime` of the triggering `AssumeRole` in CDET-007.
2. Work backwards from T=0 using VPC Flow Logs and application logs to find the initial compromise:
   - Look for inbound connections to the EC2 instance in the minutes before T=0.
   - Check for SSRF indicators in web/application logs (`169.254.169.254` in request URLs).
   - Check for unusual outbound connections from the EC2 instance.
3. Work forwards from T=0 using Splunk queries 4a and 4b to map attacker actions.
4. Build a chronological table:

```
T-XX:XX  [EC2]  Inbound connection from <attacker_ip> to port <port>
T-00:05  [EC2]  IMDS request to 169.254.169.254 (VPC Flow Logs)
T=0      [STS]  AssumeRole event (CDET-007 trigger)
T+00:01  [STS]  GetCallerIdentity from <attacker_ip>
T+00:03  [S3]   ListBuckets from <attacker_ip>
...
```

5. Note the earliest attacker-controlled timestamp — this is your **dwell time** estimate.

---

## 8. Determine Blast Radius

Answer the following before moving to containment:

- [ ] What services did the attacker enumerate? (from Splunk query 4b)
- [ ] Did the attacker successfully read from any S3 buckets? (check `GetObject` events)
- [ ] Did the attacker create any new IAM users, roles, or access keys?
- [ ] Did the attacker modify any security groups or route tables?
- [ ] Did the attacker invoke any Lambda functions?
- [ ] Did the attacker successfully pivot to a second role? (check Splunk query 4e)
- [ ] Are there any other EC2 instances with the same IAM role that could also be compromised?

Document all YES answers — these define the scope of containment and recovery.

> CDET-007 investigation complete. Move to `containment.md`.
