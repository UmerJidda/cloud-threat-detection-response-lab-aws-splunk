---
detection_id: CDET-011
detection_name: Unauthorized EC2 Instance Launch
tactic: Impact
technique: T1496
last_updated: 2026-06-18
---

# CDET-011 — Investigation Playbook

**Audience:** Tier-2 SOC analyst with AWS CLI access and Splunk access.  
**Goal:** Determine scope, confirm or refute malicious intent, and produce a documented evidence package for containment/escalation.

---

## 1. Anchor the Triggering Event

Retrieve the full raw CloudTrail event for the `RunInstances` call that fired CDET-011.

```spl
index=aws_cloudtrail eventName=RunInstances
| search userIdentity.arn="<ARN_FROM_ALERT>"
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table event_time, awsRegion, sourceIPAddress, userIdentity.arn, userIdentity.type,
         requestParameters.instanceType, requestParameters.imageId,
         requestParameters.maxCount, requestParameters.iamInstanceProfile.name,
         responseElements.instancesSet.items{}.instanceId, errorCode, errorMessage
| sort -event_time
```

**Key fields to record:**

| Field | Significance for T1496 |
|---|---|
| `requestParameters.instanceType` | GPU instances (p2/p3/p4/g4dn/g5) indicate crypto-mining |
| `requestParameters.imageId` | Public/community AMIs may contain pre-installed miners |
| `requestParameters.userData` | Base64-encoded; may contain miner bootstrap scripts |
| `requestParameters.iamInstanceProfile` | Grants the instance an identity — check permissions |
| `responseElements.instancesSet.items{}.instanceId` | Instance IDs to track and later terminate |
| `requestParameters.securityGroupIds` | Open ports (especially 3333, 4444, 14444) used by mining pools |
| `requestParameters.subnetId` | Placement — public subnet increases blast radius |

---

## 2. Decode userData

If `requestParameters.userData` is present, decode it:

```bash
# Extract and decode userData from the CloudTrail JSON
echo "<base64_encoded_userData>" | base64 --decode
```

Look for:
- Package managers installing `xmrig`, `ethminer`, `claymore`, or similar tools
- Outbound connections to known mining pool domains/IPs
- Curl/wget commands fetching external scripts
- Cron jobs or systemd services establishing persistence

---

## 3. Characterize the Actor

### 3a. Recent API activity by this actor (last 24 hours)

```spl
index=aws_cloudtrail userIdentity.arn="<ARN_FROM_ALERT>"
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| stats count by event_time, eventName, awsRegion, sourceIPAddress, errorCode
| sort -event_time
```

### 3b. Privilege escalation or credential exposure preceding the launch

```spl
index=aws_cloudtrail userIdentity.arn="<ARN_FROM_ALERT>"
  (eventName=GetSecretValue OR eventName=AssumeRole OR eventName=CreateAccessKey
   OR eventName=AttachUserPolicy OR eventName=PutUserPolicy
   OR eventName=AttachRolePolicy OR eventName=CreateRole)
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table event_time, eventName, requestParameters, responseElements, sourceIPAddress
| sort event_time
```

### 3c. Check for prior reconnaissance

```spl
index=aws_cloudtrail userIdentity.arn="<ARN_FROM_ALERT>"
  (eventName=DescribeInstances OR eventName=DescribeImages
   OR eventName=DescribeSubnets OR eventName=DescribeSecurityGroups
   OR eventName=ListBuckets OR eventName=GetAccountSummary)
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table event_time, eventName, awsRegion, sourceIPAddress
| sort event_time
```

---

## 4. Genuine T1496 Attack Chain

A typical resource-hijacking (crypto-mining) sequence via a compromised IAM credential looks like:

1. **Credential exposure** — IAM access key leaked via GitHub, S3 public bucket, or instance metadata (IMDSv1 abuse)
2. **Reconnaissance** — `DescribeRegions`, `DescribeInstances`, `GetAccountSummary` to understand the environment
3. **Privilege escalation (optional)** — `CreateRole`, `AttachRolePolicy`, or `PassRole` to gain EC2 launch permissions
4. **Instance launch** — `RunInstances` with GPU instance type, public AMI, and userData containing miner bootstrap
5. **Persistence on instance** — Miner installed via userData or SSM `SendCommand` after launch
6. **Exfiltration of profit** — Outbound connections to mining pool over non-standard ports

If you see steps 1–3 in the actor's history, the `RunInstances` is almost certainly malicious.

---

## 5. IAM and Resource Context (AWS CLI)

Use `boto3.Session()` default credential chain (configured via `aws configure`) — never hardcode credentials.

### 5a. Review the actor's IAM permissions

```bash
# If actor is an IAM user
aws iam list-attached-user-policies --user-name <USERNAME>
aws iam list-user-policies --user-name <USERNAME>
aws iam get-user --user-name <USERNAME>

# If actor is an IAM role
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
aws iam get-role --role-name <ROLE_NAME>
```

### 5b. Check instance profile permissions

```bash
aws iam get-instance-profile --instance-profile-name <PROFILE_NAME>
aws iam list-role-policies --role-name <ROLE_IN_PROFILE>
aws iam list-attached-role-policies --role-name <ROLE_IN_PROFILE>
```

### 5c. Describe the launched instances

```bash
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID_1> <INSTANCE_ID_2> \
  --region <REGION> \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,Type:InstanceType,LaunchTime:LaunchTime,PublicIP:PublicIpAddress,IAMProfile:IamInstanceProfile.Arn}'
```

### 5d. Check security groups attached to the instances

```bash
aws ec2 describe-security-groups \
  --group-ids <SG_ID> \
  --region <REGION>
```

Look for inbound rules allowing 0.0.0.0/0 and outbound rules permitting all traffic (typical for mining instances).

### 5e. Check for access key activity

```bash
# If actor is an IAM user, when was the access key last used?
aws iam get-access-key-last-used --access-key-id <ACCESS_KEY_ID>

# List all access keys for the user
aws iam list-access-keys --user-name <USERNAME>
```

---

## 6. Multi-Region Sweep

T1496 actors often launch in multiple regions simultaneously to maximize mining yield before detection.

```spl
index=aws_cloudtrail eventName=RunInstances
| search userIdentity.arn="<ARN_FROM_ALERT>" OR sourceIPAddress="<SOURCE_IP>"
| stats count by awsRegion, requestParameters.instanceType
| sort -count
```

```bash
# Enumerate all regions for suspicious instances from this actor
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "=== $region ==="
  aws ec2 describe-instances \
    --region "$region" \
    --filters "Name=instance-state-name,Values=running,pending" \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Type:InstanceType,LaunchTime:LaunchTime,KeyName:KeyName}' \
    --output table 2>/dev/null
done
```

---

## 7. Evidence Collection and Preservation

Collect and preserve the following before any containment action:

| Evidence item | How to collect |
|---|---|
| Full CloudTrail event JSON | Splunk raw event export or `aws cloudtrail lookup-events` |
| Instance metadata snapshot | `aws ec2 describe-instances --instance-ids <ID>` output |
| Security group rules | `aws ec2 describe-security-groups` output |
| IAM actor policy snapshot | `aws iam get-user-policy` / `aws iam get-role-policy` output |
| VPC Flow Logs for instance ENI | CloudWatch Logs or S3 bucket if flow logs enabled |
| userData (decoded) | From `aws ec2 describe-instance-attribute --attribute userData` |
| Access key last-used timestamps | `aws iam get-access-key-last-used` output |

```bash
# Preserve userData from running instance
aws ec2 describe-instance-attribute \
  --instance-id <INSTANCE_ID> \
  --attribute userData \
  --region <REGION> \
  --query 'UserData.Value' \
  --output text | base64 --decode > evidence_CDET-011_userdata_<INSTANCE_ID>.txt
```

---

## 8. Timeline Reconstruction

Build a unified timeline combining:

```spl
index=aws_cloudtrail
  (userIdentity.arn="<ARN_FROM_ALERT>" OR sourceIPAddress="<SOURCE_IP>")
  earliest=-7d
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table event_time, eventName, awsRegion, sourceIPAddress, userIdentity.arn,
         requestParameters, responseElements, errorCode
| sort event_time
```

Annotate the timeline with:
- T0: Estimated credential compromise time (first anomalous API call from new IP)
- T1: First reconnaissance event
- T2: `RunInstances` event (CDET-011 trigger)
- T3: Detection time (alert fired)
- T4: Triage complete
- T5: Investigation complete (this step)

---

## 9. Investigation Conclusion

Before proceeding to `containment.md`, document:

- [ ] Full list of instance IDs launched
- [ ] All regions affected
- [ ] Actor ARN and access key ID confirmed
- [ ] userData decoded and analyzed
- [ ] Instance profile permissions assessed
- [ ] Preceding attack chain events identified (or ruled out)
- [ ] Evidence package saved to incident folder
- [ ] Malicious vs. accidental determination made
