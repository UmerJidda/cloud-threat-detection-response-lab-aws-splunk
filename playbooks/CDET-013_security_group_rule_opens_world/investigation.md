---
detection_id: CDET-013
detection_name: Security Group Opens Ingress to World
tactic: Defense Evasion
technique: T1562.007
last_updated: 2026-06-18
---

# CDET-013 — Investigation Playbook
## Security Group Opens Ingress to World

**Prerequisite:** Triage is complete and the alert has been classified as a real alert.  
**Goal:** Reconstruct the full attack chain, gather evidence, and determine blast radius.

---

## 1. CloudTrail Event Fields to Examine

For `AuthorizeSecurityGroupIngress` events, extract and record every field below:

| Field path | What it tells you |
|---|---|
| `eventTime` | When the change occurred (UTC) |
| `userIdentity.arn` | Full ARN of the caller (user, role, or assumed-role session) |
| `userIdentity.sessionContext.sessionIssuer.arn` | The role that was assumed (if applicable) — pivot to find who assumed it |
| `userIdentity.accessKeyId` | Access key used — check if it is a long-term key vs. temporary STS token |
| `sourceIPAddress` | Origin IP — geo-lookup and compare against `corporate_ip_ranges.csv` |
| `userAgent` | CLI, SDK, console, or unusual tool string |
| `requestParameters.groupId` | Target security group |
| `requestParameters.ipPermissions` | Full rule detail: protocol, from/toPort, CidrIp/CidrIpv6 |
| `requestParameters.vpcId` | VPC context |
| `responseElements.return` | `true` = change was applied, `false` = denied |
| `errorCode` / `errorMessage` | Presence of repeated `UnauthorizedOperation` before success = access escalation pattern |

---

## 2. Splunk SPL Pivot Queries

Replace `<groupId>`, `<principalArn>`, and `<sourceIP>` with values from the triggering alert.

### 2a. Fetch the raw triggering event

```spl
index=aws_cloudtrail eventName=AuthorizeSecurityGroupIngress
  requestParameters.groupId="<groupId>"
| table _time, eventTime, userIdentity.arn, userIdentity.accessKeyId,
        sourceIPAddress, userAgent, requestParameters.ipPermissions,
        responseElements.return, awsRegion, recipientAccountId
| sort -_time
```

### 2b. All SG modifications by the same principal in the last 7 days

```spl
index=aws_cloudtrail
  (userIdentity.arn="<principalArn>" OR userIdentity.sessionContext.sessionIssuer.arn="<principalArn>")
  eventName IN (AuthorizeSecurityGroupIngress, AuthorizeSecurityGroupEgress,
                RevokeSecurityGroupIngress, RevokeSecurityGroupEgress,
                CreateSecurityGroup, DeleteSecurityGroup)
| table _time, eventName, requestParameters.groupId, requestParameters.ipPermissions,
        sourceIPAddress, userAgent, awsRegion
| sort -_time
```

### 2c. All API calls from the same source IP in the last 24 hours (lateral context)

```spl
index=aws_cloudtrail sourceIPAddress="<sourceIP>"
| stats count by eventName, userIdentity.arn, awsRegion
| sort -count
```

### 2d. Detect access key creation or credential escalation preceding the event

```spl
index=aws_cloudtrail
  (userIdentity.arn="<principalArn>" OR userIdentity.sessionContext.sessionIssuer.arn="<principalArn>")
  eventName IN (CreateAccessKey, AttachUserPolicy, AttachRolePolicy,
                PutUserPolicy, PutRolePolicy, AssumeRole, AssumeRoleWithWebIdentity,
                UpdateAssumeRolePolicy)
  earliest=-7d
| table _time, eventName, requestParameters, responseElements, sourceIPAddress
| sort -_time
```

### 2e. Check for reconnaissance before the modification

```spl
index=aws_cloudtrail
  (userIdentity.arn="<principalArn>" OR sourceIPAddress="<sourceIP>")
  eventName IN (DescribeSecurityGroups, DescribeInstances, DescribeVpcs,
                DescribeSubnets, DescribeNetworkInterfaces,
                GetAccountAuthorizationDetails, ListRoles)
  earliest=-2h latest=+30m
| table _time, eventName, sourceIPAddress, userIdentity.arn
| sort -_time
```

### 2f. Identify instances using the modified security group

```spl
index=aws_cloudtrail eventName=DescribeInstanceAttribute
| eval sgList=mvindex(split(requestParameters.groupSet, ","), 0)
| search sgList="<groupId>"
| table _time, responseElements.instanceId
```

> For real-time instance lookups, use the AWS CLI query in section 4 below — CloudTrail alone may not have the current association.

---

## 3. Attack Chain for T1562.007 — Disable or Modify Cloud Firewall

A genuine exploitation of this technique typically follows this pattern:

```
1. Initial Access
   - Compromised long-term IAM access key (leaked in code repo, S3, env var)
   - Phished console credentials
   - Overprivileged role assumed via SSRF or instance metadata

2. Discovery / Reconnaissance
   - DescribeSecurityGroups, DescribeInstances, DescribeVpcs
   - GetAccountAuthorizationDetails (enumerate IAM permissions)

3. Defense Evasion — T1562.007
   - AuthorizeSecurityGroupIngress with CidrIp=0.0.0.0/0
   - Opens admin port (22, 3389) or all traffic to enable direct access

4. Impact / Follow-on (occurs within minutes if successful)
   - SSH/RDP brute force or direct login to exposed instance
   - Lateral movement within VPC
   - Data exfiltration, ransomware deployment, cryptomining
   - RevokeSecurityGroupIngress to close the rule after backdoor is established
     (covers tracks — do NOT let this make you think the threat is resolved)
```

**Key indicator of malicious intent vs. accident:** Legitimate operators rarely open `0.0.0.0/0` on admin ports. Even accidental opens are typically reversed within minutes via automation. An open rule that persists beyond the automated remediation window, OR that is followed by inbound connection attempts to the instance, is strongly indicative of intent.

---

## 4. IAM and Resource Context — AWS CLI Commands

All commands use the boto3 default credential chain (`aws configure` / environment / instance role). Do not hardcode credentials.

### 4a. Describe the modified security group

```bash
aws ec2 describe-security-groups \
  --group-ids <groupId> \
  --region <awsRegion> \
  --output json
```

### 4b. Find all EC2 instances associated with the SG

```bash
aws ec2 describe-instances \
  --filters "Name=instance.group-id,Values=<groupId>" \
  --region <awsRegion> \
  --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,
           PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,
           LaunchTime:LaunchTime,Tags:Tags}" \
  --output json
```

### 4c. Check the caller's IAM identity and attached policies

```bash
# Resolve the full identity
aws sts get-caller-identity

# If the caller is an IAM user, list attached policies
aws iam list-attached-user-policies --user-name <userName>
aws iam list-user-policies --user-name <userName>

# If the caller is a role, list attached policies
aws iam list-attached-role-policies --role-name <roleName>
aws iam get-role --role-name <roleName>
```

### 4d. Inspect the access key and check for recent key creation

```bash
aws iam list-access-keys --user-name <userName>
aws iam get-access-key-last-used --access-key-id <accessKeyId>
```

### 4e. Check VPC Flow Logs for inbound connection attempts after the rule was added

```bash
# List log groups for the VPC
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/vpc/flowlogs" \
  --region <awsRegion>

# Query for inbound accepted traffic to the instance on the opened port
aws logs filter-log-events \
  --log-group-name "<vpcFlowLogGroup>" \
  --filter-pattern "[version, accountId, interfaceId, srcAddr, dstAddr, srcPort,
                    dstPort=<openedPort>, protocol, packets, bytes, start, end,
                    action=ACCEPT, logStatus]" \
  --start-time <epochMs_of_event> \
  --region <awsRegion>
```

---

## 5. Evidence to Collect and Preserve

Before any containment action, capture and attach to the incident ticket:

- [ ] Full raw CloudTrail JSON event for the `AuthorizeSecurityGroupIngress` call
- [ ] Output of `describe-security-groups` showing the current rule set
- [ ] Output of `describe-instances` showing attached instances and their state
- [ ] VPC Flow Log entries (if available) for the time window +/- 30 minutes around the event
- [ ] Screenshot or JSON export of all Splunk SPL query results from section 2
- [ ] Access key last-used timestamp and creation date
- [ ] Any `GetConsoleOutput` or `DescribeInstanceConsoleOutput` if an instance was accessed
- [ ] CloudTrail event IDs (`eventID` field) for every event in the timeline

---

## 6. Timeline Reconstruction

1. Set `T0` = `eventTime` of the `AuthorizeSecurityGroupIngress` event.
2. Go back 2 hours from `T0` and build a chronological table of all API calls by the principal and from the source IP using the SPL queries in section 2.
3. Go forward 1 hour from `T0` and look for:
   - VPC Flow Log `ACCEPT` entries to the exposed port on the affected instance
   - Any `RevokeSecurityGroupIngress` call that closes the rule (cleanup behavior)
   - Any EC2 `RunInstances`, `CreateKeyPair`, `ImportKeyPair` calls (persistence)
   - Any IAM `CreateUser`, `CreateAccessKey`, `AttachUserPolicy` calls (persistence)
4. Document the timeline in the incident ticket with `_time`, `eventName`, `principalArn`, `sourceIP`, and a brief note on each event's significance.
5. Preserve the timeline artifact as a CSV or JSON attachment before escalating.
