# CDET-007 — Expected CloudTrail Events

## Overview

This attack generates no CloudTrail events during the credential retrieval phase (IMDS is not logged). CloudTrail events only appear when the stolen credentials are *used* — typically from an external IP address. The key detection signal is the mismatch between the role's expected source (the EC2 instance IP) and the observed source (external IP).

---

## No Event: IMDS Credential Retrieval (Intentional Gap)

**The IMDS request itself does NOT generate a CloudTrail event.**

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyApplicationRole
```

This call is entirely local to the EC2 instance and is not visible to AWS control plane logging. This is why IMDS-based credential theft is particularly dangerous — there is no log of the theft itself.

The only mitigations that create visibility at the theft point:
- Host-based monitoring (EDR, auditd) on the EC2 instance logging `curl` or other HTTP client processes
- VPC Flow Logs (shows traffic to 169.254.169.254, though the payload is not captured)
- IMDSv2 enforcement (prevents SSRF-based credential retrieval without a two-step flow)

---

## Event 1: GetCallerIdentity (Credential Verification from External IP)

First action taken by the attacker after stealing credentials — verifying they work.

| Field | Value |
|-------|-------|
| `eventSource` | `sts.amazonaws.com` |
| `eventName` | `GetCallerIdentity` |
| `userIdentity.type` | `AssumedRole` |
| `userIdentity.principalId` | `AROAXXXXXXXXXXXXXXXXX:i-1234567890abcdef0` |
| `userIdentity.arn` | `arn:aws:sts::123456789012:assumed-role/MyApplicationRole/i-1234567890abcdef0` |
| `userIdentity.accountId` | Victim account ID |
| `userIdentity.sessionContext.sessionIssuer.type` | `Role` |
| `userIdentity.sessionContext.sessionIssuer.userName` | `MyApplicationRole` |
| `userIdentity.sessionContext.ec2RoleDelivery` | `1.0` (confirms credentials came from EC2 IMDS) |
| `sourceIPAddress` | **Attacker's external IP** (not the EC2 instance IP) |
| `userAgent` | `aws-cli/2.x` or custom tool user agent |

**Critical detection fields:**
- `userIdentity.sessionContext.ec2RoleDelivery` — this field appears only when credentials were obtained via EC2 IMDS. Its presence combined with a non-EC2 source IP is the definitive signal.
- `sourceIPAddress` — compared against known EC2 instance IPs in the lookup table

---

## Event 2: Subsequent API Calls (Data Access, Enumeration)

All subsequent API calls using the stolen credentials will have the same pattern:

| Field | Value |
|-------|-------|
| `userIdentity.type` | `AssumedRole` |
| `userIdentity.sessionContext.sessionIssuer.userName` | `MyApplicationRole` |
| `sourceIPAddress` | Attacker's external IP (consistent across all calls) |
| `eventName` | Various (ListBuckets, DescribeInstances, GetSecretValue, etc.) |

---

## Event 3: Eventual AssumeRole (If Attacker Pivots)

If the stolen credentials have `sts:AssumeRole` permission, the attacker may use them to assume additional roles:

| Field | Value |
|-------|-------|
| `eventSource` | `sts.amazonaws.com` |
| `eventName` | `AssumeRole` |
| `requestParameters.roleArn` | Target role the attacker is pivoting to |
| `userIdentity.type` | `AssumedRole` (from EC2 role) |
| `sourceIPAddress` | Attacker's external IP |

---

## GuardDuty Finding

| Field | Value |
|-------|-------|
| Finding Type | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` |
| Severity | High (7.0–8.9) |
| Description | EC2 instance credentials used from an IP address that is not associated with the EC2 instance |
| Resource | The IAM role (`MyApplicationRole`) |
| Action | `AWS_API_CALL` |
| Service | `cloudtrail` (GuardDuty reads from CloudTrail) |

---

## SPL Detection Query (CDET-007)

```spl
index=aws_cloudtrail
  userIdentity.type=AssumedRole
  userIdentity.sessionContext.ec2RoleDelivery=1.0
| eval instance_role=userIdentity.sessionContext.sessionIssuer.userName
| eval source_ip=sourceIPAddress
| lookup ec2_instance_ips.csv role_name AS instance_role OUTPUT instance_ips
| where NOT cidrmatch(source_ip, instance_ips)
| stats
    count as api_calls,
    values(eventName) as actions,
    values(source_ip) as external_ips
    by instance_role, userIdentity.arn
| where api_calls > 0
| eval severity="CRITICAL"
| eval alert_reason="EC2 instance role credentials used from external IP: " + mvjoin(external_ips, ", ")
```

**Without an IP lookup table** (simpler fallback):
```spl
index=aws_cloudtrail
  userIdentity.type=AssumedRole
  userIdentity.sessionContext.ec2RoleDelivery=1.0
| eval is_private_ip=if(
    cidrmatch("10.0.0.0/8", sourceIPAddress) OR
    cidrmatch("172.16.0.0/12", sourceIPAddress) OR
    cidrmatch("192.168.0.0/16", sourceIPAddress),
    1, 0
  )
| where is_private_ip=0
| table _time, userIdentity.arn, sourceIPAddress, eventName
```

---

## Event Timeline

```
T+0:00  — Attacker exploits SSRF or gains shell on EC2 instance
T+0:01  — curl http://169.254.169.254/... (NO CloudTrail event)
T+0:02  — Credentials exfiltrated to external machine
T+0:03  — GetCallerIdentity called from external IP (CLOUDTRAIL EVENT #1 — CDET-007 trigger)
T+0:05  — GuardDuty fires InstanceCredentialExfiltration finding
T+0:10  — CloudTrail event reaches S3 — Splunk alert fires
T+0:25  — SOC receives alert
```

The goal of CDET-007 is to close the detection gap at T+0:10 — earlier if CloudWatch Logs integration is active (T+0:03 to T+0:05).
