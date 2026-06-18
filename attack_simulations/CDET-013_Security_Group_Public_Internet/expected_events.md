# CDET-013 — Expected CloudTrail Events: Security Group Opened to Public Internet

**Primary Detection Event**: `AuthorizeSecurityGroupIngress`

---

## Primary Detection Event: AuthorizeSecurityGroupIngress

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEATTACKER",
    "arn": "arn:aws:iam::123456789012:user/compromised-user",
    "accountId": "123456789012",
    "accessKeyId": "AKIAEXAMPLEKEY"
  },
  "eventTime": "2026-06-16T06:22:17Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "AuthorizeSecurityGroupIngress",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "groupId": "sg-0example123",
    "ipPermissions": {
      "items": [
        {
          "ipProtocol": "tcp",
          "fromPort": 22,
          "toPort": 22,
          "ipRanges": {
            "items": [
              {
                "cidrIp": "0.0.0.0/0",
                "description": "temp-debug-access"
              }
            ]
          }
        }
      ]
    }
  },
  "responseElements": {
    "requestId": "example-req-id",
    "_return": true
  },
  "resources": [
    {
      "ARN": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0example123",
      "accountId": "123456789012",
      "type": "AWS::EC2::SecurityGroup"
    }
  ],
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012"
}
```

---

## Key Detection Fields

| Field | Detection Logic | Why It Matters |
|-------|----------------|----------------|
| `requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp` | `== "0.0.0.0/0"` | Global IPv4 exposure |
| `requestParameters.ipPermissions.items[].ipv6Ranges.items[].cidrIpv6` | `== "::/0"` | Global IPv6 exposure |
| `requestParameters.ipPermissions.items[].fromPort` | Any port (especially 22, 3389, 3306, 5432, 27017) | Backdoor port type |
| `requestParameters.groupId` | Cross-reference with instances using this SG | Assess blast radius |
| `userIdentity.arn` | IAM principal making the change | Attribution |
| `sourceIPAddress` | Compare to principal's known IPs | Unusual access location |

---

## IPv6 Variant

```json
{
  "eventName": "AuthorizeSecurityGroupIngress",
  "requestParameters": {
    "groupId": "sg-0example123",
    "ipPermissions": {
      "items": [
        {
          "ipProtocol": "tcp",
          "fromPort": 22,
          "toPort": 22,
          "ipv6Ranges": {
            "items": [
              {
                "cidrIpv6": "::/0",
                "description": "ipv6-access"
              }
            ]
          }
        }
      ]
    }
  }
}
```

---

## All-Ports Variant (Most Dangerous)

When `fromPort: 0` and `toPort: 65535`:

```json
{
  "eventName": "AuthorizeSecurityGroupIngress",
  "requestParameters": {
    "groupId": "sg-0example123",
    "ipPermissions": {
      "items": [
        {
          "ipProtocol": "tcp",
          "fromPort": 0,
          "toPort": 65535,
          "ipRanges": {
            "items": [{ "cidrIp": "0.0.0.0/0" }]
          }
        }
      ]
    }
  }
}
```

This opens all TCP ports (0–65535) to the internet — the most aggressive form.

---

## Remediation Event: RevokeSecurityGroupIngress

The revocation event is important for detection timeline analysis:

```json
{
  "eventName": "RevokeSecurityGroupIngress",
  "eventSource": "ec2.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "groupId": "sg-0example123",
    "ipPermissions": {
      "items": [
        {
          "ipProtocol": "tcp",
          "fromPort": 22,
          "toPort": 22,
          "ipRanges": {
            "items": [{ "cidrIp": "0.0.0.0/0" }]
          }
        }
      ]
    }
  }
}
```

If the revocation occurs within seconds to minutes by the same principal that added the rule, this is the "add-and-remove" simulation pattern. If revocation occurs days later by a different principal, this indicates incident response.

---

## High-Risk Port Reference

| Port | Protocol | Service | Attack Use |
|------|----------|---------|------------|
| 22 | TCP | SSH | Linux instance takeover, key deployment |
| 3389 | TCP | RDP | Windows instance takeover, ransomware |
| 3306 | TCP | MySQL | Database exfiltration |
| 5432 | TCP | PostgreSQL | Database exfiltration |
| 1433 | TCP | MSSQL | Database exfiltration |
| 27017 | TCP | MongoDB | Database exfiltration (often unauth) |
| 6379 | TCP | Redis | Cache exfiltration (often unauth) |
| 9200 | TCP | Elasticsearch | Search index exfiltration (often unauth) |
| 4444 | TCP | Metasploit | Reverse shell C2 |
| 8888 | TCP | Common C2 | Reverse shell / C2 framework |
| 0-65535 | TCP/UDP | All | Maximum backdoor — highest severity |

---

## Reconnaissance Events (Preceding the Rule Addition)

| eventName | eventSource | Notes |
|-----------|-------------|-------|
| `DescribeSecurityGroups` | `ec2.amazonaws.com` | Attacker reviewing existing SG rules |
| `DescribeInstances` | `ec2.amazonaws.com` | Finding instances using the target SG |
| `DescribeVpcs` | `ec2.amazonaws.com` | Understanding network context |
| `DescribeNetworkInterfaces` | `ec2.amazonaws.com` | Finding ENIs attached to target SG |

---

## Detection Logic (Splunk/SIEM)

```
eventSource = "ec2.amazonaws.com"
AND eventName = "AuthorizeSecurityGroupIngress"
AND (
    requestParameters.ipPermissions.items{}.ipRanges.items{}.cidrIp = "0.0.0.0/0"
    OR requestParameters.ipPermissions.items{}.ipv6Ranges.items{}.cidrIpv6 = "::/0"
)
```

Severity escalation: add rule for high-risk ports (22, 3389, all-ports 0-65535) → Critical.
