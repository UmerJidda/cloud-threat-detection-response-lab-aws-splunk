# CDET-013 — Positive Test Case

**Purpose:** Verify the detection fires when a security group ingress rule is authorized that allows traffic from 0.0.0.0/0 (IPv4) or ::/0 (IPv6), especially on high-risk ports.

## Test Input
- Sample file: sample_logs/cloudtrail/malicious/CDET-013_sg_opened_to_internet.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Trigger Conditions

### Scenario A — SSH (Port 22) Opened to All IPv4
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 0.0.0.0/0
- from_port: 22, to_port: 22
- ip_protocol: tcp
- high_risk_port: true
- Severity: critical, Urgency: 1

### Scenario B — RDP (Port 3389) Opened to All IPv6
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: ::/0
- from_port: 3389, to_port: 3389
- ip_protocol: tcp
- high_risk_port: true
- Severity: critical, Urgency: 1

### Scenario C — Non-Standard Port Opened to All IPv4
- eventName: AuthorizeSecurityGroupIngress
- cidr_range: 0.0.0.0/0
- from_port: 8080, to_port: 8080
- ip_protocol: tcp
- high_risk_port: false (not in high_risk_ports lookup)
- Severity: high, Urgency: 2

## Sample Event Fields (Scenario A)
```json
{
  "eventName": "AuthorizeSecurityGroupIngress",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012"
  },
  "requestParameters": {
    "groupId": "sg-0abc123def456789",
    "ipPermissions": {
      "items": [{
        "ipProtocol": "tcp",
        "fromPort": 22,
        "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}
      }]
    }
  },
  "sourceIPAddress": "198.51.100.77",
  "awsRegion": "us-east-1",
  "eventTime": "2024-01-15T14:32:15Z"
}
```

## Expected Result
- Detection fires: YES for all three scenarios
- Scenarios A and B: severity=critical, urgency=1 (high-risk port)
- Scenario C: severity=high, urgency=2 (non-high-risk port)
- Expected ATT&CK fields populated: tactic=Defense Evasion, technique=T1562.007

## Pass Criteria
- Alert generated within one schedule period
- alert_title equals "[CDET-013] Security Group Opened to Internet"
- group_id correctly extracted
- from_port, to_port, ip_protocol, and cidr_range correctly populated
- high_risk_port correctly set based on port lookup
- Severity correctly reflects high vs. critical based on high_risk_port status
