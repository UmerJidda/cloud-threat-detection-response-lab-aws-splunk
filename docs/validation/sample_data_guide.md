# Sample Data Guide

## Overview

The `sample_logs/` directory contains synthetic AWS event datasets that:
- Cover every detection (CDET-001 through CDET-014)
- Include both malicious events (positive test cases) and benign events (negative test cases)
- Use realistic but fictional identifiers (no real account IDs, ARNs, or IPs)
- Are safe to commit to version control

---

## Event Format

### CloudTrail Events

Sample CloudTrail events follow the native AWS CloudTrail JSON format — the same structure that Splunk receives via the Splunk Add-on for AWS. Key fields:

```json
{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLE123456",
    "arn": "arn:aws:iam::123456789012:user/attacker",
    "accountId": "123456789012",
    "userName": "attacker"
  },
  "eventTime": "2024-01-15T14:30:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.77",
  "userAgent": "aws-cli/2.14.0",
  "requestParameters": { "userName": "backdoor-user" },
  "responseElements": { ... },
  "requestID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "eventID": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012"
}
```

### GuardDuty Findings

GuardDuty sample data uses the GuardDuty Finding schema (v2.0):

```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "us-east-1",
  "id": "abc123findingid",
  "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "severity": 8.0,
  "service": { "action": { ... }, "resourceRole": "TARGET" },
  "resource": { "resourceType": "Instance", "instanceDetails": { ... } }
}
```

### Security Hub Findings

Security Hub sample data uses ASFF (Amazon Security Finding Format):

```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:securityhub:...",
  "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
  "Severity": {"Label": "HIGH", "Normalized": 70},
  "Title": "...",
  "Compliance": {"Status": "FAILED"},
  "WorkflowState": "NEW"
}
```

---

## Fictional Values Reference

All sample data uses these consistent fictional identifiers:

| Value | Meaning |
|-------|---------|
| `123456789012` | Primary production account |
| `234567890123` | Approved staging account |
| `345678901234` | Approved security account |
| `456789012345` | Approved logging account |
| `999999999999` | Attacker-controlled external account |
| `777777777777` | Third unknown account (role chain pivot) |
| `888888888888` | Fourth unknown account (role chain pivot) |
| `198.51.100.x` | Malicious external source IPs (RFC 5737) |
| `10.0.1.x` | Internal EC2 private IPs |
| `172.16.0.x` | Internal VPC IPs |
| `169.254.169.254` | EC2 instance metadata service |

---

## Generating New Sample Events

To add sample data for new detections or edge cases:

1. Identify the exact CloudTrail event structure by running the real API call or checking AWS documentation
2. Copy an existing NDJSON file as a template
3. Modify the `eventName`, `userIdentity`, `requestParameters`, and `responseElements` to match your scenario
4. Ensure the event will trigger (or suppress) the detection based on the SPL logic
5. Add the file to the coverage map in `sample_logs/README.md`

**Tips:**
- Set `errorCode` to trigger error-path branches (most detections filter `NOT errorCode=*`)
- Set `userIdentity.type=AWSService` to test lifecycle-policy exclusions in CDET-010/CDET-014
- Use `requestParameters.maxCount=50` to test threshold boundaries in CDET-011

---

## Validation Loop

```
New sample event added
        ↓
python -m validation.validator --detection CDET-XXX
        ↓
Heuristic confirms signal is present
        ↓
Load into Splunk test index
        ↓
Run detection SPL → verify alert output
        ↓
Compare to expected_alert.json
        ↓
Update checklist.md
```
