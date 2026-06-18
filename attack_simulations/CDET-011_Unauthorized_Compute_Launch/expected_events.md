# CDET-011 — Expected CloudTrail Events: Unauthorized Compute Resource Launch

**Primary Detection Events**: `RunInstances`, `CreateFunction`

---

## Primary Detection Event: RunInstances (GPU Instance)

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
  "eventTime": "2026-06-16T04:10:22Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "RunInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "instanceType": "p3.16xlarge",
    "minCount": 10,
    "maxCount": 10,
    "imageId": "ami-0abcdef1234567890",
    "userData": "<base64-encoded-mining-bootstrap-script>",
    "tagSpecificationSet": {
      "items": [
        {
          "resourceType": "instance",
          "tags": []
        }
      ]
    }
  },
  "responseElements": {
    "requestId": "example-request-id",
    "reservationId": "r-0example123",
    "ownerId": "123456789012",
    "instancesSet": {
      "items": [
        {
          "instanceId": "i-0example001",
          "instanceType": "p3.16xlarge",
          "imageId": "ami-0abcdef1234567890",
          "currentState": { "code": 0, "name": "pending" }
        }
      ]
    }
  },
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012"
}
```

---

## Key Detection Fields in RunInstances

| Field | Value | Significance |
|-------|-------|--------------|
| `requestParameters.instanceType` | `p3.16xlarge`, `g4dn.12xlarge`, etc. | GPU family = mining indicator |
| `requestParameters.minCount` | >= 5 | High count = crypto mining scale |
| `requestParameters.maxCount` | >= 5 | High count = crypto mining scale |
| `requestParameters.userData` | Base64 encoded | Decode to find mining bootstrap commands |
| `responseElements.instancesSet.items[].instanceType` | GPU type | Confirmed launched instance type |

**GPU Instance Type Patterns** to monitor:
- `p2.*` — NVIDIA K80 (older, still used)
- `p3.*` — NVIDIA V100 (high-value target)
- `p4d.*` — NVIDIA A100 (highest cost)
- `g3.*` — NVIDIA M60
- `g4dn.*` — NVIDIA T4 (common for cost-efficient mining)
- `g5.*` — NVIDIA A10G

---

## Primary Detection Event: CreateFunction (Lambda Miner)

```json
{
  "eventName": "CreateFunction20150331",
  "eventSource": "lambda.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "functionName": "crypto-worker-001",
    "runtime": "python3.12",
    "role": "arn:aws:iam::123456789012:role/lambda-exec",
    "handler": "index.handler",
    "timeout": 900,
    "memorySize": 3008,
    "description": ""
  },
  "responseElements": {
    "functionName": "crypto-worker-001",
    "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:crypto-worker-001",
    "runtime": "python3.12",
    "timeout": 900,
    "memorySize": 3008
  }
}
```

**Lambda Mining Indicators**:
- `timeout`: 900 (maximum — attacker wants longest mining window)
- `memorySize`: 3008 (maximum non-reserved — more vCPU for mining)
- `functionName` containing: `worker`, `job`, `task`, `proc` with numeric suffixes (scaling pattern)
- Function name not matching any known application function

---

## Supporting Events (Context)

### GetInstanceTypesFromInstanceRequirements — Attacker researching GPU availability

```json
{
  "eventName": "GetInstanceTypesFromInstanceRequirements",
  "eventSource": "ec2.amazonaws.com",
  "readOnly": true,
  "requestParameters": {
    "architectureTypes": ["x86_64"],
    "vCpuCount": { "min": 32 },
    "memoryMiB": { "min": 65536 }
  }
}
```

### DescribeInstanceTypeOfferings — Checking which regions have GPU instances

```json
{
  "eventName": "DescribeInstanceTypeOfferings",
  "eventSource": "ec2.amazonaws.com",
  "readOnly": true,
  "requestParameters": {
    "filters": [
      { "name": "instance-type", "values": ["p3.*", "g4dn.*"] }
    ]
  }
}
```

### DescribeSpotInstanceRequests — Attacker using Spot for cheaper mining

```json
{
  "eventName": "RequestSpotInstances",
  "eventSource": "ec2.amazonaws.com",
  "readOnly": false,
  "requestParameters": {
    "spotPrice": "5.00",
    "instanceCount": 20,
    "launchSpecification": {
      "instanceType": "g4dn.12xlarge"
    }
  }
}
```

Spot instances reduce attacker cost by 60–90% compared to on-demand. `RequestSpotInstances` for GPU types is a high-fidelity indicator.

---

## Event Timeline

```
T+0:00  GetCallerIdentity              — attacker confirms credentials work
T+0:05  DescribeInstanceTypes          — research GPU options
T+0:10  DescribeImages                 — find suitable AMI
T+0:15  RunInstances (x10, p3.16xl)    — DETECTION EVENT (CDET-011)
T+0:15  [Instance launch begins]       — AWS provisions GPU instances
T+5:00  [Instances reach running state]
T+5:01  [XMRig mining begins]          — attacker starts earning
T+6:00  [Billing begins]               — $24.48/hr × 10 = $244.80/hr
...
T+24hrs Cost anomaly alert fires       — ~$5,875 billed (if not detected earlier)
```

CDET-011 fires at T+0:15 — before the first dollar of billing occurs.

---

## Correlated Detections

- CDET-008: Excessive API Enumeration often precedes (attacker mapping IAM permissions)
- CDET-013: Security Group Modification (attacker may open ports to access miner management)
