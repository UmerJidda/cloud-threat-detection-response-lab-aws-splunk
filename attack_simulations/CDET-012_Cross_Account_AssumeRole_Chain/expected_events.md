# CDET-012 — Expected CloudTrail Events: Cross-Account AssumeRole Chain

**Primary Detection Events**: Two `AssumeRole` events where the second uses an `AssumedRole` principal type

---

## First Hop: IAMUser Assumes Role in Account A

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEATTACKER",
    "arn": "arn:aws:iam::MGMT_ACCOUNT_ID:user/compromised-user",
    "accountId": "MGMT_ACCOUNT_ID",
    "accessKeyId": "AKIAEXAMPLEKEY"
  },
  "eventTime": "2026-06-16T05:30:00Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "roleArn": "arn:aws:iam::ACCOUNT_A_ID:role/OrganizationAccountAccessRole",
    "roleSessionName": "cdet012-hop1",
    "durationSeconds": 3600
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "ASIAEXAMPLEHOP1",
      "sessionToken": "<token>",
      "expiration": "2026-06-16T06:30:00Z"
    },
    "assumedRoleUser": {
      "assumedRoleId": "AROAEXAMPLEROLE1:cdet012-hop1",
      "arn": "arn:aws:sts::ACCOUNT_A_ID:assumed-role/OrganizationAccountAccessRole/cdet012-hop1"
    }
  },
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "ACCOUNT_A_ID"
}
```

**Detection signal**: `userIdentity.type = "IAMUser"` calling AssumeRole in a different account (`ACCOUNT_A_ID != MGMT_ACCOUNT_ID`).

---

## Second Hop: AssumedRole Assumes Role in Account B (The Chain)

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLEROLE1:cdet012-hop1",
    "arn": "arn:aws:sts::ACCOUNT_A_ID:assumed-role/OrganizationAccountAccessRole/cdet012-hop1",
    "accountId": "ACCOUNT_A_ID",
    "accessKeyId": "ASIAEXAMPLEHOP1",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "principalId": "AROAEXAMPLEROLE1",
        "arn": "arn:aws:iam::ACCOUNT_A_ID:role/OrganizationAccountAccessRole",
        "accountId": "ACCOUNT_A_ID",
        "userName": "OrganizationAccountAccessRole"
      },
      "webIdFederationData": {},
      "attributes": {
        "mfaAuthenticated": "false",
        "creationDate": "2026-06-16T05:30:00Z"
      }
    }
  },
  "eventTime": "2026-06-16T05:30:15Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.99",
  "userAgent": "aws-cli/2.15.0",
  "readOnly": false,
  "requestParameters": {
    "roleArn": "arn:aws:iam::ACCOUNT_B_ID:role/OrganizationAccountAccessRole",
    "roleSessionName": "cdet012-hop2",
    "durationSeconds": 3600
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "ASIAEXAMPLEHOP2",
      "sessionToken": "<token>",
      "expiration": "2026-06-16T06:30:15Z"
    },
    "assumedRoleUser": {
      "assumedRoleId": "AROAEXAMPLEROLE2:cdet012-hop2",
      "arn": "arn:aws:sts::ACCOUNT_B_ID:assumed-role/OrganizationAccountAccessRole/cdet012-hop2"
    }
  },
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "ACCOUNT_B_ID"
}
```

---

## The Chain Fingerprint

The critical difference between the two events:

| Field | First Hop | Second Hop (Chain) |
|-------|-----------|-------------------|
| `userIdentity.type` | `IAMUser` | `AssumedRole` |
| `userIdentity.accountId` | Management account | Account A |
| `sessionContext.sessionIssuer` | N/A | Points to Account A role |
| `recipientAccountId` | Account A | Account B |
| `requestParameters.roleArn` account | Account A | Account B |

**Detection rule**: `eventName = AssumeRole` AND `userIdentity.type = AssumedRole` AND `userIdentity.accountId != recipientAccountId`

This fires specifically on chained cross-account assumptions — not on same-account role chaining, and not on the initial cross-account assumption from an IAM user.

---

## Organization Enumeration Events (Preceding the Chain)

| eventName | eventSource | Notes |
|-----------|-------------|-------|
| `ListAccounts` | `organizations.amazonaws.com` | Enumerates all account IDs |
| `ListRoots` | `organizations.amazonaws.com` | Gets organization root |
| `ListOrganizationalUnitsForParent` | `organizations.amazonaws.com` | Maps OU hierarchy |
| `ListAccountsForParent` | `organizations.amazonaws.com` | Per-OU account listing |
| `DescribeOrganization` | `organizations.amazonaws.com` | Gets master account ID |

---

## Bulk Traversal Pattern (Multiple Failed + Successful AssumeRole)

When an attacker attempts role assumption in every org account, CloudTrail records both successful and failed attempts:

**Successful assumption** (role exists and trust policy allows it):
- `errorCode`: absent
- `responseElements.credentials` contains valid keys

**Failed assumption** (role doesn't exist or trust doesn't allow):
```json
{
  "eventName": "AssumeRole",
  "errorCode": "AccessDenied",
  "errorMessage": "User: arn:aws:iam::MGMT:user/attacker is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::ACCOUNT_X:role/OrganizationAccountAccessRole"
}
```

**Detection for bulk traversal**: >= 5 `AssumeRole` events (success or failure) targeting different account IDs within 10 minutes from a single principal.

---

## CloudTrail Cross-Account Visibility

Role chain events appear in **multiple CloudTrail trails**:

1. **Management account trail**: Records the first hop (IAMUser → Account A role)
2. **Account A trail**: Records the incoming AssumeRole from management account AND the outgoing second hop
3. **Account B trail**: Records the second hop (AssumedRole from Account A → Account B role)
4. **Org-wide CloudTrail** (if configured): Records all events across all accounts

Organizations using AWS Organizations CloudTrail (enabled via Organizations settings) will see all events in a single centralized S3 bucket, making the chain visible as a correlated sequence.
