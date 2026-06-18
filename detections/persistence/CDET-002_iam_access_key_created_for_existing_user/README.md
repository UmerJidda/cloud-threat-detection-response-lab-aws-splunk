# CDET-002 — IAM Access Key Created for Existing User

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-002 |
| **Severity** | High |
| **Confidence** | High |
| **Tactic** | Persistence |
| **Technique** | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 15 minutes |

---

## Detection Logic

Adversaries who have obtained initial access to an AWS environment frequently create a new access key for an existing privileged user as their primary persistence mechanism. Unlike creating a new user, adding a key to an existing user is quieter — fewer systems alert on key creation than on account creation — and the key can be immediately used for programmatic API access.

The detection fires on two conditions:

1. **Third-party key creation** — the creating principal ARN does not match the key recipient's username (i.e., someone is creating a key for someone else).
2. **Privileged user key creation** — the key recipient is in the `privileged_iam_users` lookup, regardless of whether it is a self-rotation. Privileged users should rotate keys through approved automated processes only.

Self-rotation by standard (non-privileged) users from approved automation is suppressed via lookup.

---

## Key Fields

| Field | Description |
|-------|-------------|
| `creator_arn` | The principal who called CreateAccessKey |
| `key_owner_name` | The IAM user who receives the new key |
| `new_access_key_id` | The AKIA* ID of the created key |
| `self_rotation` | `true` if creator ARN ends with key_owner_name |
| `is_privileged` | `true` if key_owner_name is in privileged_iam_users lookup |

---

## Example Event

**Positive (third-party creation — should alert):**
```json
{
  "event_name": "CreateAccessKey",
  "event_source": "iam.amazonaws.com",
  "event_time": "2024-01-15T02:47:33Z",
  "user_identity_type": "AssumedRole",
  "user_identity_arn": "arn:aws:sts::123456789012:assumed-role/CompromisedRole/session",
  "error_code": null,
  "request_parameters": {"userName": "finance-admin"},
  "response_elements": {"accessKey": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE"}}
}
```

## Example Alert Output

```
detection_id   : CDET-002
alert_title    : [CDET-002] IAM Access Key Created for Existing User
severity       : high
creator_arn    : arn:aws:sts::123456789012:assumed-role/CompromisedRole/session
key_owner_name : finance-admin
new_access_key_id: AKIAIOSFODNN7EXAMPLE
self_rotation  : false
is_privileged  : false
event_source_ip: 198.51.100.44
region         : us-east-1
```
