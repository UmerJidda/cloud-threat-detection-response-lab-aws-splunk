# CDET-001 — IAM User Created Outside Approved Pipeline

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-001 |
| **Severity** | High |
| **Confidence** | Medium |
| **Tactic** | Persistence |
| **Technique** | T1136.003 — Create Account: Cloud Account |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 15 minutes |

---

## 1. Detection Logic

This detection identifies `CreateUser` API calls to the IAM service where the acting
principal is not a member of the approved provisioning pipeline suppression lookup. It
targets the adversarial pattern of creating a new IAM user as a persistence mechanism —
a technique that survives credential rotation and account takeover remediation of the
original compromised identity.

The detection fires only on **successful** creations (`errorCode` absent). Access-denied
attempts are excluded to reduce noise; a separate detection (future) addresses failed
IAM operations as a discovery signal.

Confidence is adjusted within the SPL based on the acting principal type and MFA
authentication status. Interactive IAM users without MFA carry higher confidence than
role-based principals, which have a higher rate of legitimate automation activity.

---

## 2. SPL Query Summary

The search filters `CreateUser` events from the `aws_cloudtrail` index, normalizes the
acting principal ARN (handling both IAMUser and AssumedRole session structures), then
performs two suppression lookups:

1. `approved_iam_principals.csv` — direct ARN match for the acting principal
2. `automation_role_arns.csv` — match against known CI/CD role ARNs
3. `approved_iam_principals.csv` — second lookup against the session issuer ARN for
   cases where an AssumedRole session was issued by an approved pipeline role

Surviving events are tagged with detection metadata and output with standard fields.

---

## 3. Required Fields

| Field | Source | Description |
|-------|--------|-------------|
| `eventName` | CloudTrail | Must equal `CreateUser` |
| `eventSource` | CloudTrail | Must equal `iam.amazonaws.com` |
| `userIdentity.arn` | CloudTrail | ARN of the creating principal |
| `userIdentity.type` | CloudTrail | IAMUser / AssumedRole / Root |
| `userIdentity.sessionContext.sessionIssuer.arn` | CloudTrail | Source role (for AssumedRole) |
| `requestParameters.userName` | CloudTrail | Name of the created user |
| `sourceIPAddress` | CloudTrail | Source IP of the request |
| `awsRegion` | CloudTrail | Region of the API call |
| `errorCode` | CloudTrail | Must be absent (null) |

---

## 4. False Positive Analysis

| Source | Description | Mitigation |
|--------|-------------|-----------|
| Terraform / CDK pipelines | Infrastructure pipelines create service accounts during stack deployments | Add pipeline role ARN to `approved_iam_principals.csv` |
| SCIM / IdP provisioning | Directory sync tools create AWS users corresponding to IdP identities | Add sync role to `automation_role_arns.csv` |
| Break-glass procedures | Emergency user creation during incidents | Add to `approved_iam_principals.csv` with `expiry_date` |
| New account bootstrapping | Initial user creation in a newly vended AWS account | Accept as a one-time event; verify and close |

**Expected FP rate before suppression:** 10–30 per day (environment dependent)
**Expected FP rate after suppression:** < 2 per day

---

## 5. Tuning Recommendations

- Run the detection in a dry-run mode (no alerting) for 7 days before enabling. Count the number of events per creating principal per day.
- Principals creating more than 1 user/day reliably are automation and should be added to suppression lookups.
- Set `expiry_date` on any suppression entry that corresponds to a temporary process (e.g., a migration project). Review expired entries monthly.
- After initial tuning, the detection may benefit from adding a `userIdentity.type=Root` exception as a separate higher-severity branch (root creating users is near-unconditionally malicious).

---

## 6. Validation Requirements

**Events required to trigger:**
- `eventName=CreateUser`
- `eventSource=iam.amazonaws.com`
- No `errorCode` field
- `userIdentity.arn` not present in `approved_iam_principals.csv` or `automation_role_arns.csv`

**Expected alert fields:** `detection_id`, `severity`, `tactic`, `technique`, `eventName`, `principal_arn`, `created_user_name`, `event_source_ip`, `region`

**Pass criteria:**
- Fires on unknown principal creating a user
- Suppressed on approved pipeline principal
- Does not fire on `AccessDenied` creation attempts

**Attack simulation mapping:** `attack_simulation/scenarios/SIM-001_iam_user_creation.md`

---

## 7. Investigation Guidance

When this detection fires:

1. **Identify the creating principal** — Review `principal_arn`. Is it a known service account, a human user, or an assumed role?
2. **Check session context** — If `userIdentity.type=AssumedRole`, the `session_issuer_arn` field shows the source role. Check whether the source role is expected to perform IAM provisioning.
3. **Review the created user** — Query IAM for the new user's policies, groups, and access keys:
   ```bash
   aws iam get-user --user-name <created_user_name>
   aws iam list-attached-user-policies --user-name <created_user_name>
   aws iam list-access-keys --user-name <created_user_name>
   ```
4. **Check for subsequent privilege escalation** — Search for `AttachUserPolicy`, `CreateAccessKey`, or `AddUserToGroup` events following the `CreateUser` event within the same session.
5. **Cross-reference with CDET-004** — Admin policy attachment within 10 minutes of user creation by the same principal is a high-confidence attack chain.

---

## 8. Containment Guidance

If confirmed as unauthorized:

1. **Disable access keys** immediately:
   ```bash
   aws iam update-access-key --user-name <username> --access-key-id <key-id> --status Inactive
   ```
2. **Remove policy attachments** to eliminate privilege:
   ```bash
   aws iam detach-user-policy --user-name <username> --policy-arn <arn>
   ```
3. **Delete the user** once evidence is preserved:
   ```bash
   aws iam delete-user --user-name <username>
   ```
4. **Investigate the creating principal** — it is likely compromised and should have its credentials rotated or revoked.

---

## 9. Recovery Guidance

After containment:
- Rotate credentials for the creating principal
- Review all actions taken by the new user (if any) between creation and deletion
- Check whether any resources were accessed, modified, or created by the unauthorized user
- Verify no other unauthorized users were created in the same session

---

## 10. Example Events

**Positive (should alert):**
```json
{
  "event_id": "abc-001",
  "event_name": "CreateUser",
  "event_source": "iam.amazonaws.com",
  "event_time": "2024-01-15T03:22:11Z",
  "aws_region": "us-east-1",
  "source_ip_address": "203.0.113.99",
  "user_agent": "aws-cli/2.15.0",
  "user_identity_type": "IAMUser",
  "user_identity_arn": "arn:aws:iam::123456789012:user/compromised-admin",
  "error_code": null,
  "request_parameters": {"userName": "backdoor-user", "path": "/"}
}
```

**Negative (suppressed — approved pipeline):**
```json
{
  "event_id": "abc-002",
  "event_name": "CreateUser",
  "event_source": "iam.amazonaws.com",
  "event_time": "2024-01-15T09:05:00Z",
  "user_identity_type": "AssumedRole",
  "user_identity_arn": "arn:aws:sts::123456789012:assumed-role/TerraformRole/terraform-run-42",
  "user_identity_account_id": "123456789012",
  "assumed_role_arn": "arn:aws:iam::123456789012:role/TerraformRole",
  "error_code": null,
  "request_parameters": {"userName": "app-service-account", "path": "/app/"}
}
```

---

## 11. Example Alert Output

```
detection_id   : CDET-001
alert_title    : [CDET-001] IAM User Created Outside Approved Pipeline
severity       : high
urgency        : 2
confidence     : high
tactic         : Persistence
technique      : T1136.003
technique_name : Create Account: Cloud Account
eventName      : CreateUser
principal_arn  : arn:aws:iam::123456789012:user/compromised-admin
principal_type : IAMUser
created_user   : backdoor-user
event_source_ip: 203.0.113.99
region         : us-east-1
mfa_used       : false
_time          : 2024-01-15T03:22:11Z
```
