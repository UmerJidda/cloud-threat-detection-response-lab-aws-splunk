---
detection_id: CDET-002
detection_name: Access Key Created for Another User
tactic: Persistence
technique: T1098.001
last_updated: 2026-06-18
---

# CDET-002 — Recovery Playbook
# Access Key Created for Another User

**Prerequisites:** Containment complete. Actor access confirmed revoked.  
**Goal:** Restore normal operations, harden the environment, and reduce future risk.

---

## 1. Verify the Threat Has Been Fully Removed

Before lifting any quarantine controls, confirm all of the following are true:

### 1.1 No active use of the backdoor key

```spl
index=aws_cloudtrail userIdentity.accessKeyId="<new_key_id>"
    earliest=<containment_timestamp> latest=now
| stats count
```

Expected result: 0 events. If any events appear after the key was disabled, re-open containment — the key may not have been fully revoked or there is a secondary credential.

### 1.2 No new keys created since containment

```spl
index=aws_cloudtrail eventName=CreateAccessKey
    (userIdentity.arn="<actor_arn>" OR requestParameters.userName="<target_username>")
    earliest=<containment_timestamp> latest=now
```

Expected result: 0 events (or only events from authorized recovery actions below).

### 1.3 Actor credentials are still inactive

```bash
aws iam list-access-keys \
  --user-name "<actor_username>" \
  --output json
```

Confirm all actor keys are `Inactive` or have been deleted per post-incident decisions.

### 1.4 Confirm no additional backdoors were planted

Run a broader sweep for IAM account manipulation actions in the window from initial access to containment:

```spl
index=aws_cloudtrail
    (eventName=CreateAccessKey OR eventName=CreateLoginProfile
     OR eventName=UpdateLoginProfile OR eventName=AddUserToGroup
     OR eventName=AttachUserPolicy OR eventName=CreatePolicyVersion
     OR eventName=SetDefaultPolicyVersion OR eventName=CreateUser
     OR eventName=CreateRole)
    earliest=<initial_access_timestamp> latest=<containment_timestamp>
    NOT userIdentity.arn="<authorized_recovery_actor>"
| table _time, eventName, userIdentity.arn, requestParameters, sourceIPAddress
```

Investigate every hit. Any unexpected IAM modification may be a secondary persistence mechanism.

---

## 2. Delete the Backdoor Key (Post-Confirmation)

Once the threat is confirmed removed and forensic evidence is preserved, delete the backdoor key. This requires documented approval (see `containment.md`).

```bash
aws iam delete-access-key \
  --user-name "<target_username>" \
  --access-key-id "<new_key_id>"
```

Confirm deletion:

```bash
aws iam list-access-keys \
  --user-name "<target_username>" \
  --output json
```

The deleted key ID should no longer appear in the list.

---

## 3. Restore Normal Operations

### 3.1 Remove the quarantine policy from the target user

Only after confirming no backdoors remain:

```bash
aws iam delete-user-policy \
  --user-name "<target_username>" \
  --policy-name "CDET-002-Quarantine"
```

Verify the user's effective permissions are back to baseline:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::<account_id>:user/<target_username>" \
  --action-names "s3:GetObject" "iam:CreateAccessKey" \
  --output json
```

### 3.2 Rotate the target user's existing legitimate keys (if any)

Even if the legitimate keys were not directly used in the attack, key rotation is advisable after a confirmed incident:

```bash
# Create a new key for the target user (requires coordination with the service owner)
aws iam create-access-key \
  --user-name "<target_username>" \
  --output json

# Update the application/service configuration with the new key
# (coordinate with service owner — do not hardcode the key)

# After the application is confirmed working with the new key, delete the old one
aws iam delete-access-key \
  --user-name "<target_username>" \
  --access-key-id "<old_legitimate_key_id>"
```

### 3.3 Remove the role session-revocation policy (if applied)

If you attached a deny policy to the actor's role in containment step 3:

```bash
aws iam delete-role-policy \
  --role-name "<compromised_role_name>" \
  --policy-name "DenyAllBefore-CDET-002-Incident"
```

Confirm legitimate role users can operate normally by checking for `AccessDenied` errors in the 5 minutes following removal:

```spl
index=aws_cloudtrail errorCode=AccessDenied
    userIdentity.sessionContext.sessionIssuer.arn="arn:aws:iam::<account_id>:role/<role_name>"
    earliest=-10m
```

---

## 4. Hardening Recommendations

Address the root cause and reduce future attack surface. Prioritize by effort and impact.

### 4.1 Enforce IAM permission boundaries

Apply a permission boundary to IAM users and roles that limits the ability to call `iam:CreateAccessKey` to only the specific user's own account (self-service rotation only):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCreateAccessKeyOnlySelf",
      "Effect": "Allow",
      "Action": "iam:CreateAccessKey",
      "Resource": "arn:aws:iam::<account_id>:user/${aws:username}"
    },
    {
      "Sid": "DenyCreateAccessKeyForOthers",
      "Effect": "Deny",
      "Action": "iam:CreateAccessKey",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "iam:ResourceTag/Owner": "${aws:username}"
        }
      }
    }
  ]
}
```

Attach this as a managed permission boundary. Consult your IAM architecture before broad deployment.

### 4.2 Enforce MFA for sensitive IAM actions

Add an SCP (Service Control Policy) or IAM policy condition that requires MFA for `iam:CreateAccessKey` when the actor is not a federated automation role:

```json
{
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

### 4.3 Enable IAM Access Analyzer

If not already enabled:

```bash
aws accessanalyzer create-analyzer \
  --analyzer-name "CDET-002-PostIncident-Analyzer" \
  --type ACCOUNT \
  --output json
```

This surfaces overly permissive policies and external access grants that may represent additional persistence paths.

### 4.4 Add AWS Config rule for key age monitoring

Ensure a Config rule monitors for access keys older than 90 days:

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "access-keys-rotated",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "ACCESS_KEYS_ROTATED"
    },
    "InputParameters": "{\"maxAccessKeyAge\": \"90\"}"
  }'
```

### 4.5 Review and tighten the actor's permissions

Determine how the actor obtained `iam:CreateAccessKey` permission for other users. Apply least privilege — most roles should only be able to create keys for themselves. Audit any policy granting `iam:CreateAccessKey` on `Resource: "*"`:

```bash
aws iam get-account-authorization-details \
  --filter "LocalManagedPolicy" "AWSManagedPolicy" \
  --output json \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('Policies', []):
    for v in p.get('PolicyVersionList', []):
        if v.get('IsDefaultVersion'):
            doc = v['Document']
            for s in doc.get('Statement', []):
                if s.get('Effect') == 'Allow' and 'iam:CreateAccessKey' in str(s.get('Action', '')):
                    print(p['PolicyName'], s)
"
```

---

## 5. Detection Tuning Recommendations

### 5.1 If this was a false positive — add suppression

If the actor is a legitimate automation pipeline not yet in the allowlist:

1. Add the actor ARN to `splunk/lookups/trusted_automation_roles.csv`.
2. If the target is a known service account with scheduled key rotation, add it to `splunk/lookups/service_accounts.csv` with `rotation_permitted=true`.
3. Update the CDET-002 detection in Splunk to apply the lookup at eval time:
   ```spl
   | lookup trusted_automation_roles.csv actor_arn AS userIdentity.arn OUTPUT is_trusted
   | where isnull(is_trusted) OR is_trusted != "true"
   ```

### 5.2 If this was a true positive — add enrichment

Enrich the detection with additional context to reduce triage time on future alerts:

- Add a lookup join to surface the target user's attached policies at alert time.
- Add a real-time lookup against `threat_intel_ips.csv` on `sourceIPAddress`.
- Add a notable event field: `cross_user_creation` = 1 when actor username != target username.
- Consider a higher base severity (critical) when `userIdentity.type = Root`.

### 5.3 Consider a companion detection

Add a detection for the immediate follow-on action — first use of a newly created access key within 15 minutes of `CreateAccessKey`:

```spl
index=aws_cloudtrail eventName=CreateAccessKey
| eval new_key=responseElements.accessKey.accessKeyId
| join new_key [
    search index=aws_cloudtrail
    | eval new_key=userIdentity.accessKeyId
    | where _time > relative_time(now(), "-15m")
  ]
| stats count by new_key, userIdentity.userName, sourceIPAddress
```

---

## 6. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Timeline documented end-to-end from initial access to containment in the incident ticket.
- [ ] Root cause identified: How did the actor obtain IAM write permissions? Was this a compromised key, exposed credential, or insider threat?
- [ ] All evidence artifacts (CloudTrail JSON, Splunk exports, AWS CLI outputs) attached to the incident ticket.
- [ ] Backdoor key confirmed deleted and no longer in `list-access-keys` output.
- [ ] Actor credentials confirmed deprovisioned or rotated.
- [ ] Target user permissions reviewed and tightened as needed.
- [ ] Hardening recommendations from section 4 prioritized and assigned to owners with due dates.
- [ ] Detection tuning recommendations from section 5 implemented or tracked in the backlog.
- [ ] Lookup CSVs updated to reflect any new trusted actors or service accounts.
- [ ] Lessons learned documented and shared with the team (15-minute sync recommended for confirmed true positives).
- [ ] If data exfiltration occurred: Legal, Compliance, and affected data owners notified per the data breach notification policy.
- [ ] CDET-002 alert volume and false-positive rate reviewed against the 30-day baseline post-tuning.
