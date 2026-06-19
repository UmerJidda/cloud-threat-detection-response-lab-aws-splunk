---
detection_id: CDET-002
detection_name: Access Key Created for Another User
tactic: Persistence
technique: T1098.001
last_updated: 2026-06-18
---

# CDET-002 — Triage Playbook
# Access Key Created for Another User

**Estimated time:** 5–10 minutes  
**Goal:** Determine whether this alert is a genuine persistence attempt or a benign/FP event before escalating.

---

## 1. Pull the Raw Alert

Retrieve the triggering CloudTrail event from Splunk. Confirm the following fields are present and non-null:

| Field | Expected format |
|---|---|
| `eventName` | `CreateAccessKey` |
| `eventSource` | `iam.amazonaws.com` |
| `userIdentity.type` | `IAMUser`, `AssumedRole`, or `Root` |
| `userIdentity.arn` | ARN of the **actor** (who performed the action) |
| `requestParameters.userName` | Username of the **target** (whose key was created) |
| `sourceIPAddress` | Should not be an AWS service CIDR unless automation is expected |
| `userAgent` | Check for CLI / SDK strings vs. console |
| `responseElements.accessKey.accessKeyId` | The newly created key ID (`AKIA...`) |
| `errorCode` | Should be absent (success); if present, downgrade urgency |

---

## 2. Validate the Alert is Real (Not Test Data / Pipeline Noise)

1. Confirm `eventTime` is within the last 24 hours and not a replayed or ingested test event.
2. Check that `recipientAccountId` matches a production account, not a sandbox/dev account listed in `splunk/lookups/aws_accounts.csv`.
3. Verify `userIdentity.arn` is **not** in `splunk/lookups/trusted_automation_roles.csv` — these are known CI/CD or provisioning actors that legitimately create keys as part of their pipeline.
4. Verify `requestParameters.userName` is **not** in `splunk/lookups/service_accounts.csv` with a flag indicating scheduled key rotation is permitted.
5. If `userAgent` contains `aws-sdk-go`, `Terraform`, `CloudFormation`, or `aws-cdk`, cross-reference with the automation allowlist before proceeding.

---

## 3. Self-/Cross-Account Check

Answer the critical triage question: **Did the actor create a key for themselves or for a different user?**

- `actor_arn` = `userIdentity.arn`
- `target_username` = `requestParameters.userName`

```
actor_username = extract the short username from actor_arn
```

- If `actor_username == target_username` → self-rotation; lower urgency, but still verify.
- If `actor_username != target_username` → **cross-user key creation**; treat as high severity and continue triage.
- If actor is `Root` → **immediate escalation required regardless of target**.

---

## 4. Urgency Determination

Ask these questions in order:

1. **Is the actor a known privileged role or admin?**  
   Check `splunk/lookups/privileged_iam_roles.csv`. If yes, the blast radius is higher — escalate.

2. **Has the target account shown any anomalous activity in the last 60 minutes?**  
   Quick Splunk check:
   ```spl
   index=aws_cloudtrail userIdentity.userName="<target_username>" earliest=-60m
   | stats count by eventName
   ```
   If you see `AssumeRole`, `GetCallerIdentity`, `ListBuckets`, or console sign-in — escalate immediately.

3. **Is the newly created key ID already appearing in other CloudTrail events?**  
   ```spl
   index=aws_cloudtrail userIdentity.accessKeyId="<new_key_id>" earliest=-15m
   ```
   Active use of a brand-new key is a critical indicator — escalate immediately.

4. **Does the source IP appear in threat intelligence lookups?**  
   Check `splunk/lookups/threat_intel_ips.csv`. Any match → escalate immediately.

---

## 5. Lookup CSVs to Reference

| Lookup file | Purpose |
|---|---|
| `splunk/lookups/aws_accounts.csv` | Classify account as prod / staging / dev / sandbox |
| `splunk/lookups/trusted_automation_roles.csv` | Known CI/CD and provisioning actors |
| `splunk/lookups/service_accounts.csv` | Service accounts with permitted key rotation schedules |
| `splunk/lookups/privileged_iam_roles.csv` | High-privilege roles that require extra scrutiny |
| `splunk/lookups/threat_intel_ips.csv` | Known malicious IP ranges |

---

## 6. PASS / FAIL Criteria

### PASS — Likely Benign / False Positive

All of the following must be true:
- Actor ARN is in `trusted_automation_roles.csv` **or** target is in `service_accounts.csv` with rotation flag set.
- Source IP is an expected internal/AWS CIDR with no threat-intel hits.
- No anomalous downstream activity on the target account within the last 60 minutes.
- No active use of the newly created key ID detected.
- Account is dev/sandbox per `aws_accounts.csv`.

**Action:** Document findings, close as FP, and tune suppression if this fires repeatedly (see `recovery.md`).

### FAIL — Treat as Real Alert

Any one of the following:
- Actor is not a known automation role and created a key for a different user.
- Actor is `Root`.
- Source IP has threat-intel hits.
- Newly created key is already being used.
- Target account shows active post-creation activity.
- Account is production.

**Action:** Proceed immediately to `investigation.md`. Do not attempt containment before completing investigation unless the key is actively being used, in which case disable the key first (see `containment.md` step 1).

---

## 7. Escalation

If this is a **FAIL**, page the on-call Tier-3 / Cloud Security Engineer and include:
- Alert link / event ID
- Actor ARN and source IP
- Target username and new key ID (`AKIA...`)
- Any active-use evidence found in step 4.3
