# CDET-002 — IAM Access Key Created for Existing User

## Technique
**Tactic:** Persistence  
**MITRE Technique:** T1098.001 — Account Manipulation: Additional Cloud Credentials  
**Severity:** High | Risk Score: 72

---

## Threat Actor Perspective

### Why Adding Credentials to Existing Accounts Is Stealthier Than Creating New Users

After establishing initial access, sophisticated adversaries prefer to add programmatic credentials to an *existing* IAM account rather than creating a new user. This approach offers several advantages that make detection and investigation harder:

**1. No new IAM principal is created**  
The `CreateUser` event that CDET-001 detects does not fire. There is no new user in `aws iam list-users`. A quick IAM audit will show the same user count as before. Incident responders focused on "what changed" may overlook a new access key on a pre-existing user account.

**2. Credentials survive credential rotation for the original user**  
If an organization's incident response procedure is to "rotate the compromised user's credentials," they will generate new keys for the original user — but the attacker's backdoor key may not be identified for rotation if the IR team does not enumerate *all* keys for *all* users. IAM access keys are per-user, not per-account, and many organizations have no automated key inventory.

**3. Access keys persist through account investigations**  
Unlike console passwords (which an org may reset company-wide via SSO), programmatic access keys are not touched by most identity provider resets. If the organization uses a federated identity provider (Okta, Azure AD) for console access but IAM users for programmatic access, those IAM access keys are a separate credential store that may be overlooked.

**4. Attribution confusion**  
Subsequent API calls from the new access key will appear in CloudTrail under the original user's identity — `userIdentity.userName = "alice"` — not under a new suspicious username. Without per-key tracking in SIEM correlations, the activity appears to be the legitimate user acting normally.

### Identifying High-Value Targets

Before creating the backdoor key, attackers enumerate existing users to identify the highest-value targets:

**Admin users and power users**  
```bash
aws iam list-users
aws iam list-attached-user-policies --user-name TARGET
aws iam list-user-policies --user-name TARGET
```
A user with `AdministratorAccess` or `PowerUserAccess` attached is the ideal target — adding a key to them grants immediate full access without any additional privilege escalation steps.

**Service accounts with broad permissions**  
Service accounts (CI/CD runners, data pipeline users, monitoring agents) often have overly broad permissions due to "just works" policy design. They also tend to have less scrutiny — a new key on `svc-deploy-prod` may not trigger a review because service account key rotation is a normal operational event.

**Dormant users with residual permissions**  
Users with no recent activity (AWS Access Advisor data) but still-active high-privilege policies are ideal targets. The account is unlikely to be actively monitored, and a new key on it may go unnoticed.

### The "Self-Rotation" Pattern That Evades Detection

Some organizations configure alerts for `CreateAccessKey` events where `userIdentity.userName != requestParameters.userName` — i.e., *someone creating a key for a different user*. Attackers can evade this by first compromising the target user's credentials, then creating a new key *as that user* (self-rotation). In this case:
- `userIdentity.userName` = `alice` (the target)
- `requestParameters.userName` = `alice` (also the target)
- The event looks identical to a legitimate self-rotation

To detect this, organizations need behavioral baselines — "has this user created an access key in the last 90 days?" — rather than simple caller-vs-target comparisons.

### Key Rotation Timing

Access keys created during a business-hours change window, coinciding with a legitimate deployment or infrastructure rotation event, benefit from:
- Higher alert volume reducing SOC attention per alert
- Change management tickets that can be cited as justification if the event is investigated
- The attacker's key appearing alongside legitimate key rotation events in the same time window

---

## Detection Context (CDET-002)

The CDET-002 detection fires on `CreateAccessKey` events where:
1. The creating principal differs from the user receiving the key (`userIdentity.userName != requestParameters.userName`), OR
2. The target user has an admin-level policy attached

The detection has a higher false positive rate in orgs where centralized IAM teams manage access keys on behalf of users. The `requestParameters.userName` field is the key signal.
