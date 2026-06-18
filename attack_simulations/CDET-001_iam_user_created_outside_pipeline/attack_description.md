# CDET-001 — IAM User Created Outside Approved Pipeline

## Technique
**Tactic:** Persistence  
**MITRE Technique:** T1136.003 — Create Account: Cloud Account  
**Severity:** High | Risk Score: 60

---

## Threat Actor Perspective

### Why Attackers Create Backdoor IAM Users

When an adversary gains initial access to an AWS environment — through phishing, credential stuffing, a compromised CI/CD pipeline, or a misconfigured role — their first priority is to establish durable persistence before the initial foothold is discovered and revoked. Creating a new IAM user is one of the most effective persistence mechanisms available because:

1. **Credential independence**: A newly created IAM user has its own access keys and console password that are entirely independent of the compromised credential used to create them. Even if the victim's security team rotates all known credentials, the backdoor user survives.
2. **Blends into legitimate infrastructure**: Every AWS account has IAM users. A single additional user is easy to miss during a fast-moving incident response without dedicated IAM baseline alerting.
3. **Full control over the credential lifecycle**: The attacker controls when keys are created, rotated, or deleted — they are not at the mercy of the victim's key rotation policy.

### How Attackers Avoid Detection

Sophisticated adversaries apply several evasion techniques when creating backdoor users:

**Naming conventions that blend in**  
Attackers research the target organization's IAM naming scheme before acting. If existing service accounts follow patterns like `svc-deploy-prod` or `app-monitoring-role`, the backdoor user will be named similarly — e.g., `svc-backup-agent` or `app-health-check`. Human reviewers skimming a user list will not notice the addition. Automated detections that lack a naming allowlist will fire on any new user, but many organizations do not have such detections deployed.

**Avoiding MFA enrollment**  
Enrolling a virtual MFA device generates an `EnableMFADevice` CloudTrail event and requires the attacker to control a TOTP device. Attackers typically skip MFA enrollment to avoid the additional event noise and operational complexity. This is actually a secondary detection signal: a console-enabled user without MFA is anomalous in security-mature environments.

**Timing during change windows**  
Many organizations suppress or de-prioritize alerts during declared change windows (e.g., Friday evening deployments). Attackers with access to internal communication channels (Slack, email) will time IAM changes to coincide with these windows, relying on alert fatigue and suppression rules to let the event pass unnoticed.

**Low initial privilege followed by escalation**  
To reduce the signal strength of the creation event, attackers may initially create the user with no permissions at all, then attach policies in a separate step hours or days later (potentially from a different IP or session). This separates the "user creation" event from the "privilege grant" event in time, making correlation harder.

### Evasion Variations

**Adding user to existing groups (preferred)**  
Attaching a user to an existing group (e.g., `Developers`, `Admins`) via `AddUserToGroup` is less conspicuous than directly attaching a managed policy because:
- The `AttachUserPolicy` event does not fire — only `AddUserToGroup` fires
- The permissions are inherited rather than explicitly granted, which can confuse manual IAM reviews
- If the group already has broad permissions, the attacker gains them without any explicit policy attachment event

**Direct policy attachment (faster, noisier)**  
Attaching `AdministratorAccess` directly via `AttachUserPolicy` is fast and grants immediate full access, but generates a high-fidelity detection event. This approach is used when speed matters more than stealth — for example, during a destructive attack where the adversary knows they have a narrow window.

**Inline policy attachment (stealthiest)**  
Using `PutUserPolicy` to attach an inline policy avoids the managed policy ARN appearing in CloudTrail's `requestParameters.policyArn` field. Inline policies do not appear in `aws iam list-attached-user-policies` — a defender must call `aws iam list-user-policies` separately. This increases the chance that a manual investigation will miss the privilege grant.

### Attack Chain Context

This technique commonly appears as step 2 or 3 in an AWS attack chain:
1. **Initial Access**: Compromised access key, phished console credentials, or SSRF to IMDS
2. **Persistence** (this technique): Create backdoor IAM user with console access or access keys
3. **Privilege Escalation**: Attach admin policy or add to admin group
4. **Defense Evasion**: Disable CloudTrail, delete logs (CDET-003)
5. **Impact/Exfiltration**: Data theft, resource abuse, ransomware

---

## Detection Context (CDET-001)

The CDET-001 detection rule fires on `CreateUser` events from CloudTrail. The key detection logic flags users created by principals that are not part of the approved automation pipeline (e.g., not `arn:aws:iam::*:role/PipelineRole`). This detection has a low false positive rate in environments with mature IaC pipelines, but higher rates in organizations that still manage IAM manually.

**Key signal**: `eventName = CreateUser` where `userIdentity.arn` does not match approved pipeline roles.
