# CDET-006 — Root Account Activity

## Technique
**Tactic:** Initial Access  
**MITRE Technique:** T1078.004 — Valid Accounts: Cloud Accounts  
**Severity:** Critical | Risk Score: 88

---

## Threat Actor Perspective

### Why Root Account Access Is Always a Critical Signal

The AWS root account is the master identity for an AWS account. It is created when the account is opened and is identified by the account's email address rather than an IAM username. Unlike any IAM user or role, the root account:

1. **Cannot be restricted by IAM policies, SCPs, or permissions boundaries** — any SCP (Service Control Policy) that applies to the entire account does not apply to root. An adversary using the root account can bypass all IAM restrictions.
2. **Is outside the normal IAM principal namespace** — root does not appear in `aws iam list-users`. Its CloudTrail entries have `userIdentity.type = "Root"` rather than `"IAMUser"` or `"AssumedRole"`.
3. **Has permanent, irrevocable capabilities** that no IAM principal can perform, even with AdministratorAccess.

### Capabilities Exclusive to Root

Root can perform actions that no IAM policy can grant to IAM principals:

| Capability | Why It Matters for Attackers |
|------------|------------------------------|
| Close the AWS account | Destroys all resources — ultimate destructive action |
| Change the root email address and password | Permanently locks out the legitimate owner |
| Remove the root account's MFA device | Can be used to lock out the security team |
| Restore access to an S3 bucket with a full-deny bucket policy | Bypasses data protection controls |
| Enable/disable CloudTrail (via console) | Defense evasion |
| Create a support plan | Potentially used for social engineering |
| View/download tax invoices and billing history | Intelligence gathering |
| Activate IAM access to billing | Attacker can grant billing access to IAM principals |

An adversary who controls the root account can perform any of these actions, creating a recovery scenario that may require AWS support involvement.

### Common Root Usage Scenarios

**Legitimate root usage:**
- Initial account setup (before IAM users are created)
- Recovering from a lockout where IAM admin access is lost
- Tasks that legally require root (account closure, changes to root email)
- Enabling IAM access to billing information (a one-time setup step)
- CloudFront key pair management (older workloads)

These are all rare events. In a well-managed account, root may not log in for months or years. Any root activity should therefore be treated as anomalous and require immediate investigation.

**Adversary root usage scenarios:**

*Scenario 1: Root credential compromise via account takeover*  
The attacker compromises the email address used to register the AWS account (often a shared mailbox or a personal email address), requests a password reset for root, and logs in. This is possible if:
- The root email account lacks MFA
- The root email is a shared/group mailbox with broad access
- The AWS account was registered with a personal email that was later compromised

*Scenario 2: MFA bypass or theft*  
If the root MFA token is stored insecurely (screenshot of QR code in email, backup codes stored in a shared drive), an attacker can gain root access by stealing the MFA seed alongside the password.

*Scenario 3: Social engineering to AWS support*  
AWS support has processes for account recovery when MFA is lost. An attacker with access to the root email can potentially use these processes to remove MFA from the root account.

*Scenario 4: Insider threat or admin abuse*  
An administrator with access to the root credentials (e.g., credentials stored in a password manager the admin controls) can use root to take actions that would be logged under their own IAM identity — attributing the actions to "root" rather than to their personal account.

### The Narrow Detection Window Problem

Root activity detection has a unique challenge: if the attacker uses root to *disable CloudTrail* as the first action, the `StopLogging` event will be recorded (CloudTrail records its own disabling), but the subsequent root actions will not be. The detection window between root login and CloudTrail disabling may be very short.

**Mitigation**: AWS GuardDuty's `RootCredentialUsage` finding and CloudWatch Alarms on root login events (via CloudTrail's CloudWatch Logs integration) provide near-real-time alerting independent of the S3-based CloudTrail delivery pipeline.

### What Root Can Do That IAM Cannot (Billing Focus)

One overlooked aspect: root can view and modify billing, payment methods, and account settings. An attacker using root can:
- Increase service limits to enable large-scale resource abuse
- Modify billing alerts to prevent cost-based anomaly detection
- Change the account name and contact information
- Remove MFA protection from the billing console

---

## Detection Context (CDET-006)

The CDET-006 detection fires on **any** CloudTrail event where `userIdentity.type = "Root"`. This includes:
- `ConsoleLogin` — root logged into the AWS Console
- Any API call — root called any AWS API

Unlike other detections, there is **no false positive threshold** — any root activity is considered critical and requires immediate investigation. The acceptable false positive rate is zero; organizations should have root activity suppressed in production to the point where any alert is a real incident.
