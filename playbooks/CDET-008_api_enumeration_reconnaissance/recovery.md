---
detection_id: CDET-008
detection_name: API Enumeration Reconnaissance
tactic: Discovery
technique: T1580
last_updated: 2026-06-18
---

# CDET-008 — API Enumeration Reconnaissance: Recovery

**Role: Tier-2 SOC Analyst**
**Prerequisites: Containment complete, IR Manager sign-off obtained**

---

## 1. Restore Normal Operations

Perform these steps only after IR Manager confirms containment is complete and the threat is neutralized.

### 1a. Issue New Credentials for the Affected Identity

```bash
# Create a new access key for the IAM user (if the old key was disabled/deleted)
aws iam create-access-key \
    --user-name <USERNAME> \
    --profile <recovery-profile>
# Securely deliver the new key to the user via your approved secrets delivery method

# If a role session revocation policy was applied, remove it
aws iam delete-role-policy \
    --role-name <ROLE_NAME> \
    --policy-name CDET008_EmergencyRevoke \
    --profile <recovery-profile>
```

### 1b. Delete the Compromised Access Key (After New Key Is Confirmed Working)

```bash
aws iam delete-access-key \
    --user-name <USERNAME> \
    --access-key-id <OLD_KEY_ID> \
    --profile <recovery-profile>
```

### 1c. Remove Temporary NACL Rules

```bash
aws ec2 delete-network-acl-entry \
    --network-acl-id <NACL_ID> \
    --rule-number 1 \
    --ingress \
    --region <REGION> \
    --profile <recovery-profile>
```

### 1d. Confirm Application Services Are Healthy

- Verify that any services using the affected role or user credentials are responding normally (health checks, CloudWatch alarms).
- Confirm that rotated secrets have been consumed by dependent applications (check for `SecretsManager:GetSecretValue` calls from expected application principals).

---

## 2. Verify the Threat Has Been Fully Removed

Run the following Splunk query to confirm no further enumeration activity from the same actor or source IP since containment was applied:

```splunk
index=aws_cloudtrail
    (userIdentity.arn="<ACTOR_ARN>" OR sourceIPAddress="<SOURCE_IP>")
    eventName IN ("Describe*","List*","Get*")
    earliest=<CONTAINMENT_TIMESTAMP> latest=now
| table _time, userIdentity.arn, sourceIPAddress, eventSource, eventName, errorCode
| sort _time
```

Expected result: zero events, or only events from known pipeline actors with the same ARN (verify individually).

Also confirm no `AssumeRole` calls succeeded from the compromised key after containment:

```splunk
index=aws_cloudtrail
    userIdentity.accessKeyId="<OLD_KEY_ID>"
    eventName="AssumeRole"
    earliest=<CONTAINMENT_TIMESTAMP>
| table _time, eventName, requestParameters, errorCode
```

Expected result: zero successful `AssumeRole` calls.

---

## 3. Hardening Steps to Prevent Recurrence

### 3a. Enforce Least-Privilege on the Affected Role/User

Review the permissions granted to the compromised identity and remove any unnecessary read-heavy policies:

```bash
# Simulate what actions the current policy allows
aws iam simulate-principal-policy \
    --policy-source-arn <ROLE_OR_USER_ARN> \
    --action-names "iam:ListRoles" "s3:ListBuckets" "ec2:DescribeInstances" \
    --profile <recovery-profile>

# Review and remove overly broad managed policies
aws iam detach-role-policy \
    --role-name <ROLE_NAME> \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess \
    --profile <recovery-profile>
# Replace with a custom policy scoped to only the services the role requires
```

### 3b. Enable MFA Delete and MFA Requirements for Sensitive APIs

If the compromised identity was an IAM user, enforce MFA for sensitive read operations via condition keys:

```json
{
  "Effect": "Deny",
  "Action": [
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters"
  ],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```

### 3c. Apply Service Control Policies to Restrict Enumeration at Scale

Work with the Security Architect to evaluate adding an SCP that limits cross-service enumeration from non-production roles:

```json
{
  "Effect": "Deny",
  "Action": [
    "iam:SimulatePrincipalPolicy",
    "iam:SimulateCustomPolicy",
    "iam:GenerateServiceLastAccessedDetails"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalTag/role-type": "security"
    }
  }
}
```

### 3d. Enable AWS IAM Access Analyzer

If not already active, enable Access Analyzer to continuously monitor for overly permissive policies:

```bash
aws accessanalyzer create-analyzer \
    --analyzer-name "CDET008-PostIncident-Analyzer" \
    --type ACCOUNT \
    --region <REGION> \
    --profile <recovery-profile>
```

### 3e. Enforce CloudTrail in All Regions

Confirm that CloudTrail multi-region logging is active and cannot be disabled by non-security principals:

```bash
aws cloudtrail describe-trails \
    --include-shadow-trails \
    --profile <recovery-profile> \
    | jq '.trailList[] | {Name, IsMultiRegionTrail, LogFileValidationEnabled, HomeRegion}'
```

All trails should show `"IsMultiRegionTrail": true` and `"LogFileValidationEnabled": true`.

---

## 4. Detection Tuning Recommendations

### 4a. Suppression (for Recurring FP Patterns)

If the investigation confirmed a specific pipeline role is repeatedly triggering CDET-008 during deployment windows:

1. Add the role ARN to `splunk/lookups/known_service_accounts.csv` with a `suppression_reason` column entry.
2. Add a Splunk alert exception:
   ```splunk
   | inputlookup known_service_accounts.csv
   | where suppression_reason="deployment_pipeline"
   ```
3. Scope the exception tightly: ARN + source IP range + time window (do NOT create open-ended suppression by ARN alone).
4. Set an expiry review date of 90 days on the suppression rule.

### 4b. Enrichment (to Reduce Investigation Time)

Add the following enrichment lookups to the CDET-008 alert to surface context faster:

- Join `userIdentity.accessKeyId` against a key-age lookup to flag keys older than 90 days automatically.
- Add ASN/geolocation lookup on `sourceIPAddress` inline in the alert.
- Add `userAgent` classification field: map known tool strings (pacu, scoutsuite, enumerate-iam) to a `recon_tool_detected: true` flag.

### 4c. Threshold Tuning

If the current burst threshold (20 events / 5 min) generates excessive noise:

- Analyze 30 days of baseline data for the burst rate of known-good pipeline roles.
- Set the threshold at mean + 3 standard deviations for each role class (pipeline vs. human vs. service).
- Consider separate thresholds per `eventSource` (IAM enumeration is higher risk than EC2 enumeration).

---

## 5. Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Root cause documented: how were the credentials compromised or misused?
- [ ] Timeline of events reconstructed from first enumeration call to containment
- [ ] Data exposure impact assessed: which secrets/resources were accessed, sensitivity level determined
- [ ] Affected resource owners notified per your data breach notification policy
- [ ] Identity and access changes (key rotation, policy updates) confirmed in IAM audit
- [ ] Suppression or enrichment rules implemented and peer-reviewed
- [ ] CDET-008 detection logic reviewed: did it fire at the right time, or was there a delay?
- [ ] Lessons learned documented in incident ticket and shared with detection engineering team
- [ ] Hardening recommendations tracked in security backlog with assigned owner and due date
- [ ] Playbook gaps identified: update triage/investigation/containment/recovery docs if any step was unclear or missing
- [ ] Metrics recorded: MTTD (mean time to detect), MTTA (mean time to acknowledge), MTTC (mean time to contain)
