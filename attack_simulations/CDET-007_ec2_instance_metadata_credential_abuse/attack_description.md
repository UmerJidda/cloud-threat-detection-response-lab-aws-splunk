# CDET-007 — EC2 Instance Metadata Credential Abuse

## Technique
**Tactic:** Credential Access  
**MITRE Technique:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API  
**Severity:** Critical | Risk Score: 85

---

## Threat Actor Perspective

### The Instance Metadata Service (IMDS)

Every EC2 instance in AWS has access to a local metadata service at the non-routable IP address `169.254.169.254`. This service provides instance-specific data including the current region, instance ID, network configuration, and — critically — **temporary AWS credentials for any IAM role attached to the instance**.

The metadata service is accessible from any process running on the EC2 instance. There is no authentication beyond being on the instance. The credentials endpoint is:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

### IMDSv1 vs IMDSv2: The Core Vulnerability

**IMDSv1 (the vulnerable version):**
- No session token required
- Any process can make a simple `GET` request to retrieve credentials
- Accessible via `curl http://169.254.169.254/...` with no additional setup
- The primary attack vector for Server-Side Request Forgery (SSRF) exploits

**IMDSv2 (the hardened version):**
- Requires a PUT request to get a session token first
- The PUT request has a configurable TTL (1-21600 seconds)
- SSRF attacks typically cannot complete the two-step token request
- Enforced by setting `HttpTokens=required` on the instance

**Why IMDSv1 is dangerous**: Many web applications have SSRF vulnerabilities (e.g., URL fetching features, PDF renderers, webhooks) that allow an attacker to make HTTP requests from the server's perspective. With IMDSv1, a single `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole` request (which a SSRF vulnerability can make) immediately returns valid AWS credentials.

### How Stolen IMDS Credentials Work Outside AWS

The credentials returned by IMDS are temporary `AssumedRole` credentials with three components:
```json
{
    "AccessKeyId": "ASIAXXXXXXXXXXXXXXXXX",
    "SecretAccessKey": "...",
    "Token": "...",
    "Expiration": "2026-06-16T12:00:00Z"
}
```

These credentials can be used **from any machine on the internet** — they are standard AWS API credentials. The key insight is that when AWS validates these credentials, it records the API call under the **assumed role's identity**, but the `sourceIPAddress` in the CloudTrail event will be the external attacker's IP, not the EC2 instance's IP.

### The Detection Signal: External Source IP

Normal usage of EC2 instance role credentials should only ever originate from:
- The EC2 instance's private IP address
- AWS service IP ranges (for service-to-service calls)

When credentials stolen from IMDS are used on an external machine, the CloudTrail `sourceIPAddress` will be an IP address that is **not** the EC2 instance's IP. This is the primary detection signal for CDET-007.

The credential type also reveals the origin:
- Access keys starting with `AKIA` are long-term IAM user keys
- Access keys starting with `ASIA` are temporary assumed-role credentials
- Instance role credentials always start with `ASIA` (AssumedRole keys)

### Why the AssumedRole Session Token Matters

The `Token` field (session token) is required when using temporary credentials. It is cryptographically bound to the `AccessKeyId` and cannot be separated. When an attacker uses stolen IMDS credentials:
- They must provide all three values: `AccessKeyId`, `SecretAccessKey`, `Token`
- AWS validates the session token against the originating account and role
- The credentials expire (typically within 1-6 hours, configurable by the role's max session duration)

After expiration, the attacker must re-steal credentials from IMDS — requiring continued access to the EC2 instance.

### GuardDuty: InstanceCredentialExfiltration Finding

AWS GuardDuty specifically detects this attack pattern as `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`. GuardDuty compares:
1. The `sourceIPAddress` of API calls using instance role credentials
2. The known IP addresses of the EC2 instance that was assigned the role

When these don't match (especially when the source IP is an ASN not belonging to AWS), GuardDuty fires a HIGH severity finding. This is one of the most reliable GuardDuty findings because false positives are extremely rare.

**Finding type**: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`  
**Severity**: High (7.0–8.9)

### Attack Execution Flow

```
1. Adversary compromises application running on EC2 instance
   (via SSRF, RCE, misconfigured app, compromised dependency)
   
2. From the compromised application context:
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
   → Returns role name: "MyApplicationRole"
   
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyApplicationRole
   → Returns: AccessKeyId, SecretAccessKey, Token, Expiration
   
3. Adversary exfiltrates these three values to their external machine
   
4. On external machine (outside AWS):
   export AWS_ACCESS_KEY_ID=ASIA...
   export AWS_SECRET_ACCESS_KEY=...
   export AWS_SESSION_TOKEN=...
   aws sts get-caller-identity  → confirms access
   aws s3 ls  → data enumeration begins
   
5. CloudTrail records all external API calls with:
   - userIdentity.arn: arn:aws:sts::ACCOUNT:assumed-role/MyApplicationRole/i-...
   - sourceIPAddress: ATTACKER_EXTERNAL_IP (not the EC2 instance IP)
```

---

## Detection Context (CDET-007)

The CDET-007 detection joins CloudTrail events where:
1. `userIdentity.type = "AssumedRole"` AND
2. `userIdentity.sessionContext.sessionIssuer.type = "Role"` AND
3. The role was originally assigned via an EC2 instance profile AND
4. `sourceIPAddress` does not match the EC2 instance's known IP addresses

The detection relies on an EC2 instance IP lookup table (`ec2_instance_ips.csv`) for the IP comparison. Without an up-to-date lookup table, this detection can only flag externally routable IPs (non-RFC1918 addresses) used with instance role credentials.
