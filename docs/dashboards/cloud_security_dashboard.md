# Cloud Security Posture Dashboard — Documentation

**File:** `splunk/dashboards/cloud_security_dashboard.xml`
**Refresh:** 600 seconds (10 minutes)
**Theme:** Dark

## Purpose

The Cloud Security Posture Dashboard provides broad visibility into AWS CloudTrail telemetry, IAM privilege operations, external-origin API calls, GuardDuty threat findings, and SecurityHub critical alerts. Unlike the SOC Operations Dashboard (which is alert-focused), this dashboard is cloud-telemetry-focused — it shows what is happening in the AWS environment at the API level, regardless of whether a CDET detection fired. Use it to discover emerging attack surfaces, validate that expected data sources are present, and quickly answer the question "what has been happening in AWS today?"

## Intended Audience

- Tier-2 and Tier-3 analysts performing cloud threat hunting
- Cloud security engineers reviewing AWS security posture
- Detection engineers assessing coverage gaps
- Incident responders who need broad-telemetry context during an active investigation

## Refresh Strategy

The 10-minute refresh balances freshness against query cost. CloudTrail aggregation queries against a full 24-hour window are moderately expensive; 10-minute stale data is acceptable for posture visibility (contrast with the SOC Operations Dashboard at 5 minutes which handles live triage). The GuardDuty and SecurityHub panels use 7-day and 30-day windows respectively and are not time-critical.

## Dependencies

| Index | Sourcetype | Purpose |
|---|---|---|
| `aws_cloudtrail` | `aws:cloudtrail` | All panels in rows 1–3 |
| `aws_security` | `aws:guardduty` | GuardDuty Findings panel |
| `aws_security` | `aws:securityhub` | SecurityHub Critical Findings panel |

No lookup tables are required for this dashboard, but the External IP Activity panel implicitly relies on the absence of RFC-1918 prefixes to identify external addresses. If your environment uses non-standard internal CIDR ranges, the panel SPL must be extended.

---

## Panel Reference

### Panel 1 — CloudTrail Events by Service (Last 24h)

**Objective:** Show the distribution of API calls across AWS services so analysts can immediately see which services are most active. Unusual concentrations (e.g., EC2 dominating in an environment that primarily uses Lambda) are early signals worth investigating.

**SPL:**
```spl
index=aws_cloudtrail earliest=-24h
| stats count by eventSource
| sort -count
```

**Interpretation:**
- `iam.amazonaws.com` and `sts.amazonaws.com` making up a large fraction of calls warrants review — excessive IAM activity relative to compute can indicate credential harvesting or privilege escalation preparation.
- Services appearing here that your organization does not actively use (e.g., `glacier.amazonaws.com`, `route53domains.amazonaws.com`) may indicate attacker-initiated service exploration.
- The pie chart is best read by looking for slices that break your expected pattern, not by absolute values.

**Response Actions:**
- For an unexpected service appearing in the top 5: run `index=aws_cloudtrail eventSource="<service>" earliest=-24h | stats count by eventName userIdentity.arn | sort -count` to enumerate the specific operations and callers.
- Cross-reference with the Top Event Types panel (Panel 2) to see which specific API calls are driving the volume.

---

### Panel 2 — Top Event Types (Last 24h)

**Objective:** Identify the 20 most-called AWS API operations. This is the most granular posture signal — it answers "what are the most common things happening in AWS right now?"

**SPL:**
```spl
index=aws_cloudtrail earliest=-24h
| stats count by eventName
| sort -count
| head 20
| rename eventName AS "Event Name", count AS "Count"
```

**Interpretation:**
- Read/describe operations (`DescribeInstances`, `ListBuckets`, `GetCallerIdentity`) dominating the top 20 is normal for a well-monitored environment — monitoring agents and legitimate scanning generate a lot of these.
- Write/modify operations (`CreateUser`, `PutBucketPolicy`, `RunInstances`) appearing in the top 20 with unexpectedly high counts warrant immediate investigation.
- `AssumeRole` in the top 5 is worth reviewing: high volume can indicate credential cycling or automated role chaining that is masking the originating identity.

**Response Actions:**
- Click any event name row to pivot into all raw events for that API call over the last 24 hours.
- For unexpected high-count write events: add the event to the IAM High-Value Events timechart (Panel 4) by modifying the saved search to include it.
- If `ConsoleLogin` with `additionalEventData.MFAUsed=No` appears, check against CDET-002 (IAM MFA Disabled).

---

### Panel 3 — Activity by AWS Region (Last 24h)

**Objective:** Surface which AWS regions are receiving API calls, enabling rapid detection of unexpected region usage that may indicate attacker-controlled infrastructure.

**SPL:**
```spl
index=aws_cloudtrail earliest=-24h
| stats count by awsRegion
| sort -count
| rename awsRegion AS "AWS Region", count AS "Event Count"
```

**Interpretation:**
- Regions listed in `approved_regions.csv` with activity are expected. All other regions are anomalous.
- A region appearing with low event counts (e.g., 5–20 events) often indicates an attacker exploring or bootstrapping infrastructure — they tend to generate low noise before scaling up.
- `us-east-1` and `us-west-2` tend to dominate in US-centric environments; APAC or EU regions with unexpectedly high volume may indicate data exfiltration staging.

**Response Actions:**
- For unapproved region activity: run `index=aws_cloudtrail awsRegion="<region>" earliest=-24h | table _time eventName userIdentity.arn sourceIPAddress | sort -_time` to build a timeline.
- Report to the account owner and consider enabling GuardDuty in the new region immediately.
- Correlate with CDET-013 (Unauthorized Region Activity) alerts in the cdet_alerts index.

---

### Panel 4 — IAM High-Value Events (Last 7 Days)

**Objective:** Track the frequency of the highest-risk IAM API operations over a weekly window. These operations directly expand the attack surface: creating users, creating access keys, attaching policies, and modifying trust relationships.

**SPL:**
```spl
index=aws_cloudtrail earliest=-7d
  eventName IN (CreateUser, CreateAccessKey, AttachUserPolicy, UpdateAssumeRolePolicy,
                DeleteUser, DeleteAccessKey, DetachUserPolicy, PutUserPolicy,
                CreateRole, DeleteRole, AttachRolePolicy)
| timechart span=1h count by eventName
```

**Interpretation:**
- A clean environment will show near-zero counts for most of these events except during known change windows (onboarding, deployments).
- `CreateAccessKey` spikes outside of business hours are a strong compromise indicator — attackers create access keys to maintain persistent access after gaining console entry.
- `UpdateAssumeRolePolicy` or `AttachRolePolicy` outside of deployment pipelines may indicate privilege escalation via CDET-003 or CDET-004 detection coverage.
- `DeleteAccessKey` or `DeleteUser` spikes may indicate an attacker attempting to cover tracks.

**Response Actions:**
- For any spike outside a known change window: run `index=aws_cloudtrail eventName="<event>" earliest=-7d | table _time userIdentity.arn sourceIPAddress requestParameters | sort -_time` to identify the actor.
- Verify that the acting principal is in `approved_iam_principals.csv`.
- If CreateAccessKey was called: immediately check whether the new key has been used: `index=aws_cloudtrail userIdentity.accessKeyId="<new_key_id>"`.

---

### Panel 5 — External IP Activity (Last 24h)

**Objective:** Identify the external (non-RFC-1918) IP addresses most actively calling AWS APIs. External IPs making AWS API calls are expected for remote workers and automation — but unknown external IPs are high-value investigation targets.

**SPL:**
```spl
index=aws_cloudtrail earliest=-24h
| where NOT match(sourceIPAddress, "^10\.") AND
        NOT match(sourceIPAddress, "^172\.(1[6-9]|2[0-9]|3[0-1])\.") AND
        NOT match(sourceIPAddress, "^192\.168\.") AND
        NOT match(sourceIPAddress, "^127\.") AND
        sourceIPAddress!="AWS Internal" AND
        sourceIPAddress!=""
| stats count values(eventName) AS event_names by sourceIPAddress userAgent
| sort -count
| head 20
| eval event_names=mvjoin(event_names, ", ")
| rename sourceIPAddress AS "Source IP"
         count AS "Event Count"
         event_names AS "Event Types"
         userAgent AS "User Agent"
```

**Interpretation:**
- IPs associated with known cloud providers (AWS, GCP, Azure CIDR ranges) may indicate legitimate cross-cloud automation.
- IPs with generic user agents (`python-requests`, `curl`, `Boto3/`) and high call volumes are automation — verify whether they are authorized.
- IPs appearing only in this list and in the `cdet_alerts` index simultaneously are confirmed threat-correlated.
- The `userAgent` field is especially useful: `aws-cli` from a developer IP is normal; `aws-cli` from a data-center IP range is not.

**Response Actions:**
- Run a threat intel lookup on the top 5 IPs using your organization's intel platform.
- For suspicious IPs: run `index=aws_cloudtrail sourceIPAddress="<IP>" earliest=-24h | table _time eventName userIdentity.arn errorCode | sort -_time` to see the full activity.
- If the IP has called `CreateUser` or `CreateAccessKey`, treat as active compromise and escalate immediately.

---

### Panel 6 — GuardDuty Findings by Type and Severity (Last 7 Days)

**Objective:** Aggregate GuardDuty findings to provide a second-layer threat signal independent of CDET detections. GuardDuty uses AWS-managed threat intel and ML; its findings complement rule-based CDET detections.

**SPL:**
```spl
index=aws_security sourcetype=aws:guardduty earliest=-7d
| stats count by type severity
| eval severity_label=case(
    severity >= 7.0, "HIGH",
    severity >= 4.0, "MEDIUM",
    severity >= 1.0, "LOW",
    true(),          "INFORMATIONAL"
  )
| sort -count
| rename type AS "Finding Type"
         severity AS "Severity Score"
         severity_label AS "Severity"
         count AS "Count"
```

**Interpretation:**
- `UnauthorizedAccess:IAMUser/` and `Recon:IAMUser/` finding types are the most directly correlated to CDET detections and should be cross-referenced against the alert queue.
- `CryptoCurrency:EC2/` findings indicate cryptomining — check your EC2 instance inventory for unauthorized workloads.
- GuardDuty HIGH findings with no corresponding CDET alert may indicate a detection coverage gap; escalate to the detection engineering team.

**Response Actions:**
- For any HIGH or CRITICAL GuardDuty finding: run `index=aws_security sourcetype=aws:guardduty type="<type>" earliest=-7d | table _time accountId region resource` to understand scope.
- Compare findings against the CDET coverage matrix — GuardDuty findings with no matching CDET detection should be triaged as potential new detection candidates (file a CDET backlog item).
- Remediation steps are finding-type-specific; refer to the AWS GuardDuty remediation runbooks.

---

### Panel 7 — SecurityHub Critical Findings (Last 30 Days)

**Objective:** Surface CRITICAL-severity findings from SecurityHub, which aggregates results from multiple security services (Inspector, Macie, Firewall Manager, IAM Access Analyzer, and GuardDuty). This gives a compliance and configuration risk view that supplements the behavioral detections.

**SPL:**
```spl
index=aws_security sourcetype=aws:securityhub earliest=-30d
  "Severity.Label"=CRITICAL
| table _time Title "Severity.Label" "ProductFields.aws/securityhub/FindingId" CreatedAt
| sort -_time
| rename _time AS "Detected"
         Title AS "Finding Title"
         "Severity.Label" AS "Severity"
         "ProductFields.aws/securityhub/FindingId" AS "Finding ID"
         CreatedAt AS "Created At"
```

**Interpretation:**
- CRITICAL findings from SecurityHub typically represent mis-configurations (e.g., publicly exposed S3 buckets, security group rules allowing unrestricted inbound access) rather than active incidents.
- Findings persisting across multiple 30-day windows indicate a systemic compliance failure — not a one-time oversight.
- A sudden increase in CRITICAL findings after a deployment window indicates that a new workload was deployed with insecure defaults.

**Response Actions:**
- For each CRITICAL finding: look up the Finding ID in the SecurityHub console to access the full finding detail and remediation guidance.
- Assign each finding to the responsible AWS account team with a remediation SLA (CRITICAL = 24 hours in most frameworks).
- If a CRITICAL finding corresponds to an exposed credential or open management port, treat as an active incident and escalate to Tier-2.
