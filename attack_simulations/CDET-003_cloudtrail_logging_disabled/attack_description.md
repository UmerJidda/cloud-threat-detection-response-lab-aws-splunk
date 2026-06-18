# CDET-003 — CloudTrail Logging Disabled

## Technique
**Tactic:** Defense Evasion  
**MITRE Technique:** T1562.008 — Impair Defenses: Disable Cloud Logs  
**Severity:** Critical | Risk Score: 90

---

## Threat Actor Perspective

### Why Disabling CloudTrail Is Step One in AWS Attacks

CloudTrail is the primary audit log for AWS API activity. Every action taken by an adversary — creating users, assuming roles, launching instances, accessing S3 data — is recorded in CloudTrail. Before executing their primary objectives, sophisticated adversaries will attempt to disable, degrade, or delete CloudTrail to prevent forensic reconstruction of their actions and reduce real-time detection capabilities.

This is one of the most consequential single actions an adversary can take in AWS: it is simultaneously a defense evasion technique *and* a signal of imminent impact. Any organization with CloudTrail alerting should treat a disable event as a Severity 1 incident requiring immediate response.

### The Narrow Detection Window Problem

The paradox of CloudTrail disabling is that the disabling event *is itself a CloudTrail event*. When an adversary calls `cloudtrail:StopLogging`:
1. CloudTrail records the `StopLogging` event
2. After that event, no further CloudTrail events are recorded
3. The detection window is the time between the `StopLogging` event appearing in the trail and the SIEM processing it

In practice, CloudTrail events may take 5-15 minutes to appear in S3, and another 5-10 minutes for the SIEM collector to process them. This creates a 10-25 minute blind window between when logging stops and when the SOC is alerted. A skilled adversary can execute a significant attack in that window.

**CloudWatch Logs integration changes this**: If CloudTrail is configured to stream to CloudWatch Logs, the `StopLogging` event may appear within 1-2 minutes, dramatically reducing the blind window. This is why CloudWatch Logs integration is a recommended defense.

### Three Attack Variants

**Variant 1: StopLogging (Most Common)**  
`aws cloudtrail stop-logging --name <trail-name>`

This stops all API event recording immediately. The trail configuration is preserved — logging can be restarted. This is the fastest and most reversible method. Commonly used by:
- Opportunistic attackers who want to cover tracks before data exfiltration
- Ransomware operators before encryption
- Insider threat actors before privilege abuse

**Variant 2: UpdateTrail Degradation (Stealthiest)**  
Rather than stopping logging entirely, an adversary can degrade it in ways that may not trigger "logging disabled" alerts:
- `--no-include-management-events` — removes IAM, STS, KMS events (most attack actions)
- `--no-include-global-service-events` — removes global service (IAM) logging
- Setting `--s3-bucket-name` to a bucket the attacker controls — logs go to attacker, not defender
- Enabling `--no-enable-log-file-validation` — logs can now be tampered with undetected

These changes generate `UpdateTrail` events, which many organizations do not alert on with the same urgency as `StopLogging`. Detection requires monitoring the *specific parameter changes* within `UpdateTrail`, not just the event name.

**Variant 3: DeleteTrail (Most Destructive)**  
`aws cloudtrail delete-trail --name <trail-name>`

This permanently removes the trail configuration. All CloudTrail logging ceases. Unlike `StopLogging`, there is no "restart" — the trail must be recreated from scratch (losing any CloudWatch Logs integration, S3 configuration, and KMS settings). This is irreversible without infrastructure-as-code records.

**WARNING**: `DeleteTrail` should only ever be executed in isolated sandbox accounts during security testing. In a production environment, this action causes immediate compliance violations and may be unrecoverable without Terraform/CloudFormation trail definitions.

### Multi-Region vs. Single-Region Impact

CloudTrail trails can be:
- **Single-region**: Only captures events in one region — easily bypassed by switching to another region
- **Multi-region** (the recommended configuration): Captures events across all regions from a single trail

An adversary who stops a single-region trail can simply switch to another region to continue their attack without being logged. Stopping a multi-region trail eliminates logging for the entire account.

An important evasion technique: if the target has both a multi-region trail AND single-region trails, stopping only the single-region trails may not stop the multi-region trail. Attackers who enumerate trail configurations before acting (`DescribeTrails`) will identify the multi-region trail and target it specifically.

### Recovery Difficulty

After `StopLogging`: Re-enable with `start-logging` — all future events recorded, no gap in trail config.  
After `UpdateTrail` degradation: Restore original configuration — some events may have been missed.  
After `DeleteTrail`: Full recreation required. If CloudFormation/Terraform is not current, manual reconstruction. Historical gap in CloudTrail coverage creates audit compliance issues.

---

## Detection Context (CDET-003)

The CDET-003 detection fires on `StopLogging`, `DeleteTrail`, and certain `UpdateTrail` events. The `UpdateTrail` variant looks for parameter changes that disable management events, global service events, or change the destination S3 bucket.

**Key insight**: `StopLogging` and `DeleteTrail` have essentially zero legitimate use cases in production accounts. They should be treated as unambiguous attacker activity unless pre-approved in a change management system.
