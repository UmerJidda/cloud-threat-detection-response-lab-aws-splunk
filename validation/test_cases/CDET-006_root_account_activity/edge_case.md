# CDET-006 — Edge Case

**Purpose:** Verify detection behavior for root account events with MFA enabled (expected occasional legitimate use) and for automated root actions from AWS itself.

## Scenario: Root Activity with MFA Enabled

### Event Details
- eventName: UpdateAccountPasswordPolicy
- userIdentity.type: Root
- userIdentity.sessionContext.attributes.mfaAuthenticated: true
- mfa_used: Yes
- event_source_ip: 198.51.100.1

### Expected Result
- Detection fires: YES
- MFA presence does NOT suppress root activity detection
- mfa_used field should be "Yes" in the alert output
- This allows responders to note that MFA was used, potentially reducing urgency during triage, but the alert must still fire
- No suppression should exist for root+MFA events

## Scenario: Root Activity from AWS Internal Source (service-activity)

### Event Details
- eventName: CheckMfa
- userIdentity.type: Root
- sourceIPAddress: "AWS Internal" or "aws-internal"
- eventType: AwsServiceEvent

### Expected Result
- Detection fires: YES (or document if intentionally excluded)
- Some AWS-internal root service events may be expected (e.g., compliance checks)
- If the SPL excludes eventType=AwsServiceEvent, document this as a suppression
- If not excluded, AWS service events from root will generate alerts — document expected volume

## Scenario: Multiple Root Events in Same Minute (Alert Deduplication)

### Event Details
- 5 root events in the same minute from the same IP
- eventNames: CreateUser, AttachUserPolicy, CreateAccessKey, PutUserPolicy, ConsoleLogin

### Expected Result
- Detection fires: YES, 5 separate alerts OR 1 grouped alert depending on Splunk alert configuration
- Verify alert deduplication settings are appropriate
- Document whether the detection is configured to fire per-event or per-minute-window

## Pass Criteria
- Confirm detection fires for root events regardless of MFA status
- Confirm mfa_used field correctly reflects "Yes" or "No"
- Document AWS internal root event behavior
- Document alert deduplication behavior for burst root activity
