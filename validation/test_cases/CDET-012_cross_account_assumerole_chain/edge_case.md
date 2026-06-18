# CDET-012 — Edge Case

**Purpose:** Verify severity escalation when chaining occurs, and detection behavior when a role assumption chain returns to the original account.

## Scenario: Role Chain That Returns to the Original Account (Boomerang Pattern)

### Event Details
- Principal in account 123456789012 assumes role in account 999888777666 (external, unapproved)
- From 999888777666, assumes a role back in account 123456789012 (same account, different role)
- Event sequence:
  1. AssumeRole: 123456789012 → 999888777666 (external hop, unapproved)
  2. AssumeRole: 999888777666 → 123456789012 (back to original account)
- is_chained_assumption: true
- distinct_target_accounts: 2 (both 999888777666 and 123456789012 appear as targets)

### Expected Result
- Detection fires: YES for the first hop (targeting unapproved account 999888777666)
- Second hop may or may not be detected depending on whether same-account targets are excluded
- Confirm detection captures the external account in the chain even if the chain eventually returns home
- Severity: critical (chained assumption)

## Scenario: Approved Principal Assumes Unapproved Account Once (Severity Boundary)

### Event Details
- principal_arn: arn:aws:iam::123456789012:role/ApprovedCrossAccountRole (in automation_role_arns)
- AssumeRole target: arn:aws:iam::999888777666:role/UnknownRole (NOT in approved_assume_targets)
- total_assumes: 1
- is_chained_assumption: false

### Expected Result
- Detection fires: YES (target account is unapproved, even from an approved principal)
- Severity: high (not critical — single hop, not chained)
- Urgency: 2
- This tests that approved callers cannot bypass detection by targeting unapproved accounts

## Scenario: Exactly 2 Distinct Target Accounts (Severity Escalation Boundary)

### Event Details
- Same principal assumes roles in exactly 2 distinct external accounts within the lookback window
- distinct_target_accounts: 2
- is_chained_assumption: true (AssumedRole calling AssumeRole)

### Expected Result
- Detection fires: YES
- Severity should be critical (chained assumption across multiple accounts)
- Verify that the threshold for "chained" is is_chained_assumption=true (AssumedRole type), not just distinct_target_accounts > 1

## Pass Criteria
- Confirm detection fires for the boomerang role chain pattern
- Confirm severity is critical for chained assumptions
- Confirm detection fires even when caller is in automation_role_arns but target is unapproved
- Confirm severity escalation logic is based on is_chained_assumption flag
