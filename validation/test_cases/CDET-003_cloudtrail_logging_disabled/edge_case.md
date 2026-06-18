# CDET-003 — Edge Case

**Purpose:** Verify detection behavior when UpdateTrail partially degrades logging — only one of the three degradation parameters is set to false.

## Scenario: Single-Field Degradation via UpdateTrail

### Event Details
- eventName: UpdateTrail
- requestParameters:
  - IsMultiRegionTrail: false (ONLY this field is degraded)
  - IncludeGlobalServiceEvents: true (unchanged)
  - EnableLogFileValidation: true (unchanged)
- principal_arn: arn:aws:iam::123456789012:user/ops-engineer
- region: us-east-1

### Expected Result
- Detection fires: YES
- disable_reason: "UpdateTrail degraded logging configuration"
- Disabling multi-region trail coverage is a meaningful reduction in visibility, even if other settings remain enabled

## Scenario: UpdateTrail by Automation Role That Legitimately Adjusts Coverage

### Event Details
- eventName: UpdateTrail
- userIdentity.type: AssumedRole
- session_issuer_arn: arn:aws:iam::123456789012:role/TerraformExecutionRole
- requestParameters: IsMultiRegionTrail=false (changing regional scope for cost reasons)

### Expected Result
- Detection fires: YES (CDET-003 has no automation-role suppression by design — any logging degradation is critical regardless of caller)
- This is intentional: even authorized pipeline changes that reduce logging coverage should be reviewed
- If a false positive occurs from legitimate Terraform cost optimization, document the specific trail ARN in a known-exception comment in the detection, rather than suppressing the entire role

## Scenario: DeleteTrail on a Non-Primary Trail
- eventName: DeleteTrail
- requestParameters.name: arn:aws:cloudtrail:us-west-2:123456789012:trail/secondary-region-trail
- This is a secondary/non-critical trail

### Expected Result
- Detection fires: YES
- CDET-003 does not distinguish between primary and secondary trails — all deletion events are critical
- Document which trails are considered critical vs. secondary in the suppression lookup if needed

## Pass Criteria
- Load all edge case events into the test index
- Confirm detection fires for single-field UpdateTrail degradation
- Confirm detection fires even for automation role callers
- Confirm detection fires for non-primary trail deletion
- Document any exceptions or known legitimate cases in data/validation_results/
