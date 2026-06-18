# CDET-011 — Negative Test Case

**Purpose:** Verify the detection does NOT fire when compute resources are launched by approved principals, regardless of instance type.

## Test Input
- Sample file: sample_logs/cloudtrail/benign/CDET-011_approved_launch.ndjson
- Index the file into Splunk index: aws_cloudtrail
- Sourcetype: aws:cloudtrail

## Suppression Conditions

### Scenario A — Approved Principal Launches Standard EC2 Instance
- eventName: RunInstances
- principal_arn: arn:aws:iam::123456789012:role/EC2ProvisioningRole (in approved_compute_principals)
- instance_type: t3.medium (not suspicious)
- is_suspicious_type: false
- Should NOT fire

### Scenario B — Approved Principal Launches GPU Instance (Legitimate ML Workload)
- eventName: RunInstances
- principal_arn: arn:aws:iam::123456789012:role/MLTrainingRole (in approved_compute_principals)
- instance_type: p3.16xlarge (suspicious type, but approved principal)
- is_suspicious_type: true
- Principal is approved → suppressed
- Should NOT fire

### Scenario C — Approved Lambda Principal Creates Function
- eventName: CreateFunction
- principal_arn: arn:aws:iam::123456789012:role/LambdaDeployRole (in approved_compute_principals)
- function_runtime: python3.9
- Should NOT fire

### Scenario D — TerminateInstances or StopInstances (Lifecycle, Not Launch)
- eventName: TerminateInstances
- Any principal
- Not a resource launch event
- Should NOT fire

## Expected Result
- Detection fires: NO for all four scenarios

## Pass Criteria
- Load all scenario events into the test index
- Confirm zero alerts for approved principals and non-launch events
- Verify approved_compute_principals lookup is correctly applied
- Confirm that suspicious instance type alone does NOT fire if the principal is approved
