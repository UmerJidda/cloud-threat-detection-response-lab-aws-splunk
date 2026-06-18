# CDET-011 — Unauthorized Compute Resource Launch

| Field | Value |
|-------|-------|
| **Detection ID** | CDET-011 |
| **Severity** | High |
| **Confidence** | Medium |
| **Tactic** | Impact |
| **Technique** | T1496 — Resource Hijacking |
| **Status** | Testing |
| **Data Source** | CloudTrail |
| **Schedule** | Every 15 minutes |

## Detection Logic

Resource hijacking — particularly cryptocurrency mining — is one of the most financially motivated attack categories in AWS. Adversaries who gain AWS credentials with EC2 or Lambda permissions will often immediately launch the largest available GPU or high-CPU instances to maximize mining throughput. AWS does not cap this by default; an attacker can accrue significant charges in hours.

The detection targets `RunInstances` and `CreateFunction` from principals not in the approved compute-provisioning lookups, with elevated priority for:
- GPU instance types (p2, p3, p4, g3, g4) commonly used for mining
- Large instance counts (≥ 10 instances in a single call)
- Lambda deployments in regions the organization does not normally use

The `suspicious_instance_types.csv` lookup must be populated with instance type prefixes known to be abused.

## Required Lookups

**`suspicious_instance_types.csv`**:
```csv
instance_type,is_suspicious_type,abuse_category
p2.xlarge,true,cryptocurrency mining (GPU)
p3.2xlarge,true,cryptocurrency mining (GPU)
p4d.24xlarge,true,cryptocurrency mining (GPU)
g4dn.xlarge,true,cryptocurrency mining (GPU)
g3.4xlarge,true,cryptocurrency mining (GPU)
c5.18xlarge,true,high-CPU abuse
c5.24xlarge,true,high-CPU abuse
```

## Example Alert Output

```
detection_id    : CDET-011
severity        : high
eventName       : RunInstances
principal_arn   : arn:aws:iam::123456789012:user/compromised-dev
instance_type   : p3.8xlarge
instance_count  : 5
is_suspicious_type: true
abuse_category  : cryptocurrency mining (GPU)
event_source_ip : 198.51.100.77
region          : us-east-1
```

## Containment Guidance

1. Terminate all running instances launched by the unauthorized principal: `aws ec2 terminate-instances --instance-ids <ids>`
2. Revoke the acting principal's credentials immediately
3. Set an IAM Service Control Policy or permission boundary to prevent re-launch while investigation proceeds
4. Check all regions — mining operations often launch in multiple regions simultaneously
5. Review AWS Cost Explorer for anomalous charges to estimate financial impact
