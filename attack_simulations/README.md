# Attack Simulations

This directory contains attack simulation documentation and scripts for all 14 detections.

## Purpose

Attack simulations serve two purposes:

1. **Validation** — understand exactly what CloudTrail events an attack generates, so sample data can be verified against real attack patterns
2. **Red Team / Purple Team exercises** — provide runnable scripts for authorized testing with sufficient AWS permissions

## Safety Model

| Script mode | What it does | Required permissions |
|-------------|-------------|---------------------|
| Default (dry-run) | Prints actions without executing | Read-only (SecurityAudit) |
| `--execute` | Performs the actual AWS API calls | Write permissions for the specific service |

Most scripts are safe to run in dry-run mode with read-only credentials. The `simulate.py` for CDET-008 (enumeration) and CDET-007 (IMDSv2 assessment) are fully read-only and can be run without `--execute`.

> **Warning:** Running simulations with `--execute` in a production account can cause real harm. Use isolated test accounts only.

## Directory Structure

```
attack_simulations/
├── README.md
├── CDET-001_iam_user_created_outside_pipeline/
│   ├── attack_description.md
│   ├── simulation_steps.md
│   ├── expected_events.md
│   └── simulate.py
├── CDET-002_iam_access_key_created_for_existing_user/
│   └── ...
...
└── CDET-014_cloudtrail_log_deleted_from_s3/
    └── ...
```

## Running Simulations

```bash
# Safe: enumerate what the simulation would do (dry-run)
python attack_simulations/CDET-001_iam_user_created_outside_pipeline/simulate.py \
  --username backdoor-test-user \
  --region us-east-1

# Actually execute (requires write permissions + isolated test account)
python attack_simulations/CDET-001_iam_user_created_outside_pipeline/simulate.py \
  --username backdoor-test-user \
  --region us-east-1 \
  --execute

# Read-only enumeration (CDET-008) — safe to run anywhere
python attack_simulations/CDET-008_excessive_api_enumeration/simulate.py \
  --region us-east-1
```

## Relationship to Detections

Each simulation is mapped to its detection:

| Simulation | Detection | Technique |
|-----------|-----------|-----------|
| CDET-001 | IAM User Created Outside Pipeline | T1136.003 |
| CDET-002 | IAM Access Key Created for Existing User | T1098.001 |
| CDET-003 | CloudTrail Logging Disabled | T1562.008 |
| CDET-004 | Admin Policy Attached to Principal | T1078.004 |
| CDET-005 | Cross-Account Role Trust Modified | T1484.002 |
| CDET-006 | Root Account Activity | T1078.004 |
| CDET-007 | EC2 Instance Metadata Credential Abuse | T1552.005 |
| CDET-008 | Excessive API Enumeration | T1580 |
| CDET-009 | S3 Replication to External Account | T1537 |
| CDET-010 | Mass S3 Object Deletion | T1485 |
| CDET-011 | Unauthorized Compute Resource Launch | T1496 |
| CDET-012 | Cross-Account AssumeRole Chain | T1550.001 |
| CDET-013 | Security Group Opened to Public Internet | T1562.007 |
| CDET-014 | CloudTrail Log File Deleted from S3 | T1070.004 |
