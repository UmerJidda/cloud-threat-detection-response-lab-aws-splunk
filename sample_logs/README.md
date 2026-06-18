# Sample Logs

Synthetic AWS event datasets for detection validation and demonstration.

All events use fictional but realistic values:
- Primary account: `123456789012`
- Attacker-controlled account: `999999999999`
- Approved internal accounts: `234567890123`, `345678901234`, `456789012345`
- Malicious source IPs: `198.51.100.x/24` (RFC 5737 documentation range — safe for test data)
- Internal IPs: `10.0.1.x`, `172.16.x.x`, `169.254.169.254`

---

## Directory Structure

```
sample_logs/
├── cloudtrail/
│   ├── malicious/     — Events that SHOULD trigger detections
│   └── benign/        — Events that SHOULD NOT trigger detections (suppressed)
├── guardduty/
│   └── malicious/     — GuardDuty findings for CDET-007
├── securityhub/
│   └── findings/      — Security Hub ASFF findings
├── alerts/
│   └── sample_alerts.ndjson  — Expected alert output for all 14 detections
└── validation/        — Validation result snapshots
```

---

## Coverage Map

| File | Detection | Type |
|------|-----------|------|
| `cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson` | CDET-001 | Malicious |
| `cloudtrail/malicious/CDET-002_iam_access_key_created_for_existing_user.ndjson` | CDET-002 | Malicious |
| `cloudtrail/malicious/CDET-003_cloudtrail_logging_disabled.ndjson` | CDET-003 | Malicious |
| `cloudtrail/malicious/CDET-004_admin_policy_attached.ndjson` | CDET-004 | Malicious |
| `cloudtrail/malicious/CDET-005_cross_account_role_trust_modified.ndjson` | CDET-005 | Malicious |
| `cloudtrail/malicious/CDET-006_root_account_activity.ndjson` | CDET-006 | Malicious |
| `cloudtrail/malicious/CDET-007_ec2_metadata_credential_abuse.ndjson` | CDET-007 | Malicious |
| `cloudtrail/malicious/CDET-008_excessive_api_enumeration.ndjson` | CDET-008 | Malicious |
| `cloudtrail/malicious/CDET-009_s3_replication_external_account.ndjson` | CDET-009 | Malicious |
| `cloudtrail/malicious/CDET-010_mass_s3_object_deletion.ndjson` | CDET-010 | Malicious |
| `cloudtrail/malicious/CDET-011_unauthorized_compute_launch.ndjson` | CDET-011 | Malicious |
| `cloudtrail/malicious/CDET-012_cross_account_assumerole_chain.ndjson` | CDET-012 | Malicious |
| `cloudtrail/malicious/CDET-013_security_group_public_internet.ndjson` | CDET-013 | Malicious |
| `cloudtrail/malicious/CDET-014_cloudtrail_log_deleted.ndjson` | CDET-014 | Malicious |
| `cloudtrail/benign/normal_iam_activity.ndjson` | CDET-001/002/003 negative | Benign |
| `cloudtrail/benign/normal_s3_activity.ndjson` | CDET-009/010 negative | Benign |
| `cloudtrail/benign/normal_sts_activity.ndjson` | CDET-005/012 negative | Benign |
| `cloudtrail/benign/normal_ec2_activity.ndjson` | CDET-011/013 negative | Benign |
| `guardduty/malicious/CDET-007_instance_credential_exfiltration.ndjson` | CDET-007 GD branch | Malicious |
| `securityhub/findings/sample_findings.ndjson` | Security posture | Reference |
| `alerts/sample_alerts.ndjson` | All 14 detections | Expected output |

---

## Loading into Splunk

```bash
# Load a single malicious sample for CDET-001 validation
/opt/splunk/bin/splunk add oneshot \
  sample_logs/cloudtrail/malicious/CDET-001_iam_user_created_outside_pipeline.ndjson \
  -index aws_cloudtrail \
  -sourcetype aws:cloudtrail

# Load GuardDuty sample for CDET-007 (Branch B)
/opt/splunk/bin/splunk add oneshot \
  sample_logs/guardduty/malicious/CDET-007_instance_credential_exfiltration.ndjson \
  -index aws_security \
  -sourcetype aws:guardduty:finding
```

After loading, run the corresponding detection SPL in Splunk Search and compare the output to `sample_alerts.ndjson`.
