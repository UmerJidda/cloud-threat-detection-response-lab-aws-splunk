"""
Detection Validation Framework — core runner.

Loads test case definitions, simulates Splunk detection execution by
replaying sample NDJSON events through the detection logic, and produces
structured validation reports.

Usage:
    python -m validation.validator --detection CDET-001
    python -m validation.validator --all
    python -m validation.validator --all --output-dir data/validation_results/
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from validation.schema import (
    AlertAssertion,
    DetectionValidationSummary,
    FieldAssertion,
    FieldResult,
    TestCase,
    TestCaseType,
    TestResult,
    ValidationResult,
    ValidationRunSummary,
)

logger = structlog.get_logger(__name__)

ROOT = Path(__file__).parent.parent

# ── Test case registry ────────────────────────────────────────────────────────

def _load_test_case_definitions() -> dict[str, list[TestCase]]:
    """
    Load test case definitions from validation/test_cases/<CDET-XXX>/ directories.

    Each directory contains:
      expected_alert.json  — fields the alert output must contain
      positive_case.md     — human-readable description (not parsed)
      negative_case.md     — human-readable description (not parsed)
    """
    test_cases: dict[str, list[TestCase]] = {}
    tc_root = ROOT / "validation" / "test_cases"

    if not tc_root.exists():
        logger.warning("test_cases_directory_missing", path=str(tc_root))
        return test_cases

    for cdet_dir in sorted(tc_root.iterdir()):
        if not cdet_dir.is_dir():
            continue

        detection_id = cdet_dir.name.split("_")[0].upper()
        expected_alert_file = cdet_dir / "expected_alert.json"

        if not expected_alert_file.exists():
            logger.warning("missing_expected_alert", detection_id=detection_id)
            continue

        expected_alert = json.loads(expected_alert_file.read_text(encoding="utf-8"))
        cases = _build_test_cases(detection_id, expected_alert)
        test_cases[detection_id] = cases

    return test_cases


def _build_test_cases(detection_id: str, expected: dict[str, Any]) -> list[TestCase]:
    """Build TestCase objects from an expected_alert.json definition."""
    cdet_lower = detection_id.lower().replace("-", "")
    severity = expected.get("severity", "high")
    urgency = expected.get("urgency", 2)
    tactic = expected.get("tactic", "")
    technique = expected.get("technique", "")

    required_fields = [
        FieldAssertion("detection_id", expected_value=detection_id),
        FieldAssertion("severity", expected_value=severity),
        FieldAssertion("urgency", expected_value=urgency),
        FieldAssertion("tactic", expected_value=tactic),
        FieldAssertion("technique", expected_value=technique),
        FieldAssertion("principal_arn", must_be_nonempty=True),
        FieldAssertion("region", must_be_nonempty=True),
    ]

    # Add detection-specific fields from expected_alert.json
    skip_keys = {"detection_id", "severity", "urgency", "tactic", "technique",
                 "_time", "alert_title", "confidence", "technique_name"}
    for key, val in expected.items():
        if key not in skip_keys:
            required_fields.append(
                FieldAssertion(key, must_exist=True, must_be_nonempty=bool(val))
            )

    positive_sample = _find_sample_file(detection_id, "malicious")
    negative_sample = _find_sample_file(detection_id, "benign") or _find_sample_file(
        detection_id, "suppressed"
    )

    cases = [
        TestCase(
            detection_id=detection_id,
            test_case_type=TestCaseType.POSITIVE,
            name=f"{detection_id} — positive case",
            description="Detection must fire on confirmed malicious event",
            sample_file=positive_sample or Path(f"sample_logs/cloudtrail/malicious/{cdet_lower}.ndjson"),
            alert_assertion=AlertAssertion(
                should_fire=True,
                expected_severity=severity,
                expected_urgency=urgency,
                expected_tactic=tactic,
                expected_technique=technique,
                field_assertions=required_fields,
            ),
        ),
        TestCase(
            detection_id=detection_id,
            test_case_type=TestCaseType.NEGATIVE,
            name=f"{detection_id} — negative case (suppression)",
            description="Detection must NOT fire when principal is in suppression lookup",
            sample_file=negative_sample or Path(f"sample_logs/cloudtrail/benign/normal_iam_activity.ndjson"),
            alert_assertion=AlertAssertion(
                should_fire=False,
                max_alert_count=0,
                field_assertions=[],
            ),
        ),
    ]
    return cases


def _find_sample_file(detection_id: str, category: str) -> Path | None:
    """Locate the most likely sample NDJSON file for a detection."""
    cdet_lower = detection_id.lower().replace("-", "_")
    patterns = [
        ROOT / "sample_logs" / "cloudtrail" / category / f"{cdet_lower}_*.ndjson",
        ROOT / "sample_logs" / "cloudtrail" / category / f"*{cdet_lower}*.ndjson",
        ROOT / "sample_logs" / "guardduty" / category / f"{cdet_lower}_*.ndjson",
    ]
    for pattern in patterns:
        matches = sorted(pattern.parent.glob(pattern.name))
        if matches:
            return matches[0]
    return None


# ── Sample-based detection runner ─────────────────────────────────────────────

def _load_ndjson(path: Path) -> list[dict[str, Any]]:
    """Load all events from an NDJSON file."""
    if not path.exists():
        logger.warning("sample_file_not_found", path=str(path))
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("json_parse_error", path=str(path), error=str(exc))
    return events


def _run_heuristic_detection(
    detection_id: str,
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Heuristic evaluation of events against detection logic.

    This is NOT a Splunk replacement — it validates that sample data contains
    the expected signals. The real detection runs in Splunk.

    Returns a list of mock alert dicts that represent what the detection
    would generate.
    """
    # Suppressed principals (mirror the lookup CSVs)
    _SUPPRESSED_ARNS = {
        "arn:aws:iam::123456789012:role/DeploymentPipelineRole",
        "arn:aws:iam::123456789012:role/TerraformExecutionRole",
        "arn:aws:iam::123456789012:role/AutoScalingRole",
        "arn:aws:iam::123456789012:role/SecurityAuditRole",
    }
    _APPROVED_ACCOUNTS = {"123456789012", "234567890123", "345678901234", "456789012345"}

    alerts = []

    for event in events:
        uid = event.get("userIdentity", {})
        principal_arn = uid.get("arn", uid.get("principalId", "unknown"))
        principal_type = uid.get("type", "unknown")
        event_name = event.get("eventName", "")
        source_ip = event.get("sourceIPAddress", "")
        region = event.get("awsRegion", "us-east-1")
        error_code = event.get("errorCode", "")

        if error_code:
            continue

        # Suppress known automation roles
        session_issuer = uid.get("sessionContext", {}).get("sessionIssuer", {}).get("arn", "")
        if principal_arn in _SUPPRESSED_ARNS or session_issuer in _SUPPRESSED_ARNS:
            continue

        fired = False
        alert: dict[str, Any] = {
            "detection_id": detection_id,
            "principal_arn": principal_arn,
            "principal_type": principal_type,
            "eventName": event_name,
            "event_source_ip": source_ip,
            "region": region,
            "_time": event.get("eventTime", ""),
        }

        rp = event.get("requestParameters") or {}

        if detection_id == "CDET-001":
            if event_name == "CreateUser" and principal_arn not in _SUPPRESSED_ARNS:
                fired = True
                alert.update({
                    "severity": "high", "urgency": 2,
                    "tactic": "Persistence", "technique": "T1136.003",
                    "technique_name": "Create Account: Cloud Account",
                    "new_user_name": rp.get("userName", ""),
                })

        elif detection_id == "CDET-002":
            if event_name == "CreateAccessKey":
                creator = uid.get("userName", "")
                target_user = rp.get("userName", "")
                is_cross_user = creator and target_user and creator != target_user
                if is_cross_user:
                    fired = True
                    alert.update({
                        "severity": "high", "urgency": 2,
                        "tactic": "Persistence", "technique": "T1098.001",
                        "technique_name": "Account Manipulation: Additional Cloud Credentials",
                        "key_owner_name": target_user,
                        "is_cross_user": "true",
                    })

        elif detection_id == "CDET-003":
            if event_name in ("StopLogging", "DeleteTrail"):
                fired = True
                alert.update({
                    "severity": "critical", "urgency": 1,
                    "tactic": "Defense Evasion", "technique": "T1562.008",
                    "technique_name": "Impair Defenses: Disable or Modify Cloud Logs",
                    "disable_reason": f"Trail {event_name.lower()}",
                })
            elif event_name == "UpdateTrail":
                degraded = (
                    rp.get("enableLogFileValidation") is False
                    or rp.get("isMultiRegionTrail") is False
                    or rp.get("includeGlobalServiceEvents") is False
                )
                if degraded:
                    fired = True
                    alert.update({
                        "severity": "critical", "urgency": 1,
                        "tactic": "Defense Evasion", "technique": "T1562.008",
                        "technique_name": "Impair Defenses: Disable or Modify Cloud Logs",
                        "disable_reason": "Trail coverage degraded via UpdateTrail",
                    })

        elif detection_id == "CDET-004":
            _ADMIN_POLICIES = {
                "arn:aws:iam::aws:policy/AdministratorAccess",
                "arn:aws:iam::aws:policy/PowerUserAccess",
                "arn:aws:iam::aws:policy/IAMFullAccess",
            }
            policy_arn = rp.get("policyArn", "")
            if event_name in ("AttachUserPolicy", "AttachRolePolicy") and policy_arn in _ADMIN_POLICIES:
                fired = True
                alert.update({
                    "severity": "critical", "urgency": 1,
                    "tactic": "Privilege Escalation", "technique": "T1078.004",
                    "technique_name": "Valid Accounts: Cloud Accounts",
                    "policy_arn": policy_arn,
                    "is_wildcard_inline": "false",
                })
            elif event_name in ("PutUserPolicy", "PutRolePolicy"):
                doc = str(rp.get("policyDocument", ""))
                if '"*"' in doc or "'*'" in doc:
                    fired = True
                    alert.update({
                        "severity": "critical", "urgency": 1,
                        "tactic": "Privilege Escalation", "technique": "T1078.004",
                        "technique_name": "Valid Accounts: Cloud Accounts",
                        "is_wildcard_inline": "true",
                    })

        elif detection_id == "CDET-005":
            if event_name in ("CreateRole", "UpdateAssumeRolePolicy"):
                doc = str(rp.get("assumeRolePolicyDocument", rp.get("policyDocument", "")))
                # Check for external account IDs
                import re
                account_ids = re.findall(r'\b(\d{12})\b', doc)
                external = [a for a in account_ids if a not in _APPROVED_ACCOUNTS]
                if external:
                    fired = True
                    alert.update({
                        "severity": "high", "urgency": 2,
                        "tactic": "Privilege Escalation", "technique": "T1484.002",
                        "technique_name": "Domain or Tenant Policy Modification: Trust Modification",
                        "external_account_id": external[0],
                    })

        elif detection_id == "CDET-006":
            if principal_type == "Root":
                fired = True
                mfa = event.get("additionalEventData", {}).get("MFAUsed", "No")
                alert.update({
                    "severity": "critical", "urgency": 1,
                    "tactic": "Initial Access", "technique": "T1078.004",
                    "technique_name": "Valid Accounts: Cloud Accounts",
                    "mfa_used": mfa,
                    "root_action_category": (
                        "console_login" if event_name == "ConsoleLogin"
                        else "api_call"
                    ),
                })

        elif detection_id == "CDET-007":
            si = uid.get("sessionContext", {}).get("sessionIssuer", {})
            if (
                principal_type == "AssumedRole"
                and si.get("type") == "EC2Instance"
                and not source_ip.startswith(("10.", "172.16.", "172.17.", "169.254."))
            ):
                fired = True
                alert.update({
                    "severity": "high", "urgency": 2,
                    "tactic": "Credential Access", "technique": "T1552.005",
                    "technique_name": "Unsecured Credentials: Cloud Instance Metadata API",
                    "detection_source": "cloudtrail",
                    "session_issuer_arn": si.get("arn", ""),
                })
            # Also match GuardDuty findings
            if event.get("type", "").startswith("UnauthorizedAccess") and "InstanceCredentialExfiltration" in event.get("type", ""):
                fired = True
                alert.update({
                    "severity": "high", "urgency": 2,
                    "tactic": "Credential Access", "technique": "T1552.005",
                    "technique_name": "Unsecured Credentials: Cloud Instance Metadata API",
                    "detection_source": "guardduty",
                })

        elif detection_id == "CDET-009":
            if event_name == "PutBucketReplication":
                config = str(rp.get("replicationConfiguration", ""))
                import re
                account_ids = re.findall(r'\b(\d{12})\b', config)
                external = [a for a in account_ids if a not in _APPROVED_ACCOUNTS]
                if external:
                    fired = True
                    alert.update({
                        "severity": "high", "urgency": 2,
                        "tactic": "Exfiltration", "technique": "T1537",
                        "technique_name": "Transfer Data to Cloud Account",
                        "destination_account_id": external[0],
                        "source_bucket": rp.get("bucketName", ""),
                    })

        elif detection_id == "CDET-011":
            if event_name == "RunInstances" and principal_arn not in _SUPPRESSED_ARNS:
                itype = rp.get("instanceType", "")
                fired = True
                alert.update({
                    "severity": "high", "urgency": 2,
                    "tactic": "Impact", "technique": "T1496",
                    "technique_name": "Resource Hijacking",
                    "instance_type": itype,
                    "instance_count": rp.get("maxCount", 1),
                })

        elif detection_id == "CDET-012":
            if event_name == "AssumeRole":
                target_arn = rp.get("roleArn", "")
                import re
                match = re.search(r':(\d{12}):', target_arn)
                if match:
                    target_account = match.group(1)
                    if target_account not in _APPROVED_ACCOUNTS:
                        fired = True
                        is_chained = principal_type == "AssumedRole"
                        alert.update({
                            "severity": "critical" if is_chained else "high",
                            "urgency": 1 if is_chained else 2,
                            "tactic": "Lateral Movement", "technique": "T1550.001",
                            "technique_name": "Use Alternate Authentication Material: Application Access Token",
                            "is_chained_assumption": str(is_chained).lower(),
                            "target_account_id": target_account,
                        })

        elif detection_id == "CDET-013":
            if event_name == "AuthorizeSecurityGroupIngress":
                perms = rp.get("ipPermissions", {})
                ip_ranges = []
                if isinstance(perms, dict):
                    for item in perms.get("items", []):
                        for cidr_item in item.get("ipRanges", {}).get("items", []):
                            ip_ranges.append(cidr_item.get("cidrIp", ""))
                elif isinstance(perms, list):
                    for item in perms:
                        for cidr_item in item.get("ipRanges", []):
                            ip_ranges.append(cidr_item.get("cidrIp", ""))
                if any(c in ("0.0.0.0/0", "::/0") for c in ip_ranges):
                    fired = True
                    alert.update({
                        "severity": "high", "urgency": 2,
                        "tactic": "Defense Evasion", "technique": "T1562.007",
                        "technique_name": "Impair Defenses: Disable or Modify Cloud Firewall",
                        "group_id": rp.get("groupId", ""),
                        "cidr_range": "0.0.0.0/0",
                    })

        elif detection_id == "CDET-014":
            if event_name in ("DeleteObject", "DeleteObjects", "DeleteBucket"):
                # AWSService exclusion
                if principal_type == "AWSService":
                    continue
                bucket = rp.get("bucketName", rp.get("Bucket", ""))
                _CLOUDTRAIL_BUCKETS = {"example-org-cloudtrail-logs", "example-org-cloudtrail-secondary"}
                if bucket in _CLOUDTRAIL_BUCKETS:
                    fired = True
                    alert.update({
                        "severity": "critical", "urgency": 1,
                        "tactic": "Defense Evasion", "technique": "T1070.004",
                        "technique_name": "Indicator Removal: File Deletion",
                        "bucket_name": bucket,
                        "deletion_type": (
                            "CRITICAL: Entire CloudTrail log bucket deleted"
                            if event_name == "DeleteBucket"
                            else "Batch or single CloudTrail log deletion"
                        ),
                    })

        elif detection_id == "CDET-010":
            # Aggregate events — handled separately in _run_aggregation_detection
            continue

        elif detection_id == "CDET-008":
            # Aggregate events — handled separately
            continue

        if fired:
            alerts.append(alert)

    # Handle aggregation-based detections
    if detection_id == "CDET-008":
        alerts.extend(_eval_cdet008(events, _SUPPRESSED_ARNS))
    elif detection_id == "CDET-010":
        alerts.extend(_eval_cdet010(events, _SUPPRESSED_ARNS))

    return alerts


def _eval_cdet008(
    events: list[dict[str, Any]],
    suppressed: set[str],
) -> list[dict[str, Any]]:
    from collections import defaultdict
    counts: dict[str, dict[str, Any]] = defaultdict(lambda: {"total": 0, "apis": set(), "ips": set()})
    for e in events:
        uid = e.get("userIdentity", {})
        arn = uid.get("arn", uid.get("principalId", "unknown"))
        if arn in suppressed:
            continue
        if not e.get("readOnly", True):
            continue
        counts[arn]["total"] += 1
        counts[arn]["apis"].add(e.get("eventName", ""))
        counts[arn]["ips"].add(e.get("sourceIPAddress", ""))

    alerts = []
    for arn, data in counts.items():
        if data["total"] >= 50 and len(data["apis"]) >= 5:
            alerts.append({
                "detection_id": "CDET-008",
                "severity": "medium", "urgency": 3,
                "tactic": "Discovery", "technique": "T1580",
                "technique_name": "Cloud Infrastructure Discovery",
                "principal_arn": arn,
                "total_calls": data["total"],
                "unique_api_calls": len(data["apis"]),
                "event_source_ip": list(data["ips"])[0] if data["ips"] else "",
                "region": "us-east-1",
            })
    return alerts


def _eval_cdet010(
    events: list[dict[str, Any]],
    suppressed: set[str],
) -> list[dict[str, Any]]:
    from collections import defaultdict
    by_principal: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "estimated": 0, "buckets": set(), "ip": ""}
    )
    for e in events:
        uid = e.get("userIdentity", {})
        if uid.get("type") == "AWSService":
            continue
        arn = uid.get("arn", "unknown")
        if arn in suppressed:
            continue
        ev = e.get("eventName", "")
        if ev not in ("DeleteObject", "DeleteObjects", "DeleteBucket"):
            continue
        d = by_principal[arn]
        d["count"] += 1
        d["estimated"] += 100 if ev == "DeleteObjects" else (1000 if ev == "DeleteBucket" else 1)
        rp = e.get("requestParameters") or {}
        d["buckets"].add(rp.get("bucketName", rp.get("Bucket", "unknown")))
        d["ip"] = e.get("sourceIPAddress", "")

    alerts = []
    for arn, d in by_principal.items():
        if d["estimated"] >= 100 or d["count"] >= 20:
            alerts.append({
                "detection_id": "CDET-010",
                "severity": "critical", "urgency": 1,
                "tactic": "Impact", "technique": "T1485",
                "technique_name": "Data Destruction",
                "principal_arn": arn,
                "total_delete_events": d["count"],
                "estimated_objects_deleted": d["estimated"],
                "buckets_targeted": len(d["buckets"]),
                "bucket_names_str": ", ".join(d["buckets"]),
                "event_source_ip": d["ip"],
                "region": "us-east-1",
            })
    return alerts


# ── Evaluator ─────────────────────────────────────────────────────────────────

def _evaluate_test_case(test_case: TestCase) -> ValidationResult:
    """Run a single test case and return a ValidationResult."""
    events = _load_ndjson(ROOT / test_case.sample_file)

    if not events and test_case.test_case_type == TestCaseType.POSITIVE:
        return ValidationResult(
            detection_id=test_case.detection_id,
            test_case_type=test_case.test_case_type,
            test_name=test_case.name,
            result=TestResult.SKIP,
            alert_count=0,
            errors=[f"Sample file not found: {test_case.sample_file}"],
        )

    alerts = _run_heuristic_detection(test_case.detection_id, events)
    assertion = test_case.alert_assertion

    errors: list[str] = []
    field_results: list[FieldResult] = []

    if assertion.should_fire:
        if not alerts:
            errors.append(
                f"Expected detection to fire but got 0 alerts "
                f"from {len(events)} events"
            )
        else:
            first = alerts[0]
            for fa in assertion.field_assertions:
                passed, reason = fa.evaluate(first)
                field_results.append(FieldResult(fa.field_name, passed, reason))
                if not passed:
                    errors.append(f"Field assertion failed: {reason}")

            if assertion.expected_severity and first.get("severity") != assertion.expected_severity:
                errors.append(
                    f"Severity mismatch: expected={assertion.expected_severity}, "
                    f"got={first.get('severity')}"
                )
    else:
        if alerts:
            errors.append(
                f"Expected NO alerts but got {len(alerts)} "
                f"(suppression may be incomplete)"
            )

    result = TestResult.PASS if not errors else TestResult.FAIL

    return ValidationResult(
        detection_id=test_case.detection_id,
        test_case_type=test_case.test_case_type,
        test_name=test_case.name,
        result=result,
        alert_count=len(alerts),
        field_results=field_results,
        errors=errors,
    )


# ── Report writer ──────────────────────────────────────────────────────────────

def _write_report(summary: ValidationRunSummary, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = summary.run_timestamp.replace(":", "").replace("-", "")[:15]
    report_path = output_dir / f"validation_run_{ts}.json"

    def _to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            from dataclasses import asdict
            return asdict(obj)
        if hasattr(obj, "value"):
            return obj.value
        return str(obj)

    import dataclasses
    report_path.write_text(
        json.dumps(dataclasses.asdict(summary), default=str, indent=2),
        encoding="utf-8",
    )
    logger.info("validation_report_written", path=str(report_path))
    return report_path


# ── CLI entry point ────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run detection validation tests against sample NDJSON data."
    )
    parser.add_argument("--detection", help="Run tests for a single detection ID (e.g. CDET-001)")
    parser.add_argument("--all", action="store_true", help="Run tests for all detections")
    parser.add_argument(
        "--output-dir",
        default="data/validation_results",
        help="Directory to write validation reports (default: data/validation_results)",
    )
    args = parser.parse_args(argv)

    if not args.detection and not args.all:
        parser.error("Specify --detection CDET-XXX or --all")

    test_cases_by_detection = _load_test_case_definitions()

    if args.detection:
        did = args.detection.upper()
        if did not in test_cases_by_detection:
            print(f"No test cases found for {did}. Check validation/test_cases/ directory.")
            return 1
        run_detections = [did]
    else:
        run_detections = sorted(test_cases_by_detection.keys())

    run_id = str(uuid.uuid4())[:8]
    run_timestamp = datetime.utcnow().isoformat()
    summaries: list[DetectionValidationSummary] = []

    for did in run_detections:
        cases = test_cases_by_detection.get(did, [])
        dsummary = DetectionValidationSummary(detection_id=did)

        for tc in cases:
            result = _evaluate_test_case(tc)
            status = "PASS" if result.passed else "FAIL"
            icon = "✓" if result.passed else "✗"
            print(f"  {icon} {result.test_name}: {status}")
            if result.errors:
                for err in result.errors:
                    print(f"      → {err}")

            if tc.test_case_type.value == "positive":
                dsummary.positive_result = result
            elif tc.test_case_type.value == "negative":
                dsummary.negative_result = result
            else:
                dsummary.edge_result = result

        promotion_ready = "✓ Ready" if dsummary.ready_for_promotion else "✗ Not ready"
        print(f"  └─ {did}: {promotion_ready} for promotion\n")
        summaries.append(dsummary)

    passed = sum(1 for s in summaries if s.all_passed)
    failed = len(summaries) - passed
    coverage = round(passed / len(summaries) * 100, 1) if summaries else 0.0

    run_summary = ValidationRunSummary(
        run_id=run_id,
        run_timestamp=run_timestamp,
        detections_tested=len(summaries),
        detections_passed=passed,
        detections_failed=failed,
        detections_skipped=0,
        results=summaries,
        coverage_percent=coverage,
    )

    print(f"\n{'='*60}")
    print(f"Validation Run {run_id}")
    print(f"Tested: {len(summaries)}  Passed: {passed}  Failed: {failed}")
    print(f"Coverage: {coverage}%")
    print(f"{'='*60}\n")

    output_dir = ROOT / args.output_dir
    report_path = _write_report(run_summary, output_dir)
    print(f"Report written to: {report_path}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
