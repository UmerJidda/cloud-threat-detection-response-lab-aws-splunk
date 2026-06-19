"""
detection_validator.py — Heuristic detection logic validator.

Mirrors the SPL detection rules in Python so sample data can be validated
without a running Splunk instance. Each detector checks a list of ParsedEvent
objects against the detection's trigger conditions and returns a structured result.

This is NOT a replacement for Splunk — it is a pre-ingestion quality gate for
sample data and detection logic review.

Usage:
    from scripts.detection_validator import run_validation, load_all_validators

    validators = load_all_validators()
    events = list(CloudTrailParser().parse_file(Path("sample_logs/.../CDET-001.ndjson")))
    result = run_validation("CDET-001", events, validators)
    print(result.passed, result.summary)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

import structlog

from scripts.cloudtrail_parser import ParsedEvent

logger = structlog.get_logger(__name__)

# ── result types ──────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    detection_id: str
    test_name: str
    should_fire: bool
    fired: bool
    matched_events: list[str] = field(default_factory=list)  # event IDs
    field_checks: list[tuple[str, bool, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.should_fire == self.fired

    @property
    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        fired_str = "fired" if self.fired else "did not fire"
        expected_str = "expected to fire" if self.should_fire else "expected to NOT fire"
        return f"[{status}] {self.detection_id}/{self.test_name}: {fired_str} ({expected_str})"


DetectorFn = Callable[[list[ParsedEvent]], list[ParsedEvent]]


@dataclass
class Validator:
    detection_id: str
    name: str
    detector: DetectorFn


# ── suppression lookups (loaded at module level from splunk/lookups/) ─────────

def _load_csv_column(path: Path, column: str) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    import csv
    values: set[str] = set()
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            val = row.get(column, "").strip()
            if val:
                values.add(val)
    return frozenset(values)


_LOOKUPS = Path("splunk/lookups")
_APPROVED_PRINCIPALS = _load_csv_column(_LOOKUPS / "approved_iam_principals.csv", "principal_arn")
_AUTOMATION_ROLES = _load_csv_column(_LOOKUPS / "automation_role_arns.csv", "role_arn")
_ADMIN_POLICIES = _load_csv_column(_LOOKUPS / "admin_policy_arns.csv", "policy_arn")
_APPROVED_ACCOUNTS = _load_csv_column(_LOOKUPS / "approved_aws_accounts.csv", "account_id")
_APPROVED_CIDRS = _load_csv_column(_LOOKUPS / "approved_cidr_ranges.csv", "cidr")
_SUSPICIOUS_TYPES = _load_csv_column(_LOOKUPS / "suspicious_instance_types.csv", "instance_type")


def _is_approved(event: ParsedEvent) -> bool:
    arn = event.identity_arn or ""
    issuer = event.session_issuer_arn or ""
    return (
        arn in _APPROVED_PRINCIPALS
        or issuer in _APPROVED_PRINCIPALS
        or any(issuer.endswith(r.split("/")[-1]) for r in _AUTOMATION_ROLES if r)
        or issuer in _AUTOMATION_ROLES
    )


# ── per-detection detector functions ─────────────────────────────────────────

def _detect_001(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-001: IAM user created by non-pipeline principal."""
    return [
        e for e in events
        if e.event_name == "CreateUser"
        and e.event_source == "iam.amazonaws.com"
        and not e.is_error
        and not _is_approved(e)
    ]


def _detect_002(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-002: Access key created for a different user (not self-service)."""
    return [
        e for e in events
        if e.event_name == "CreateAccessKey"
        and e.event_source == "iam.amazonaws.com"
        and not e.is_error
        and not _is_approved(e)
        and e.request_parameters.get("userName") != e.identity_username
    ]


def _detect_003(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-003: CloudTrail logging disabled or trail deleted."""
    return [
        e for e in events
        if e.event_source == "cloudtrail.amazonaws.com"
        and e.event_name in {"StopLogging", "DeleteTrail"}
        and not e.is_error
    ]


def _detect_004(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-004: Admin policy attached to IAM principal."""
    return [
        e for e in events
        if e.event_name in {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
        and e.event_source == "iam.amazonaws.com"
        and not e.is_error
        and not _is_approved(e)
        and e.request_parameters.get("policyArn", "") in _ADMIN_POLICIES
    ]


def _detect_005(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-005: Cross-account role trust modified to external account."""
    results = []
    for e in events:
        if e.event_name != "UpdateAssumeRolePolicy" or e.is_error:
            continue
        policy_doc = e.request_parameters.get("policyDocument", "")
        if isinstance(policy_doc, dict):
            policy_str = json.dumps(policy_doc)
        else:
            policy_str = str(policy_doc)
        import re
        account_ids = set(re.findall(r'"arn:aws[^"]*:([0-9]{12}):[^"]*"', policy_str))
        external = account_ids - _APPROVED_ACCOUNTS - {e.identity_account_id or ""}
        if external:
            results.append(e)
    return results


def _detect_006(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-006: Root account activity (any event)."""
    return [e for e in events if e.is_root]


def _detect_007(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-007: EC2 metadata credentials used from external/routable IP."""
    import ipaddress
    _PRIVATE = [
        ipaddress.ip_network(n) for n in
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    ]
    results = []
    for e in events:
        if e.identity_type != "AssumedRole" or not e.session_issuer_arn:
            continue
        if e.source_ip_address in ("169.254.169.254", "AWS Internal"):
            continue
        try:
            addr = ipaddress.ip_address(e.source_ip_address)
            if any(addr in net for net in _PRIVATE):
                continue
        except ValueError:
            continue
        if "ec2.amazonaws.com" in (e.session_issuer_arn or ""):
            continue
        results.append(e)
    return results


def _detect_008(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-008: Excessive API enumeration — >50 read-only calls per principal per 5 min."""
    from collections import defaultdict
    from datetime import timedelta

    window = timedelta(minutes=5)
    threshold = 50
    read_apis = {"Describe", "List", "Get", "Scan"}

    by_principal: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in events:
        if any(e.event_name.startswith(p) for p in read_apis):
            key = e.identity_arn or e.identity_username or "unknown"
            by_principal[key].append(e)

    results = []
    for _principal, evts in by_principal.items():
        evts.sort(key=lambda x: x.event_time)
        for i, start in enumerate(evts):
            window_evts = [e for e in evts[i:] if e.event_time - start.event_time <= window]
            if len(window_evts) >= threshold:
                results.extend(window_evts)
                break
    return list({e.event_id: e for e in results}.values())


def _detect_009(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-009: S3 replication configured to external account."""
    import re
    results = []
    for e in events:
        if e.event_name != "PutBucketReplication" or e.is_error:
            continue
        policy_str = json.dumps(e.request_parameters)
        accounts = set(re.findall(r'"account":\s*"([0-9]{12})"', policy_str))
        external = accounts - _APPROVED_ACCOUNTS
        if external:
            results.append(e)
    return results


def _detect_010(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-010: Mass S3 object deletion — >50 objects in a single DeleteObjects call."""
    results = []
    for e in events:
        if e.event_name != "DeleteObjects" or e.is_error:
            continue
        delete_payload = e.request_parameters.get("Delete", {})
        objects = delete_payload.get("objects", [])
        if isinstance(objects, list) and len(objects) >= 50:
            results.append(e)
    return results


def _detect_011(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-011: RunInstances by non-approved principal with suspicious type/region."""
    results = []
    for e in events:
        if e.event_name != "RunInstances" or e.is_error:
            continue
        if _is_approved(e):
            continue
        instance_type = e.request_parameters.get("instanceType", "")
        if instance_type in _SUSPICIOUS_TYPES:
            results.append(e)
            continue
    return results


def _detect_012(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-012: Cross-account AssumeRole to unapproved account."""
    results = []
    for e in events:
        if e.event_name != "AssumeRole" or e.is_error:
            continue
        role_arn = e.request_parameters.get("roleArn", "")
        if not role_arn:
            continue
        parts = role_arn.split(":")
        if len(parts) >= 5:
            target_account = parts[4]
            if target_account != e.identity_account_id and target_account not in _APPROVED_ACCOUNTS:
                results.append(e)
    return results


def _detect_013(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-013: Security group rule opening ingress to 0.0.0.0/0 or ::/0."""
    results = []
    for e in events:
        if e.event_name not in {"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"}:
            continue
        if e.is_error:
            continue
        ip_perms = e.request_parameters.get("ipPermissions", {})
        items = ip_perms.get("items", []) if isinstance(ip_perms, dict) else []
        for perm in items:
            for ip_range in perm.get("ipRanges", {}).get("items", []):
                if ip_range.get("cidrIp", "") in ("0.0.0.0/0",):
                    results.append(e)
                    break
            for ipv6_range in perm.get("ipv6Ranges", {}).get("items", []):
                if ipv6_range.get("cidrIpv6", "") == "::/0":
                    results.append(e)
                    break
    return results


def _detect_014(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """CDET-014: S3 DeleteObject on a bucket/key matching CloudTrail log pattern."""
    import re
    _CT_PATTERN = re.compile(r"AWSLogs/[0-9]{12}/CloudTrail/")
    results = []
    for e in events:
        if e.event_name not in {"DeleteObject", "DeleteObjects"} or e.is_error:
            continue
        key = e.request_parameters.get("key", "")
        if _CT_PATTERN.search(key):
            results.append(e)
    return results


# ── registry ──────────────────────────────────────────────────────────────────

_DETECTORS: dict[str, DetectorFn] = {
    "CDET-001": _detect_001,
    "CDET-002": _detect_002,
    "CDET-003": _detect_003,
    "CDET-004": _detect_004,
    "CDET-005": _detect_005,
    "CDET-006": _detect_006,
    "CDET-007": _detect_007,
    "CDET-008": _detect_008,
    "CDET-009": _detect_009,
    "CDET-010": _detect_010,
    "CDET-011": _detect_011,
    "CDET-012": _detect_012,
    "CDET-013": _detect_013,
    "CDET-014": _detect_014,
}


def load_all_validators() -> dict[str, Validator]:
    return {
        cdet_id: Validator(
            detection_id=cdet_id,
            name=f"{cdet_id} heuristic",
            detector=fn,
        )
        for cdet_id, fn in _DETECTORS.items()
    }


def run_validation(
    detection_id: str,
    events: list[ParsedEvent],
    validators: dict[str, Validator] | None = None,
    should_fire: bool = True,
    test_name: str = "positive",
) -> ValidationResult:
    """Run a single detection against a list of events."""
    if validators is None:
        validators = load_all_validators()

    validator = validators.get(detection_id)
    if validator is None:
        return ValidationResult(
            detection_id=detection_id,
            test_name=test_name,
            should_fire=should_fire,
            fired=False,
            errors=[f"No validator registered for {detection_id}"],
        )

    try:
        matched = validator.detector(events)
        return ValidationResult(
            detection_id=detection_id,
            test_name=test_name,
            should_fire=should_fire,
            fired=len(matched) > 0,
            matched_events=[e.event_id for e in matched],
        )
    except Exception as exc:
        logger.error("validator_error", detection_id=detection_id, error=str(exc))
        return ValidationResult(
            detection_id=detection_id,
            test_name=test_name,
            should_fire=should_fire,
            fired=False,
            errors=[str(exc)],
        )


# ── unit-test examples ────────────────────────────────────────────────────────

def _example_tests() -> None:
    from scripts.cloudtrail_parser import CloudTrailParser

    parser = CloudTrailParser()
    validators = load_all_validators()

    # CDET-001 positive: unknown principal creating user
    raw_001 = {
        "eventID": "test-001-pos",
        "eventTime": "2024-01-15T14:02:11Z",
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.77",
        "userAgent": "aws-cli",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/attacker",
                         "accountId": "123456789012", "userName": "attacker"},
        "requestParameters": {"userName": "backdoor-user"},
    }
    e = parser.parse_dict(raw_001)
    result = run_validation("CDET-001", [e], validators, should_fire=True)
    assert result.passed, f"CDET-001 positive failed: {result.summary}"

    # CDET-003 positive: StopLogging
    raw_003 = {
        "eventID": "test-003-pos",
        "eventTime": "2024-01-15T14:02:11Z",
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.77",
        "userAgent": "aws-cli",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/attacker",
                         "accountId": "123456789012", "userName": "attacker"},
        "requestParameters": {"name": "management-events-trail"},
    }
    e = parser.parse_dict(raw_003)
    result = run_validation("CDET-003", [e], validators, should_fire=True)
    assert result.passed, f"CDET-003 positive failed: {result.summary}"

    # CDET-006 positive: Root activity
    raw_006 = {
        "eventID": "test-006-pos",
        "eventTime": "2024-01-15T14:02:11Z",
        "eventName": "GetCallerIdentity",
        "eventSource": "sts.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.77",
        "userAgent": "aws-cli",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root",
                         "accountId": "123456789012"},
    }
    e = parser.parse_dict(raw_006)
    result = run_validation("CDET-006", [e], validators, should_fire=True)
    assert result.passed, f"CDET-006 positive failed: {result.summary}"

    print("All detection validator assertions passed.")


if __name__ == "__main__":
    _example_tests()
