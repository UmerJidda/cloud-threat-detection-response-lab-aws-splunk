"""
Unit tests for AWS collector normalization logic.

These tests exercise the _normalize() methods and schema dataclasses without
making real AWS API calls.  Use moto for integration-level tests.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from scripts.aws_collectors.schema import (
    CloudTrailEvent,
    GuardDutyFinding,
    IAMAccessKey,
    IAMRole,
    IAMUser,
    SecurityGroupRule,
    SecurityHubFinding,
    Severity,
)


# ─────────────────────────────────────────────────────────────────────
# CloudTrail
# ─────────────────────────────────────────────────────────────────────

class TestCloudTrailCollectorNormalize:
    def _make_collector(self) -> object:
        from scripts.aws_collectors.cloudtrail_collector import CloudTrailCollector

        with patch("boto3.Session"):
            return CloudTrailCollector(region="us-east-1")

    def _raw_event(self, event_name: str = "CreateUser") -> dict:
        payload = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
            },
            "eventTime": "2024-01-15T10:30:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": event_name,
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.5",
            "userAgent": "aws-cli/2.15.0",
            "requestParameters": {"userName": "mallory"},
            "responseElements": {},
        }
        return {
            "EventId": "abc-123",
            "EventName": event_name,
            "EventTime": datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            "EventSource": "iam.amazonaws.com",
            "CloudTrailEvent": json.dumps(payload),
        }

    def test_normalize_returns_cloudtrail_event(self) -> None:
        collector = self._make_collector()
        event = collector._normalize(self._raw_event("CreateUser"))
        assert isinstance(event, CloudTrailEvent)
        assert event.event_name == "CreateUser"
        assert event.source_ip_address == "203.0.113.5"
        assert event.user_identity_type == "IAMUser"
        assert event.user_identity_arn == "arn:aws:iam::123456789012:user/alice"

    def test_normalize_returns_none_on_bad_json(self) -> None:
        collector = self._make_collector()
        result = collector._normalize(
            {"EventId": "x", "CloudTrailEvent": "not-json"}
        )
        assert result is None

    def test_normalize_captures_error_code(self) -> None:
        raw = self._raw_event("CreateUser")
        payload = json.loads(raw["CloudTrailEvent"])
        payload["errorCode"] = "AccessDenied"
        payload["errorMessage"] = "User is not authorized"
        raw["CloudTrailEvent"] = json.dumps(payload)
        collector = self._make_collector()
        event = collector._normalize(raw)
        assert event is not None
        assert event.error_code == "AccessDenied"


# ─────────────────────────────────────────────────────────────────────
# GuardDuty
# ─────────────────────────────────────────────────────────────────────

class TestGuardDutyCollectorNormalize:
    def _make_collector(self) -> object:
        from scripts.aws_collectors.guardduty_collector import GuardDutyCollector

        with patch("boto3.Session"):
            return GuardDutyCollector(region="us-east-1")

    def _raw_finding(self, severity: float = 7.5) -> dict:
        return {
            "Id": "gd-001",
            "Title": "Unusual IAM AssumeRole activity",
            "Description": "A principal assumed a role from an unusual location.",
            "Severity": severity,
            "Type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "Region": "us-east-1",
            "AccountId": "123456789012",
            "CreatedAt": "2024-01-15T10:00:00Z",
            "UpdatedAt": "2024-01-15T10:05:00Z",
            "Resource": {
                "ResourceType": "Instance",
                "InstanceDetails": {"InstanceId": "i-0abc123"},
            },
            "Service": {
                "Action": {
                    "ActionType": "NETWORK_CONNECTION",
                    "NetworkConnectionAction": {
                        "RemoteIpDetails": {
                            "IpAddressV4": "198.51.100.22",
                            "Country": {"CountryCode": "RU"},
                        }
                    },
                }
            },
        }

    def test_normalize_returns_guardduty_finding(self) -> None:
        collector = self._make_collector()
        finding = collector._normalize(self._raw_finding(7.5))
        assert isinstance(finding, GuardDutyFinding)
        assert finding.severity == 7.5
        assert finding.severity_label == Severity.HIGH
        assert finding.remote_ip_address == "198.51.100.22"
        assert finding.remote_country_code == "RU"
        assert finding.resource_id == "i-0abc123"

    def test_severity_label_medium(self) -> None:
        collector = self._make_collector()
        finding = collector._normalize(self._raw_finding(5.0))
        assert finding is not None
        assert finding.severity_label == Severity.MEDIUM

    def test_normalize_returns_none_on_missing_required_field(self) -> None:
        collector = self._make_collector()
        result = collector._normalize({"Severity": "not-a-number"})
        assert result is None


# ─────────────────────────────────────────────────────────────────────
# Security Group
# ─────────────────────────────────────────────────────────────────────

class TestSecurityGroupCollectorNormalize:
    def _make_collector(self) -> object:
        from scripts.aws_collectors.security_group_collector import SecurityGroupCollector

        with patch("boto3.Session"):
            return SecurityGroupCollector(region="us-east-1")

    def _raw_sg(self) -> dict:
        return {
            "GroupId": "sg-0abc12345",
            "GroupName": "web-tier",
            "VpcId": "vpc-0def67890",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                },
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }

    def test_public_ingress_flagged(self) -> None:
        collector = self._make_collector()
        rules = list(collector._normalize_sg(self._raw_sg()))
        public_ingress = [r for r in rules if r.direction == "ingress" and r.publicly_exposed]
        assert len(public_ingress) == 1
        assert public_ingress[0].from_port == 443

    def test_private_ingress_not_flagged(self) -> None:
        collector = self._make_collector()
        rules = list(collector._normalize_sg(self._raw_sg()))
        ssh_rule = next(r for r in rules if r.from_port == 22 and r.direction == "ingress")
        assert not ssh_rule.publicly_exposed

    def test_rule_count(self) -> None:
        collector = self._make_collector()
        rules = list(collector._normalize_sg(self._raw_sg()))
        assert len(rules) == 3  # 2 ingress + 1 egress


# ─────────────────────────────────────────────────────────────────────
# Schema dataclasses
# ─────────────────────────────────────────────────────────────────────

class TestSchema:
    def test_severity_enum_values(self) -> None:
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"

    def test_iam_user_defaults(self) -> None:
        user = IAMUser(
            user_id="AIDAXXXXXXXX",
            user_name="alice",
            arn="arn:aws:iam::123456789012:user/alice",
            created=datetime.now(tz=timezone.utc),
            password_last_used=None,
            mfa_active=False,
        )
        assert user.access_keys == []
        assert user.attached_policies == []
        assert user.groups == []
