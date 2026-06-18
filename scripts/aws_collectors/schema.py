"""
Common internal schema for normalized AWS security telemetry.

All collectors output dicts conforming to these dataclasses so downstream
detection logic and validation frameworks operate against a single interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class CloudTrailEvent:
    """Normalized CloudTrail event."""

    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    source_ip_address: str
    user_agent: str
    user_identity_type: str
    user_identity_arn: str | None
    user_identity_account_id: str | None
    assumed_role_arn: str | None
    error_code: str | None
    error_message: str | None
    request_parameters: dict[str, Any] = field(default_factory=dict)
    response_elements: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class IAMUser:
    """Normalized IAM user record."""

    user_id: str
    user_name: str
    arn: str
    created: datetime
    password_last_used: datetime | None
    mfa_active: bool
    access_keys: list[IAMAccessKey] = field(default_factory=list)
    attached_policies: list[str] = field(default_factory=list)
    inline_policy_names: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)


@dataclass
class IAMRole:
    """Normalized IAM role record."""

    role_id: str
    role_name: str
    arn: str
    created: datetime
    assume_role_policy: dict[str, Any] = field(default_factory=dict)
    attached_policies: list[str] = field(default_factory=list)
    inline_policy_names: list[str] = field(default_factory=list)


@dataclass
class IAMAccessKey:
    """Normalized IAM access key record."""

    access_key_id: str
    user_name: str
    status: str  # Active | Inactive
    created: datetime
    last_used: datetime | None
    last_used_region: str | None
    last_used_service: str | None


@dataclass
class SecurityGroupRule:
    """Normalized security group ingress or egress rule."""

    group_id: str
    group_name: str
    vpc_id: str | None
    direction: str  # ingress | egress
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr_ranges: list[str] = field(default_factory=list)
    ipv6_cidr_ranges: list[str] = field(default_factory=list)
    publicly_exposed: bool = False


@dataclass
class SecurityHubFinding:
    """Normalized Security Hub finding."""

    finding_id: str
    title: str
    description: str
    severity: Severity
    severity_score: float
    compliance_status: str | None
    workflow_status: str
    record_state: str
    product_name: str
    generator_id: str
    created: datetime
    updated: datetime
    resource_type: str | None
    resource_id: str | None
    aws_account_id: str
    region: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardDutyFinding:
    """Normalized GuardDuty finding."""

    finding_id: str
    title: str
    description: str
    severity: float
    severity_label: Severity
    finding_type: str
    region: str
    aws_account_id: str
    created: datetime
    updated: datetime
    resource_type: str | None
    resource_id: str | None
    threat_intelligence_details: list[dict[str, Any]] = field(default_factory=list)
    action_type: str | None = None
    remote_ip_address: str | None = None
    remote_country_code: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
