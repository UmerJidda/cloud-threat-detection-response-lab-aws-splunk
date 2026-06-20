"""
Security Group telemetry collector.

Enumerates EC2 security group rules across all VPCs in the configured region.
Flags rules that expose any port to the public internet (0.0.0.0/0 or ::/0).

Permissions required (read-only):
    ec2:DescribeSecurityGroups
    ec2:DescribeSecurityGroupRules  (optional; used when available)
"""

from __future__ import annotations

from typing import Any, Iterator

import structlog
from botocore.exceptions import ClientError

from .base_collector import BaseCollector
from .schema import SecurityGroupRule

logger = structlog.get_logger(__name__)

OPEN_CIDR_V4 = "0.0.0.0/0"
OPEN_CIDR_V6 = "::/0"


class SecurityGroupCollector(BaseCollector):
    """
    Collect and normalize EC2 security group rules, flagging public exposure.
    """

    @property
    def collector_name(self) -> str:
        return "security_groups"

    def collect(self) -> Iterator[SecurityGroupRule]:
        """Yield one SecurityGroupRule per ingress/egress permission entry."""
        ec2 = self._session.client("ec2")

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    yield from self._normalize_sg(sg)
        except ClientError as exc:
            self._log.error(
                "security_group_describe_failed",
                region=self.region,
                error=str(exc),
            )
            raise

    def _normalize_sg(self, sg: Any) -> Iterator[SecurityGroupRule]:
        group_id = sg["GroupId"]
        group_name = sg.get("GroupName", "")
        vpc_id = sg.get("VpcId")

        for rule in sg.get("IpPermissions", []):
            yield self._build_rule(group_id, group_name, vpc_id, "ingress", rule)

        for rule in sg.get("IpPermissionsEgress", []):
            yield self._build_rule(group_id, group_name, vpc_id, "egress", rule)

    @staticmethod
    def _build_rule(
        group_id: str,
        group_name: str,
        vpc_id: str | None,
        direction: str,
        rule: dict[str, Any],
    ) -> SecurityGroupRule:
        cidr_ranges = [r["CidrIp"] for r in rule.get("IpRanges", [])]
        ipv6_ranges = [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
        publicly_exposed = OPEN_CIDR_V4 in cidr_ranges or OPEN_CIDR_V6 in ipv6_ranges

        return SecurityGroupRule(
            group_id=group_id,
            group_name=group_name,
            vpc_id=vpc_id,
            direction=direction,
            protocol=rule.get("IpProtocol", "-1"),
            from_port=rule.get("FromPort"),
            to_port=rule.get("ToPort"),
            cidr_ranges=cidr_ranges,
            ipv6_cidr_ranges=ipv6_ranges,
            publicly_exposed=publicly_exposed,
        )
