"""
ioc_extractor.py — Extract Indicators of Compromise from CloudTrail events.

Scans parsed events and alert records to extract structured IOCs: IP addresses,
IAM ARNs, access key IDs, S3 object paths, EC2 instance IDs, and other
artefacts that investigators use for pivot queries and blocking.

Usage:
    from scripts.ioc_extractor import IoCExtractor
    from scripts.cloudtrail_parser import CloudTrailParser

    parser = CloudTrailParser()
    extractor = IoCExtractor()

    events = list(parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-001.ndjson")))
    report = extractor.extract_from_events(events)
    print(report.summary())
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

from scripts.cloudtrail_parser import ParsedEvent

logger = structlog.get_logger(__name__)

# ── regex patterns ─────────────────────────────────────────────────────────────
_ARN_RE = re.compile(r"arn:aws[a-z\-]*:[a-z0-9\-]*:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+")
_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b")
_ACCOUNT_ID_RE = re.compile(r"\b[0-9]{12}\b")
_S3_PATH_RE = re.compile(r"s3://[a-z0-9.\-/]+")
_INSTANCE_ID_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b")
_ROLE_SESSION_RE = re.compile(r":assumed-role/([^/]+)/([^\"'\s]+)")


class IoCType(str, Enum):
    IP_ADDRESS = "ip_address"
    IAM_ARN = "iam_arn"
    ACCESS_KEY_ID = "access_key_id"
    AWS_ACCOUNT_ID = "aws_account_id"
    S3_PATH = "s3_path"
    EC2_INSTANCE_ID = "ec2_instance_id"
    ASSUMED_ROLE_SESSION = "assumed_role_session"
    HOSTNAME = "hostname"


@dataclass
class IoC:
    """A single extracted indicator of compromise."""

    ioc_type: IoCType
    value: str
    first_seen: datetime
    last_seen: datetime
    source_events: list[str] = field(default_factory=list)  # event IDs
    context: dict[str, Any] = field(default_factory=dict)
    count: int = 1

    def merge(self, other: "IoC") -> None:
        """Update timestamps and merge source events from a duplicate."""
        if other.first_seen < self.first_seen:
            self.first_seen = other.first_seen
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
        self.source_events = list(set(self.source_events + other.source_events))
        self.count += 1


@dataclass
class IoCReport:
    """Aggregated IOC extraction result across a set of events."""

    extraction_time: datetime
    event_count: int
    iocs: list[IoC] = field(default_factory=list)

    def by_type(self, ioc_type: IoCType) -> list[IoC]:
        return [i for i in self.iocs if i.ioc_type == ioc_type]

    @property
    def ip_addresses(self) -> list[str]:
        return [i.value for i in self.by_type(IoCType.IP_ADDRESS)]

    @property
    def iam_arns(self) -> list[str]:
        return [i.value for i in self.by_type(IoCType.IAM_ARN)]

    @property
    def access_keys(self) -> list[str]:
        return [i.value for i in self.by_type(IoCType.ACCESS_KEY_ID)]

    def summary(self) -> str:
        lines = [
            f"IoC Report — {self.event_count} events, {len(self.iocs)} indicators",
            f"  IP addresses:      {len(self.ip_addresses)}",
            f"  IAM ARNs:          {len(self.iam_arns)}",
            f"  Access keys:       {len(self.access_keys)}",
            f"  AWS account IDs:   {len(self.by_type(IoCType.AWS_ACCOUNT_ID))}",
            f"  EC2 instance IDs:  {len(self.by_type(IoCType.EC2_INSTANCE_ID))}",
            f"  S3 paths:          {len(self.by_type(IoCType.S3_PATH))}",
        ]
        return "\n".join(lines)


class IoCExtractor:
    """Extract and deduplicate IOCs from CloudTrail events or raw dicts."""

    # RFC 5737 / 1918 — exclude from external IP list
    _PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    def extract_from_events(self, events: list[ParsedEvent]) -> IoCReport:
        """Extract IOCs from a list of ParsedEvent objects."""
        ioc_map: dict[tuple[IoCType, str], IoC] = {}

        for event in events:
            self._process_event(event, ioc_map)

        return IoCReport(
            extraction_time=datetime.utcnow(),
            event_count=len(events),
            iocs=list(ioc_map.values()),
        )

    def extract_from_alert(self, alert: dict[str, Any]) -> IoCReport:
        """Extract IOCs from a Splunk-style alert dict."""
        ioc_map: dict[tuple[IoCType, str], IoC] = {}
        ts = datetime.utcnow()
        text = str(alert)

        self._extract_from_text(text, ts, "alert", ioc_map)

        # Named fields take priority over regex scraping
        for field_name in ("actor_arn", "creator_arn", "session_issuer_arn", "new_user_arn"):
            val = alert.get(field_name)
            if val:
                self._add(ioc_map, IoCType.IAM_ARN, val, ts, "alert")

        for field_name in ("event_source_ip", "sourceIPAddress"):
            val = alert.get(field_name)
            if val:
                self._add(ioc_map, IoCType.IP_ADDRESS, val, ts, "alert")

        return IoCReport(
            extraction_time=ts,
            event_count=1,
            iocs=list(ioc_map.values()),
        )

    # ── internal ──────────────────────────────────────────────────────────────

    def _process_event(
        self,
        event: ParsedEvent,
        ioc_map: dict[tuple[IoCType, str], IoC],
    ) -> None:
        ts = event.event_time
        eid = event.event_id

        # Direct fields
        if event.source_ip_address:
            self._add(ioc_map, IoCType.IP_ADDRESS, event.source_ip_address, ts, eid)
        if event.identity_arn:
            self._add(ioc_map, IoCType.IAM_ARN, event.identity_arn, ts, eid)
        if event.session_issuer_arn:
            self._add(ioc_map, IoCType.IAM_ARN, event.session_issuer_arn, ts, eid)
        if event.identity_account_id:
            self._add(ioc_map, IoCType.AWS_ACCOUNT_ID, event.identity_account_id, ts, eid)

        # Scan request parameters and response elements for additional artefacts
        for container in (event.request_parameters, event.response_elements, event.raw):
            text = str(container)
            self._extract_from_text(text, ts, eid, ioc_map)

    def _extract_from_text(
        self,
        text: str,
        ts: datetime,
        source_id: str,
        ioc_map: dict[tuple[IoCType, str], IoC],
    ) -> None:
        # Access keys
        for m in _ACCESS_KEY_RE.finditer(text):
            self._add(ioc_map, IoCType.ACCESS_KEY_ID, m.group(), ts, source_id)

        # ARNs (before account IDs to avoid false-positive account ID extraction)
        for m in _ARN_RE.finditer(text):
            self._add(ioc_map, IoCType.IAM_ARN, m.group(), ts, source_id)

        # EC2 instance IDs
        for m in _INSTANCE_ID_RE.finditer(text):
            self._add(ioc_map, IoCType.EC2_INSTANCE_ID, m.group(), ts, source_id)

        # S3 paths
        for m in _S3_PATH_RE.finditer(text):
            self._add(ioc_map, IoCType.S3_PATH, m.group(), ts, source_id)

        # Assumed-role session names (useful for pivot)
        for m in _ROLE_SESSION_RE.finditer(text):
            role_name, session_name = m.group(1), m.group(2)
            self._add(ioc_map, IoCType.ASSUMED_ROLE_SESSION,
                      f"{role_name}/{session_name}", ts, source_id,
                      context={"role_name": role_name, "session_name": session_name})

    def _add(
        self,
        ioc_map: dict[tuple[IoCType, str], IoC],
        ioc_type: IoCType,
        value: str,
        ts: datetime,
        source_id: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        if not value or value in ("null", "None", "unknown"):
            return

        # Skip AWS service endpoints used as sourceIPAddress
        if ioc_type == IoCType.IP_ADDRESS:
            if value.endswith(".amazonaws.com") or value == "AWS Internal":
                return
            try:
                addr = ipaddress.ip_address(value)
                if any(addr in net for net in self._PRIVATE_NETWORKS):
                    return  # skip RFC1918 and test-net addresses
            except ValueError:
                return  # not a valid IP

        key = (ioc_type, value)
        if key in ioc_map:
            ioc_map[key].merge(IoC(ioc_type, value, ts, ts, [source_id]))
        else:
            ioc_map[key] = IoC(
                ioc_type=ioc_type,
                value=value,
                first_seen=ts,
                last_seen=ts,
                source_events=[source_id],
                context=context or {},
            )


# ── unit-test examples ────────────────────────────────────────────────────────

def _example_tests() -> None:
    """Illustrative assertions — run with pytest or directly."""
    from datetime import timezone
    from scripts.cloudtrail_parser import CloudTrailParser

    raw = {
        "eventID": "abc123",
        "eventTime": "2024-01-15T14:02:11Z",
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.77",
        "userAgent": "aws-cli/2.13.0",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/attacker",
            "accountId": "123456789012",
        },
        "requestParameters": {"userName": "backdoor-user"},
        "responseElements": {
            "user": {
                "arn": "arn:aws:iam::123456789012:user/backdoor-user",
                "userId": "AIDAEXAMPLEBACKDOOR1",
            }
        },
    }
    parser = CloudTrailParser()
    event = parser.parse_dict(raw)
    assert event is not None

    extractor = IoCExtractor()
    report = extractor.extract_from_events([event])

    # 198.51.100.77 is TEST-NET-2 — should be excluded as private/test range
    assert "198.51.100.77" not in report.ip_addresses
    assert any("attacker" in arn for arn in report.iam_arns)
    assert report.event_count == 1

    print("All IoC extractor assertions passed.")
    print(report.summary())


if __name__ == "__main__":
    _example_tests()
