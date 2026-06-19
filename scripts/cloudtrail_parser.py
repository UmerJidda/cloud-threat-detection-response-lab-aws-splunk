"""
cloudtrail_parser.py — Parse and normalize CloudTrail event records.

Reads raw CloudTrail JSON (either single-record JSON, NDJSON, or the S3
compressed archive format) and returns normalized CloudTrailEvent objects
suitable for detection logic or incident investigation.

Usage:
    from scripts.cloudtrail_parser import CloudTrailParser

    parser = CloudTrailParser()
    for event in parser.parse_file(Path("sample_logs/cloudtrail/malicious/CDET-001.ndjson")):
        print(event.event_name, event.user_identity_arn)
"""

from __future__ import annotations

import gzip
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ParsedEvent:
    """Normalized CloudTrail event with all investigatively-relevant fields."""

    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    source_ip_address: str
    user_agent: str
    # Identity
    identity_type: str
    identity_arn: str | None
    identity_account_id: str | None
    identity_username: str | None
    session_issuer_arn: str | None
    session_issuer_type: str | None
    mfa_authenticated: bool
    # Error
    error_code: str | None
    error_message: str | None
    # Payload
    request_parameters: dict[str, Any] = field(default_factory=dict)
    response_elements: dict[str, Any] = field(default_factory=dict)
    # Classification helpers (set by caller)
    is_read_only: bool = False
    is_management_event: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.error_code is not None

    @property
    def is_root(self) -> bool:
        return self.identity_type == "Root"

    @property
    def actor_label(self) -> str:
        """Human-readable label for the acting principal."""
        if self.identity_username:
            return self.identity_username
        if self.session_issuer_arn:
            return self.session_issuer_arn.split("/")[-1]
        return self.identity_arn or "unknown"


class CloudTrailParser:
    """
    Parse CloudTrail records from multiple source formats.

    Supports:
    - NDJSON (one JSON object per line)
    - Single JSON object
    - CloudTrail S3 archive format: {"Records": [...]}
    - Gzip-compressed files (.json.gz)
    """

    def parse_file(self, path: Path) -> Iterator[ParsedEvent]:
        """Yield ParsedEvent objects from a file at the given path."""
        log = logger.bind(path=str(path))
        if not path.exists():
            log.error("file_not_found")
            return

        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    yield from self._parse_text(fh.read(), log)
            else:
                yield from self._parse_text(path.read_text(encoding="utf-8"), log)
        except OSError as exc:
            log.error("file_read_error", error=str(exc))

    def parse_string(self, text: str) -> Iterator[ParsedEvent]:
        """Yield ParsedEvent objects from a raw string."""
        yield from self._parse_text(text, logger)

    def parse_dict(self, raw: dict[str, Any]) -> ParsedEvent | None:
        """Parse a single raw CloudTrail dict. Returns None on failure."""
        try:
            return self._normalize(raw)
        except Exception as exc:
            logger.warning("parse_failed", error=str(exc), event_name=raw.get("eventName"))
            return None

    # ── internal ──────────────────────────────────────────────────────────────

    def _parse_text(self, text: str, log: Any) -> Iterator[ParsedEvent]:
        text = text.strip()
        if not text:
            return

        # Try NDJSON first (most common in this repo)
        if text.startswith("{"):
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            for lineno, line in enumerate(lines, 1):
                try:
                    obj = json.loads(line)
                    # CloudTrail S3 archive wraps records in {"Records": [...]}
                    if "Records" in obj:
                        for record in obj["Records"]:
                            event = self._normalize(record)
                            if event:
                                yield event
                    else:
                        event = self._normalize(obj)
                        if event:
                            yield event
                except json.JSONDecodeError as exc:
                    log.warning("json_decode_error", lineno=lineno, error=str(exc))
        elif text.startswith("["):
            # JSON array
            try:
                records = json.loads(text)
                for record in records:
                    event = self._normalize(record)
                    if event:
                        yield event
            except json.JSONDecodeError as exc:
                log.error("json_array_decode_error", error=str(exc))

    def _normalize(self, raw: dict[str, Any]) -> ParsedEvent | None:
        """Convert a raw CloudTrail dict to a ParsedEvent."""
        if not isinstance(raw, dict):
            return None

        identity = raw.get("userIdentity", {})
        session_ctx = identity.get("sessionContext", {})
        session_issuer = session_ctx.get("sessionIssuer", {})
        attrs = session_ctx.get("attributes", {})

        event_time = self._parse_time(raw.get("eventTime", ""))
        if event_time is None:
            return None

        return ParsedEvent(
            event_id=raw.get("eventID", ""),
            event_time=event_time,
            event_name=raw.get("eventName", ""),
            event_source=raw.get("eventSource", ""),
            aws_region=raw.get("awsRegion", ""),
            source_ip_address=raw.get("sourceIPAddress", ""),
            user_agent=raw.get("userAgent", ""),
            identity_type=identity.get("type", ""),
            identity_arn=identity.get("arn"),
            identity_account_id=identity.get("accountId"),
            identity_username=identity.get("userName"),
            session_issuer_arn=session_issuer.get("arn"),
            session_issuer_type=session_issuer.get("type"),
            mfa_authenticated=attrs.get("mfaAuthenticated", "false").lower() == "true",
            error_code=raw.get("errorCode"),
            error_message=raw.get("errorMessage"),
            request_parameters=raw.get("requestParameters") or {},
            response_elements=raw.get("responseElements") or {},
            is_read_only=raw.get("readOnly", False),
            is_management_event=raw.get("managementEvent", True),
            raw=raw,
        )

    @staticmethod
    def _parse_time(value: str) -> datetime | None:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        except ValueError:
            return None


def filter_events(
    events: Iterator[ParsedEvent],
    *,
    event_names: set[str] | None = None,
    exclude_errors: bool = False,
    exclude_read_only: bool = False,
    identity_type: str | None = None,
) -> Iterator[ParsedEvent]:
    """Filter a stream of events by common investigation criteria."""
    for event in events:
        if exclude_errors and event.is_error:
            continue
        if exclude_read_only and event.is_read_only:
            continue
        if event_names and event.event_name not in event_names:
            continue
        if identity_type and event.identity_type != identity_type:
            continue
        yield event


# ── unit-test examples ────────────────────────────────────────────────────────

def _example_tests() -> None:
    """Illustrative assertions — run with pytest or directly."""
    parser = CloudTrailParser()

    # Valid single event
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
            "userName": "attacker",
        },
        "requestParameters": {"userName": "backdoor-user"},
        "readOnly": False,
        "managementEvent": True,
    }
    event = parser.parse_dict(raw)
    assert event is not None
    assert event.event_name == "CreateUser"
    assert event.actor_label == "attacker"
    assert not event.is_root
    assert not event.is_error

    # Root event
    root_raw = {**raw, "eventID": "def456", "userIdentity": {"type": "Root"}, "eventTime": "2024-01-15T14:02:11Z"}
    root_event = parser.parse_dict(root_raw)
    assert root_event is not None
    assert root_event.is_root

    # Bad input returns None
    assert parser.parse_dict({}) is None  # no eventTime
    assert parser.parse_dict("not a dict") is None  # type: ignore[arg-type]

    print("All example assertions passed.")


if __name__ == "__main__":
    _example_tests()
