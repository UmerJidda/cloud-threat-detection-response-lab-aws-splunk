"""
CloudTrail telemetry collector.

Retrieves management events via CloudTrail LookupEvents with a focus on
security-relevant API calls: user activity, root usage, IAM mutations,
and cross-account role assumptions.

Permissions required (read-only):
    cloudtrail:LookupEvents
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import structlog
from botocore.exceptions import ClientError

from .base_collector import BaseCollector
from .schema import CloudTrailEvent

logger = structlog.get_logger(__name__)

# API calls that are high-value for threat detection regardless of source.
HIGH_VALUE_EVENT_NAMES: frozenset[str] = frozenset(
    {
        # IAM mutations
        "CreateUser",
        "DeleteUser",
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateAccessKey",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "AddUserToGroup",
        "RemoveUserFromGroup",
        "CreateRole",
        "DeleteRole",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "UpdateAssumeRolePolicy",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "DeleteLoginProfile",
        "CreateVirtualMFADevice",
        "DeactivateMFADevice",
        "EnableMFADevice",
        # STS / lateral movement
        "AssumeRole",
        "AssumeRoleWithSAML",
        "AssumeRoleWithWebIdentity",
        # Defense evasion
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
        # Root activity (any root call is significant)
        "ConsoleLogin",
    }
)


class CloudTrailCollector(BaseCollector):
    """
    Collect recent CloudTrail management events using LookupEvents.

    LookupEvents is limited to the last 90 days and returns up to 50 results
    per page. This collector pages through all results for the configured
    lookback window and normalizes each event to the CloudTrailEvent schema.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        lookback_hours: int = 24,
        max_results: int = 1000,
    ) -> None:
        super().__init__(region=region)
        self.lookback_hours = lookback_hours
        self.max_results = max_results

    @property
    def collector_name(self) -> str:
        return "cloudtrail"

    def collect(self) -> Iterator[CloudTrailEvent]:
        """Yield CloudTrailEvent objects for recent management events."""
        client = self._session.client("cloudtrail")
        end_time = datetime.now(tz=timezone.utc)
        start_time = end_time - timedelta(hours=self.lookback_hours)

        self._log.info(
            "cloudtrail_lookup_started",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            lookback_hours=self.lookback_hours,
        )

        paginator = client.get_paginator("lookup_events")
        collected = 0

        try:
            page_iterator = paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": self.max_results, "PageSize": 50},
            )

            for page in page_iterator:
                for raw_event in page.get("Events", []):
                    event = self._normalize(raw_event)
                    if event is not None:
                        collected += 1
                        yield event

                    if collected >= self.max_results:
                        self._log.info(
                            "cloudtrail_max_results_reached", max=self.max_results
                        )
                        return

        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            self._log.error(
                "cloudtrail_lookup_failed",
                error_code=error_code,
                error=str(exc),
            )
            raise

    def _normalize(self, raw: dict[str, Any]) -> CloudTrailEvent | None:
        """Map a raw LookupEvents record to the internal CloudTrailEvent schema."""
        try:
            cloud_trail_event: dict[str, Any] = {}
            if "CloudTrailEvent" in raw:
                import json

                cloud_trail_event = json.loads(raw["CloudTrailEvent"])

            user_identity = cloud_trail_event.get("userIdentity", {})
            session_context = user_identity.get("sessionContext", {})
            session_issuer = session_context.get("sessionIssuer", {})

            return CloudTrailEvent(
                event_id=raw.get("EventId", ""),
                event_time=raw.get("EventTime", datetime.now(tz=timezone.utc)),
                event_name=raw.get("EventName", ""),
                event_source=raw.get("EventSource", ""),
                aws_region=cloud_trail_event.get("awsRegion", self.region),
                source_ip_address=cloud_trail_event.get("sourceIPAddress", ""),
                user_agent=cloud_trail_event.get("userAgent", ""),
                user_identity_type=user_identity.get("type", ""),
                user_identity_arn=user_identity.get("arn"),
                user_identity_account_id=user_identity.get("accountId"),
                assumed_role_arn=session_issuer.get("arn"),
                error_code=cloud_trail_event.get("errorCode"),
                error_message=cloud_trail_event.get("errorMessage"),
                request_parameters=cloud_trail_event.get("requestParameters") or {},
                response_elements=cloud_trail_event.get("responseElements") or {},
                raw=cloud_trail_event,
            )
        except Exception as exc:
            self._log.warning("cloudtrail_event_parse_error", error=str(exc))
            return None
