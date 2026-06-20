"""
GuardDuty findings collector.

Lists active GuardDuty findings for the configured detector, normalizing
threat intelligence details, resource context, and action metadata.

Permissions required (read-only):
    guardduty:ListDetectors
    guardduty:ListFindings
    guardduty:GetFindings
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

import structlog
from botocore.exceptions import ClientError

from .base_collector import BaseCollector
from .schema import GuardDutyFinding, Severity

logger = structlog.get_logger(__name__)

_SEVERITY_LABEL_MAP: list[tuple[float, Severity]] = [
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (1.0, Severity.LOW),
]

# GuardDuty GetFindings accepts a maximum of 50 IDs per call.
_GET_FINDINGS_BATCH_SIZE = 50


def _severity_label(score: float) -> Severity:
    for threshold, label in _SEVERITY_LABEL_MAP:
        if score >= threshold:
            return label
    return Severity.INFORMATIONAL


class GuardDutyCollector(BaseCollector):
    """
    Collect GuardDuty findings from the active detector in the configured region.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        severity_threshold: float = 4.0,
        detector_id: str | None = None,
    ) -> None:
        super().__init__(region=region)
        self.severity_threshold = severity_threshold
        self._detector_id = detector_id  # override; auto-detected if None

    @property
    def collector_name(self) -> str:
        return "guardduty"

    def collect(self) -> Iterator[GuardDutyFinding]:
        """Yield GuardDutyFinding records above the severity threshold."""
        client = self._session.client("guardduty")
        detector_id = self._resolve_detector_id(client)
        if detector_id is None:
            self._log.warning("guardduty_no_detector", region=self.region)
            return

        self._log.info(
            "guardduty_collection_started",
            detector_id=detector_id,
            severity_threshold=self.severity_threshold,
        )

        finding_ids = list(self._list_finding_ids(client, detector_id))
        self._log.info("guardduty_finding_ids_listed", count=len(finding_ids))

        for batch_start in range(0, len(finding_ids), _GET_FINDINGS_BATCH_SIZE):
            batch = finding_ids[batch_start : batch_start + _GET_FINDINGS_BATCH_SIZE]
            yield from self._get_findings(client, detector_id, batch)

    def _resolve_detector_id(self, client: Any) -> str | None:
        if self._detector_id:
            return self._detector_id
        try:
            response = client.list_detectors()
            detectors = response.get("DetectorIds", [])
            return detectors[0] if detectors else None
        except ClientError as exc:
            self._log.error("guardduty_list_detectors_failed", error=str(exc))
            return None

    def _list_finding_ids(self, client: Any, detector_id: str) -> Iterator[str]:
        criteria = {
            "Criterion": {
                "severity": {
                    "Gte": int(self.severity_threshold * 10),
                },
                "service.archived": {
                    "Eq": ["false"],
                },
            }
        }
        try:
            paginator = client.get_paginator("list_findings")
            for page in paginator.paginate(DetectorId=detector_id, FindingCriteria=criteria):
                yield from page.get("FindingIds", [])
        except ClientError as exc:
            self._log.error("guardduty_list_findings_failed", error=str(exc))
            raise

    def _get_findings(self, client: Any, detector_id: str, finding_ids: list[str]) -> Iterator[GuardDutyFinding]:
        try:
            response = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
            for raw in response.get("Findings", []):
                finding = self._normalize(raw)
                if finding is not None:
                    yield finding
        except ClientError as exc:
            self._log.error("guardduty_get_findings_failed", error=str(exc))
            raise

    def _normalize(self, raw: dict[str, Any]) -> GuardDutyFinding | None:
        try:
            severity_score = float(raw.get("Severity", 0.0))
            service = raw.get("Service", {})
            action = service.get("Action", {})
            action_type = action.get("ActionType")

            remote_ip_address: str | None = None
            remote_country_code: str | None = None

            if action_type == "NETWORK_CONNECTION":
                remote_ip = action.get("NetworkConnectionAction", {}).get("RemoteIpDetails", {})
                remote_ip_address = remote_ip.get("IpAddressV4")
                remote_country_code = remote_ip.get("Country", {}).get("CountryCode")
            elif action_type == "PORT_PROBE":
                probe_details = action.get("PortProbeAction", {}).get("PortProbeDetails", [{}])
                if probe_details:
                    remote_ip = probe_details[0].get("RemoteIpDetails", {})
                    remote_ip_address = remote_ip.get("IpAddressV4")
                    remote_country_code = remote_ip.get("Country", {}).get("CountryCode")

            ti_details = service.get("AdditionalInfo", {}).get("ThreatListName", [])
            if isinstance(ti_details, str):
                ti_details = [ti_details]

            resource = raw.get("Resource", {})
            resource_type = resource.get("ResourceType")
            resource_id: str | None = None
            if resource_type == "Instance":
                resource_id = resource.get("InstanceDetails", {}).get("InstanceId")
            elif resource_type == "AccessKey":
                resource_id = resource.get("AccessKeyDetails", {}).get("AccessKeyId")
            elif resource_type == "S3Bucket":
                buckets = resource.get("S3BucketDetails", [])
                resource_id = buckets[0].get("Name") if buckets else None

            created_at = raw.get("CreatedAt", "")
            updated_at = raw.get("UpdatedAt", "")

            return GuardDutyFinding(
                finding_id=raw.get("Id", ""),
                title=raw.get("Title", ""),
                description=raw.get("Description", ""),
                severity=severity_score,
                severity_label=_severity_label(severity_score),
                finding_type=raw.get("Type", ""),
                region=raw.get("Region", self.region),
                aws_account_id=raw.get("AccountId", ""),
                created=datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                if created_at
                else datetime.now(tz=timezone.utc),
                updated=datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                if updated_at
                else datetime.now(tz=timezone.utc),
                resource_type=resource_type,
                resource_id=resource_id,
                threat_intelligence_details=ti_details if isinstance(ti_details, list) else [],
                action_type=action_type,
                remote_ip_address=remote_ip_address,
                remote_country_code=remote_country_code,
                raw=raw,
            )
        except Exception as exc:
            self._log.warning("guardduty_finding_parse_error", error=str(exc))
            return None
