"""
Security Hub findings collector.

Retrieves active findings from AWS Security Hub, normalizing severity,
compliance status, and resource context into the internal schema.

Permissions required (read-only):
    securityhub:GetFindings
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

import structlog
from botocore.exceptions import ClientError

from .base_collector import BaseCollector
from .schema import SecurityHubFinding, Severity

logger = structlog.get_logger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFORMATIONAL,
}


class SecurityHubCollector(BaseCollector):
    """
    Collect AWS Security Hub findings filtered by severity label.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        severity_labels: list[str] | None = None,
    ) -> None:
        super().__init__(region=region)
        self.severity_labels = severity_labels or ["CRITICAL", "HIGH", "MEDIUM"]

    @property
    def collector_name(self) -> str:
        return "securityhub"

    def collect(self) -> Iterator[SecurityHubFinding]:
        """Yield SecurityHubFinding records for active findings."""
        client = self._session.client("securityhub")

        filters: dict[str, Any] = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW", "Comparison": "EQUALS"},
                {"Value": "NOTIFIED", "Comparison": "EQUALS"},
            ],
            "SeverityLabel": [
                {"Value": label, "Comparison": "EQUALS"}
                for label in self.severity_labels
            ],
        }

        self._log.info(
            "securityhub_collection_started",
            severity_labels=self.severity_labels,
        )

        try:
            paginator = client.get_paginator("get_findings")
            for page in paginator.paginate(Filters=filters):
                for raw in page.get("Findings", []):
                    finding = self._normalize(raw)
                    if finding is not None:
                        yield finding
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "InvalidAccessException":
                self._log.warning(
                    "securityhub_not_enabled",
                    region=self.region,
                    hint="Security Hub may not be enabled in this region.",
                )
                return
            self._log.error("securityhub_get_findings_failed", error=str(exc))
            raise

    def _normalize(self, raw: dict[str, Any]) -> SecurityHubFinding | None:
        try:
            severity_raw = raw.get("Severity", {})
            severity_label_str = severity_raw.get("Label", "INFORMATIONAL").upper()
            severity = _SEVERITY_MAP.get(severity_label_str, Severity.INFORMATIONAL)

            resources = raw.get("Resources", [])
            first_resource = resources[0] if resources else {}

            created_at = raw.get("CreatedAt", "")
            updated_at = raw.get("UpdatedAt", "")

            return SecurityHubFinding(
                finding_id=raw.get("Id", ""),
                title=raw.get("Title", ""),
                description=raw.get("Description", ""),
                severity=severity,
                severity_score=float(severity_raw.get("Normalized", 0)),
                compliance_status=raw.get("Compliance", {}).get("Status"),
                workflow_status=raw.get("Workflow", {}).get("Status", "NEW"),
                record_state=raw.get("RecordState", "ACTIVE"),
                product_name=raw.get("ProductName", ""),
                generator_id=raw.get("GeneratorId", ""),
                created=datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                if created_at
                else datetime.now(tz=timezone.utc),
                updated=datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                if updated_at
                else datetime.now(tz=timezone.utc),
                resource_type=first_resource.get("Type"),
                resource_id=first_resource.get("Id"),
                aws_account_id=raw.get("AwsAccountId", ""),
                region=raw.get("Region", self.region),
                raw=raw,
            )
        except Exception as exc:
            self._log.warning("securityhub_finding_parse_error", error=str(exc))
            return None
