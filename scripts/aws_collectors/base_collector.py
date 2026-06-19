"""
Abstract base class for all AWS security telemetry collectors.

Establishes the boto3 session pattern, structured logging, and output
contract that every concrete collector must follow.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

import boto3
import structlog

logger = structlog.get_logger(__name__)


def _default_serializer(obj: Any) -> str:
    """JSON serializer for types not handled by the standard library."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


@dataclass
class CollectorResult:
    """Container for a single collector run."""

    collector_name: str
    aws_account_id: str
    aws_region: str
    collected_at: datetime
    record_count: int
    records: list[dict[str, Any]]
    errors: list[str]


class BaseCollector(ABC):
    """
    Base class for read-only AWS security telemetry collectors.

    Credentials are resolved from the boto3 default chain (i.e. `aws configure`).
    Never pass explicit credentials to this class or its subclasses.
    """

    def __init__(self, region: str = "us-east-1") -> None:
        self.region = region
        # Credentials resolved via default chain — no explicit keys ever passed.
        self._session = boto3.Session(region_name=region)
        self._log = structlog.get_logger(self.__class__.__name__)

    @property
    @abstractmethod
    def collector_name(self) -> str:
        """Short identifier used in output filenames and logs."""
        ...

    @abstractmethod
    def collect(self) -> Iterator[Any]:
        """Yield normalized schema objects one at a time."""
        ...

    def run(self, output_dir: Path | None = None) -> CollectorResult:
        """
        Execute collection, normalize output, and optionally persist to disk.

        Args:
            output_dir: If provided, write NDJSON results to this directory.

        Returns:
            CollectorResult summarizing the run.
        """
        account_id = self._get_account_id()
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        collected_at = datetime.utcnow()

        self._log.info(
            "collector_started",
            collector=self.collector_name,
            region=self.region,
            account_id=account_id,
        )

        for item in self.collect():
            try:
                records.append(asdict(item))
            except Exception as exc:
                error_msg = f"Serialization error: {exc}"
                self._log.warning("record_serialization_error", error=error_msg)
                errors.append(error_msg)

        result = CollectorResult(
            collector_name=self.collector_name,
            aws_account_id=account_id,
            aws_region=self.region,
            collected_at=collected_at,
            record_count=len(records),
            records=records,
            errors=errors,
        )

        self._log.info(
            "collector_finished",
            collector=self.collector_name,
            records=len(records),
            errors=len(errors),
        )

        if output_dir is not None:
            self._write_output(result, output_dir)

        return result

    def _get_account_id(self) -> str:
        try:
            sts = self._session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as exc:
            self._log.warning("account_id_lookup_failed", error=str(exc))
            return "unknown"

    def _write_output(self, result: CollectorResult, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = (
            f"{self.collector_name}_{result.aws_account_id}_{result.collected_at.strftime('%Y%m%dT%H%M%SZ')}.ndjson"
        )
        out_path = output_dir / filename
        with out_path.open("w", encoding="utf-8") as fh:
            for record in result.records:
                fh.write(json.dumps(record, default=_default_serializer) + "\n")
        self._log.info("output_written", path=str(out_path), records=result.record_count)
