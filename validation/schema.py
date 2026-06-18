"""
Validation schema for the Cloud Threat Detection Lab.

Defines dataclasses and enums used throughout the validation framework.
All validation results and test case definitions conform to this schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class TestResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class TestCaseType(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    EDGE = "edge"


@dataclass
class FieldAssertion:
    """Asserts that a specific field in the alert output meets a condition."""

    field_name: str
    expected_value: Any | None = None
    expected_type: str | None = None
    must_exist: bool = True
    must_be_nonempty: bool = False

    def evaluate(self, alert: dict[str, Any]) -> tuple[bool, str]:
        """Return (passed, reason)."""
        if self.field_name not in alert:
            if self.must_exist:
                return False, f"Missing required field: {self.field_name}"
            return True, "field absent (allowed)"

        value = alert[self.field_name]

        if self.must_be_nonempty and not value:
            return False, f"Field '{self.field_name}' is empty"

        if self.expected_value is not None and value != self.expected_value:
            return False, (
                f"Field '{self.field_name}': expected={self.expected_value!r}, "
                f"got={value!r}"
            )

        if self.expected_type is not None and not isinstance(value, eval(self.expected_type)):
            return False, (
                f"Field '{self.field_name}' wrong type: "
                f"expected={self.expected_type}, got={type(value).__name__}"
            )

        return True, "ok"


@dataclass
class AlertAssertion:
    """Asserts that an alert was or was not generated with specific properties."""

    should_fire: bool
    expected_severity: str | None = None
    expected_urgency: int | None = None
    expected_tactic: str | None = None
    expected_technique: str | None = None
    field_assertions: list[FieldAssertion] = field(default_factory=list)
    min_alert_count: int = 1
    max_alert_count: int | None = None


@dataclass
class TestCase:
    """A single validation test case for a detection."""

    detection_id: str
    test_case_type: TestCaseType
    name: str
    description: str
    sample_file: Path
    alert_assertion: AlertAssertion
    notes: str = ""


@dataclass
class FieldResult:
    """Result of evaluating a single field assertion."""

    field_name: str
    passed: bool
    reason: str


@dataclass
class ValidationResult:
    """Full result of running a single test case."""

    detection_id: str
    test_case_type: TestCaseType
    test_name: str
    result: TestResult
    alert_count: int
    field_results: list[FieldResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def passed(self) -> bool:
        return self.result == TestResult.PASS

    @property
    def failed_fields(self) -> list[FieldResult]:
        return [f for f in self.field_results if not f.passed]


@dataclass
class DetectionValidationSummary:
    """Aggregated validation results for one detection across all its test cases."""

    detection_id: str
    positive_result: ValidationResult | None = None
    negative_result: ValidationResult | None = None
    edge_result: ValidationResult | None = None

    @property
    def all_passed(self) -> bool:
        results = [r for r in [
            self.positive_result,
            self.negative_result,
            self.edge_result,
        ] if r is not None]
        return all(r.passed for r in results)

    @property
    def ready_for_promotion(self) -> bool:
        """True if all mandatory tests (positive + negative) pass."""
        return (
            self.positive_result is not None
            and self.positive_result.passed
            and self.negative_result is not None
            and self.negative_result.passed
        )


@dataclass
class ValidationRunSummary:
    """Top-level summary of a full validation run across all detections."""

    run_id: str
    run_timestamp: str
    detections_tested: int
    detections_passed: int
    detections_failed: int
    detections_skipped: int
    results: list[DetectionValidationSummary] = field(default_factory=list)
    coverage_percent: float = 0.0
