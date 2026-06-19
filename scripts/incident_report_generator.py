"""
incident_report_generator.py — Generate structured incident reports from
enriched CDET alerts and CloudTrail investigation data.

Produces three output formats keyed to audience:
  - Executive summary (Markdown) — one-page business impact, response status
  - Analyst report (Markdown) — full technical timeline, IOCs, evidence chain
  - Investigation summary (JSON) — machine-readable, suitable for SIEM ingestion

Usage:
    from scripts.incident_report_generator import IncidentReportGenerator
    from scripts.alert_enrichment import AlertEnricher

    enricher = AlertEnricher()
    enriched = enricher.enrich(alert_dict)

    gen = IncidentReportGenerator()
    report = gen.generate(enriched, events=parsed_event_list)
    gen.write_reports(report, output_dir=Path("reports/generated"))
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from scripts.alert_enrichment import EnrichedAlert
from scripts.cloudtrail_parser import ParsedEvent
from scripts.ioc_extractor import IoCExtractor, IoCReport

logger = structlog.get_logger(__name__)

# ── severity → business language ─────────────────────────────────────────────

_SEVERITY_IMPACT: dict[str, str] = {
    "critical": "Potential compromise of cloud infrastructure. Immediate executive notification required.",
    "high": "Significant security control failure. Requires same-business-day investigation and response.",
    "medium": "Suspicious activity requiring investigation within 24-48 hours.",
    "low": "Low-priority finding; review during next scheduled triage cycle.",
    "informational": "Informational. No immediate action required.",
}

_TACTIC_BUSINESS_IMPACT: dict[str, str] = {
    "Persistence": "Attacker may retain unauthorized access even after credential rotation.",
    "Privilege Escalation": "Attacker may have gained administrative access to cloud resources.",
    "Defense Evasion": "Attacker may have disabled monitoring, reducing visibility into ongoing activity.",
    "Credential Access": "Attacker may have obtained valid credentials for further lateral movement.",
    "Discovery": "Attacker was mapping cloud infrastructure, likely in preparation for a follow-on attack.",
    "Lateral Movement": "Attacker may have moved from one account or resource to another.",
    "Exfiltration": "Sensitive data may have been copied outside the organization's cloud environment.",
    "Impact": "Attacker may have caused service disruption or data destruction.",
    "Initial Access": "Attacker may have gained initial foothold using compromised credentials.",
    "Collection": "Attacker was gathering data prior to exfiltration.",
}


# ── report data structures ────────────────────────────────────────────────────


@dataclass
class TimelineEntry:
    timestamp: str
    event_id: str
    event_name: str
    actor: str
    region: str
    source_ip: str
    description: str


@dataclass
class IncidentReport:
    """Fully-populated incident report, pre-rendered to all three formats."""

    # Metadata
    incident_id: str
    detection_id: str
    generated_at: str
    severity: str
    tactic: str
    technique: str
    technique_name: str

    # Affected scope
    actor_arn: str
    source_ip: str
    aws_region: str
    affected_resource: str

    # Timeline
    timeline: list[TimelineEntry] = field(default_factory=list)

    # IOCs
    ioc_report: IoCReport | None = None

    # Narrative
    executive_summary_text: str = ""
    analyst_summary_text: str = ""

    # IAM context (from enrichment)
    principal_exists: bool | None = None
    principal_mfa_active: bool | None = None
    principal_attached_policies: list[str] = field(default_factory=list)

    # Queries
    recommended_queries: list[str] = field(default_factory=list)

    # Escalation
    escalation_reason: str = ""

    # Enrichment errors
    enrichment_errors: list[str] = field(default_factory=list)


# ── generator ─────────────────────────────────────────────────────────────────


class IncidentReportGenerator:
    """
    Generate executive, analyst, and machine-readable incident reports.

    All output is deterministic given the same input — no timestamps are
    injected internally; the caller controls the reference time via
    generate(..., report_time=...).
    """

    def __init__(self, output_dir: Path | None = None) -> None:
        self._output_dir = output_dir or Path("reports/generated")
        self._ioc_extractor = IoCExtractor()

    def generate(
        self,
        enriched: EnrichedAlert,
        events: list[ParsedEvent] | None = None,
        report_time: datetime | None = None,
    ) -> IncidentReport:
        """Build an IncidentReport from an EnrichedAlert and optional events."""
        ts = (report_time or datetime.now(timezone.utc)).isoformat()
        original = enriched.original
        detection_id = original.get("detection_id", "UNKNOWN")
        log = logger.bind(detection_id=detection_id)

        ioc_report: IoCReport | None = None
        timeline: list[TimelineEntry] = []

        if events:
            ioc_report = self._ioc_extractor.extract_from_events(events)
            timeline = self._build_timeline(events)
        else:
            ioc_report = self._ioc_extractor.extract_from_alert(original)

        actor_arn = (
            original.get("creator_arn") or original.get("actor_arn") or original.get("session_issuer_arn") or "unknown"
        )
        source_ip = original.get("event_source_ip") or original.get("sourceIPAddress") or "unknown"
        region = original.get("region") or original.get("awsRegion") or "unknown"
        resource = self._infer_affected_resource(original)

        incident_id = f"INC-{detection_id}-{ts[:10].replace('-', '')}"

        report = IncidentReport(
            incident_id=incident_id,
            detection_id=detection_id,
            generated_at=ts,
            severity=enriched.enriched_severity or enriched.base_severity,
            tactic=enriched.attack_tactic,
            technique=enriched.attack_technique,
            technique_name=enriched.attack_technique_name,
            actor_arn=actor_arn,
            source_ip=source_ip,
            aws_region=region,
            affected_resource=resource,
            timeline=timeline,
            ioc_report=ioc_report,
            principal_exists=enriched.principal_exists,
            principal_mfa_active=enriched.principal_mfa_active,
            principal_attached_policies=enriched.principal_attached_policies,
            recommended_queries=enriched.recommended_queries,
            escalation_reason=enriched.severity_escalation_reason,
            enrichment_errors=enriched.enrichment_errors,
        )

        report.executive_summary_text = self._render_executive(report)
        report.analyst_summary_text = self._render_analyst(report)

        log.info("report_generated", incident_id=incident_id, severity=report.severity)
        return report

    def write_reports(self, report: IncidentReport, output_dir: Path | None = None) -> dict[str, Path]:
        """Write all three report formats to disk. Returns map of format → path."""
        dest = output_dir or self._output_dir
        dest.mkdir(parents=True, exist_ok=True)

        stem = f"{report.incident_id}"
        paths: dict[str, Path] = {}

        exec_path = dest / f"{stem}_executive.md"
        exec_path.write_text(report.executive_summary_text, encoding="utf-8")
        paths["executive"] = exec_path

        analyst_path = dest / f"{stem}_analyst.md"
        analyst_path.write_text(report.analyst_summary_text, encoding="utf-8")
        paths["analyst"] = analyst_path

        json_path = dest / f"{stem}_summary.json"
        json_path.write_text(self._render_json(report), encoding="utf-8")
        paths["json"] = json_path

        logger.info("reports_written", paths={k: str(v) for k, v in paths.items()})
        return paths

    # ── rendering ─────────────────────────────────────────────────────────────

    def _render_executive(self, r: IncidentReport) -> str:
        impact = _SEVERITY_IMPACT.get(r.severity.lower(), "Review recommended.")
        tactic_impact = _TACTIC_BUSINESS_IMPACT.get(r.tactic, "Potential security impact.")
        mfa_status = (
            "MFA was NOT active"
            if r.principal_mfa_active is False
            else "MFA status unknown"
            if r.principal_mfa_active is None
            else "MFA was active"
        )
        escalation_note = f"\n> **Escalation reason:** {r.escalation_reason}\n" if r.escalation_reason else ""

        return f"""# Executive Incident Summary

**Incident ID:** {r.incident_id}
**Detection:** {r.detection_id}
**Generated:** {r.generated_at}
**Severity:** {r.severity.upper()}
{escalation_note}
---

## Business Impact

{impact}

**ATT&CK Context:** {r.tactic} — {r.technique} ({r.technique_name})

{tactic_impact}

---

## Affected Scope

| Field | Value |
|---|---|
| Actor | `{r.actor_arn}` |
| Source IP | `{r.source_ip}` |
| AWS Region | `{r.aws_region}` |
| Affected Resource | `{r.affected_resource}` |
| Principal MFA | {mfa_status} |

---

## Response Status

- [ ] Alert triaged by on-call analyst
- [ ] Affected principal identified and assessed
- [ ] Containment action taken (disable key / revoke session / detach policy)
- [ ] Root cause determined
- [ ] Recovery completed
- [ ] Post-incident review scheduled

---

## Next Steps

1. Review the analyst report for full technical timeline and evidence.
2. Verify the actor (`{r.actor_arn}`) had legitimate need for this action.
3. If unauthorized, follow the containment playbook for `{r.detection_id}`.
4. Update detection lookups if this was a false positive (approved pipeline actor).

---

*Report generated by Cloud Threat Detection Lab — {r.detection_id} detection.*
"""

    def _render_analyst(self, r: IncidentReport) -> str:
        ioc_section = self._render_ioc_section(r.ioc_report)
        timeline_section = self._render_timeline_section(r.timeline)
        queries_section = self._render_queries_section(r.recommended_queries)
        policy_section = (
            "\n".join(f"  - `{p}`" for p in r.principal_attached_policies)
            if r.principal_attached_policies
            else "  - None retrieved (IAM enrichment not available or no policies attached)"
        )
        errors_section = "\n".join(f"  - {e}" for e in r.enrichment_errors) if r.enrichment_errors else "  - None"

        return f"""# Analyst Incident Report

**Incident ID:** {r.incident_id}
**Detection:** {r.detection_id}
**Generated:** {r.generated_at}
**Severity:** {r.severity.upper()}
**ATT&CK:** [{r.technique} — {r.technique_name}](https://attack.mitre.org/techniques/{r.technique.replace(".", "/")})

---

## Detection Summary

| Field | Value |
|---|---|
| Actor ARN | `{r.actor_arn}` |
| Source IP | `{r.source_ip}` |
| Region | `{r.aws_region}` |
| Resource | `{r.affected_resource}` |
| Tactic | {r.tactic} |
| Technique | {r.technique} |
| Severity | {r.severity} |
| Escalation | {r.escalation_reason or "None"} |

---

## Principal Context (IAM Enrichment)

| Field | Value |
|---|---|
| Principal exists | {r.principal_exists} |
| MFA active | {r.principal_mfa_active} |
| Attached policies | {len(r.principal_attached_policies)} |

**Attached policies:**
{policy_section}

---

{timeline_section}

---

{ioc_section}

---

{queries_section}

---

## Evidence Chain

1. CloudTrail event triggered `{r.detection_id}` detection rule.
2. Alert enriched with ATT&CK context, IAM principal status, and severity classification.
3. IOCs extracted from event payload (see IOC section above).
4. Recommended pivot queries generated (see Queries section above).

---

## Enrichment Errors

{errors_section}

---

## Playbook Reference

See `playbooks/{r.detection_id}_*/` for:
- `triage.md` — initial validation steps
- `investigation.md` — deep-dive investigation procedure
- `containment.md` — how to stop the attack
- `recovery.md` — how to restore normal operations

---

*Report generated by Cloud Threat Detection Lab — {r.detection_id} detection.*
"""

    def _render_ioc_section(self, ioc_report: IoCReport | None) -> str:
        if not ioc_report or not ioc_report.iocs:
            return "## Indicators of Compromise\n\nNo IOCs extracted."

        lines = ["## Indicators of Compromise", ""]
        lines.append(f"Extracted from {ioc_report.event_count} event(s).")
        lines.append("")

        for ioc_type in sorted({i.ioc_type for i in ioc_report.iocs}, key=lambda x: x.value):
            typed = ioc_report.by_type(ioc_type)
            if not typed:
                continue
            lines.append(f"### {ioc_type.value.replace('_', ' ').title()}")
            lines.append("")
            lines.append("| Value | Count | First Seen | Last Seen |")
            lines.append("|---|---|---|---|")
            for ioc in sorted(typed, key=lambda x: x.count, reverse=True):
                lines.append(
                    f"| `{ioc.value}` | {ioc.count} | {ioc.first_seen.isoformat()} | {ioc.last_seen.isoformat()} |"
                )
            lines.append("")

        return "\n".join(lines)

    def _render_timeline_section(self, timeline: list[TimelineEntry]) -> str:
        if not timeline:
            return "## Event Timeline\n\nNo events available for timeline reconstruction."

        lines = ["## Event Timeline", ""]
        lines.append("| Time | Event | Actor | Source IP | Region | Description |")
        lines.append("|---|---|---|---|---|---|")
        for entry in timeline:
            lines.append(
                f"| `{entry.timestamp}` | `{entry.event_name}` | `{entry.actor}` "
                f"| `{entry.source_ip}` | `{entry.region}` | {entry.description} |"
            )
        return "\n".join(lines)

    def _render_queries_section(self, queries: list[str]) -> str:
        if not queries:
            return "## Recommended Pivot Queries\n\nNo queries generated."
        lines = ["## Recommended Pivot Queries", ""]
        for i, q in enumerate(queries, 1):
            lines.append(f"**Query {i}** (Splunk SPL):")
            lines.append(f"```spl\n{q}\n```")
            lines.append("")
        return "\n".join(lines)

    def _render_json(self, r: IncidentReport) -> str:
        summary: dict[str, Any] = {
            "incident_id": r.incident_id,
            "detection_id": r.detection_id,
            "generated_at": r.generated_at,
            "severity": r.severity,
            "tactic": r.tactic,
            "technique": r.technique,
            "technique_name": r.technique_name,
            "actor_arn": r.actor_arn,
            "source_ip": r.source_ip,
            "aws_region": r.aws_region,
            "affected_resource": r.affected_resource,
            "principal_exists": r.principal_exists,
            "principal_mfa_active": r.principal_mfa_active,
            "principal_attached_policies": r.principal_attached_policies,
            "escalation_reason": r.escalation_reason,
            "enrichment_errors": r.enrichment_errors,
            "recommended_queries": r.recommended_queries,
            "timeline": [
                {
                    "timestamp": e.timestamp,
                    "event_id": e.event_id,
                    "event_name": e.event_name,
                    "actor": e.actor,
                    "region": e.region,
                    "source_ip": e.source_ip,
                    "description": e.description,
                }
                for e in r.timeline
            ],
            "iocs": (
                [
                    {
                        "type": ioc.ioc_type.value,
                        "value": ioc.value,
                        "count": ioc.count,
                        "first_seen": ioc.first_seen.isoformat(),
                        "last_seen": ioc.last_seen.isoformat(),
                        "source_events": ioc.source_events,
                    }
                    for ioc in r.ioc_report.iocs
                ]
                if r.ioc_report
                else []
            ),
        }
        return json.dumps(summary, indent=2, default=str)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _build_timeline(self, events: list[ParsedEvent]) -> list[TimelineEntry]:
        sorted_events = sorted(events, key=lambda e: e.event_time)
        entries = []
        for e in sorted_events:
            entries.append(
                TimelineEntry(
                    timestamp=e.event_time.isoformat(),
                    event_id=e.event_id,
                    event_name=e.event_name,
                    actor=e.actor_label,
                    region=e.aws_region,
                    source_ip=e.source_ip_address,
                    description=self._event_description(e),
                )
            )
        return entries

    @staticmethod
    def _event_description(e: ParsedEvent) -> str:
        if e.is_error:
            return f"{e.event_name} failed with `{e.error_code}`"
        params = e.request_parameters
        if e.event_name == "CreateUser":
            return f"Created IAM user `{params.get('userName', 'unknown')}`"
        if e.event_name == "CreateAccessKey":
            return f"Created access key for `{params.get('userName', 'unknown')}`"
        if e.event_name in ("StopLogging", "DeleteTrail"):
            return f"CloudTrail logging impaired: `{params.get('name', 'unknown')}`"
        if e.event_name in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
            return f"Attached policy `{params.get('policyArn', 'unknown')}`"
        if e.event_name == "RunInstances":
            return f"Launched `{params.get('instanceType', 'unknown')}` instance"
        if e.event_name == "AssumeRole":
            return f"Assumed role `{params.get('roleArn', 'unknown')}`"
        return e.event_name

    @staticmethod
    def _infer_affected_resource(original: dict[str, Any]) -> str:
        for key in ("new_user_name", "target_user", "role_arn", "bucket_name", "instance_id", "trail_arn", "policyArn"):
            val = original.get(key)
            if val:
                return str(val)
        return "see alert fields"


# ── unit-test examples ────────────────────────────────────────────────────────


def _example_tests() -> None:
    from scripts.alert_enrichment import AlertEnricher

    enricher = AlertEnricher()
    alert = {
        "detection_id": "CDET-001",
        "creator_arn": "arn:aws:iam::123456789012:user/attacker",
        "event_source_ip": "203.0.113.45",
        "new_user_name": "backdoor-user",
        "mfa_used": "no",
        "severity": "high",
        "region": "us-east-1",
    }
    enriched = enricher.enrich(alert)

    gen = IncidentReportGenerator()
    report = gen.generate(
        enriched,
        report_time=datetime(2024, 1, 15, 14, 2, 11, tzinfo=timezone.utc),
    )

    assert report.detection_id == "CDET-001"
    assert report.severity == "critical"  # escalated by MFA=no
    assert report.actor_arn == "arn:aws:iam::123456789012:user/attacker"
    assert "CDET-001" in report.executive_summary_text
    assert "CDET-001" in report.analyst_summary_text
    assert "incident_id" in report.analyst_summary_text

    json_str = gen._render_json(report)
    parsed = json.loads(json_str)
    assert parsed["detection_id"] == "CDET-001"
    assert parsed["severity"] == "critical"

    print("All incident report generator assertions passed.")


if __name__ == "__main__":
    _example_tests()
