"""
alert_enrichment.py — Enrich CDET alerts with IAM context, ATT&CK mapping,
and severity classification using only local lookups and the boto3 default
credential chain.

The enrichment pipeline is designed to be called per-alert from a Splunk
Adaptive Response action or a standalone investigation script.

Usage:
    from scripts.alert_enrichment import AlertEnricher

    session = boto3.Session()          # uses `aws configure` credentials
    enricher = AlertEnricher(session)

    alert = {
        "detection_id": "CDET-001",
        "creator_arn": "arn:aws:iam::123456789012:user/attacker",
        "event_source_ip": "203.0.113.45",
        "new_user_name": "backdoor-user",
    }
    enriched = enricher.enrich(alert)
    print(enriched)
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import boto3
import structlog
from botocore.exceptions import ClientError

logger = structlog.get_logger(__name__)

# ATT&CK context for all 14 CDETs — no external API call required
_ATTACK_CONTEXT: dict[str, dict[str, str]] = {
    "CDET-001": {"tactic": "Persistence", "technique": "T1136.003",
                 "technique_name": "Create Account: Cloud Account",
                 "tactic_url": "https://attack.mitre.org/techniques/T1136/003/"},
    "CDET-002": {"tactic": "Persistence", "technique": "T1098.001",
                 "technique_name": "Account Manipulation: Additional Cloud Credentials",
                 "tactic_url": "https://attack.mitre.org/techniques/T1098/001/"},
    "CDET-003": {"tactic": "Defense Evasion", "technique": "T1562.008",
                 "technique_name": "Impair Defenses: Disable Cloud Logs",
                 "tactic_url": "https://attack.mitre.org/techniques/T1562/008/"},
    "CDET-004": {"tactic": "Privilege Escalation", "technique": "T1078.004",
                 "technique_name": "Valid Accounts: Cloud Accounts",
                 "tactic_url": "https://attack.mitre.org/techniques/T1078/004/"},
    "CDET-005": {"tactic": "Privilege Escalation", "technique": "T1484.002",
                 "technique_name": "Domain Policy Modification: Trust Modification",
                 "tactic_url": "https://attack.mitre.org/techniques/T1484/002/"},
    "CDET-006": {"tactic": "Initial Access", "technique": "T1078.004",
                 "technique_name": "Valid Accounts: Cloud Accounts",
                 "tactic_url": "https://attack.mitre.org/techniques/T1078/004/"},
    "CDET-007": {"tactic": "Credential Access", "technique": "T1552.005",
                 "technique_name": "Unsecured Credentials: Cloud Instance Metadata API",
                 "tactic_url": "https://attack.mitre.org/techniques/T1552/005/"},
    "CDET-008": {"tactic": "Discovery", "technique": "T1580",
                 "technique_name": "Cloud Infrastructure Discovery",
                 "tactic_url": "https://attack.mitre.org/techniques/T1580/"},
    "CDET-009": {"tactic": "Exfiltration", "technique": "T1537",
                 "technique_name": "Transfer Data to Cloud Account",
                 "tactic_url": "https://attack.mitre.org/techniques/T1537/"},
    "CDET-010": {"tactic": "Impact", "technique": "T1485",
                 "technique_name": "Data Destruction",
                 "tactic_url": "https://attack.mitre.org/techniques/T1485/"},
    "CDET-011": {"tactic": "Impact", "technique": "T1496",
                 "technique_name": "Resource Hijacking",
                 "tactic_url": "https://attack.mitre.org/techniques/T1496/"},
    "CDET-012": {"tactic": "Lateral Movement", "technique": "T1550.001",
                 "technique_name": "Use Alternate Authentication Material",
                 "tactic_url": "https://attack.mitre.org/techniques/T1550/001/"},
    "CDET-013": {"tactic": "Defense Evasion", "technique": "T1562.007",
                 "technique_name": "Impair Defenses: Disable or Modify Cloud Firewall",
                 "tactic_url": "https://attack.mitre.org/techniques/T1562/007/"},
    "CDET-014": {"tactic": "Defense Evasion", "technique": "T1070.004",
                 "technique_name": "Indicator Removal: File Deletion",
                 "tactic_url": "https://attack.mitre.org/techniques/T1070/004/"},
}

_SEVERITY_ESCALATION: dict[str, dict[str, Any]] = {
    "CDET-001": {"base": "high", "escalate_if": ["no_mfa", "admin_policy_attached"],
                 "escalated": "critical"},
    "CDET-002": {"base": "high", "escalate_if": ["second_key_created"],
                 "escalated": "critical"},
    "CDET-003": {"base": "critical", "escalate_if": [], "escalated": "critical"},
    "CDET-004": {"base": "critical", "escalate_if": [], "escalated": "critical"},
    "CDET-005": {"base": "high", "escalate_if": ["external_account"],
                 "escalated": "critical"},
    "CDET-006": {"base": "critical", "escalate_if": [], "escalated": "critical"},
    "CDET-007": {"base": "high", "escalate_if": ["external_ip"], "escalated": "critical"},
    "CDET-008": {"base": "medium", "escalate_if": ["rapid_enumeration"],
                 "escalated": "high"},
    "CDET-009": {"base": "high", "escalate_if": ["unapproved_account"],
                 "escalated": "critical"},
    "CDET-010": {"base": "critical", "escalate_if": [], "escalated": "critical"},
    "CDET-011": {"base": "high", "escalate_if": ["unapproved_region", "gpu_instance"],
                 "escalated": "critical"},
    "CDET-012": {"base": "high", "escalate_if": ["three_hop_chain"],
                 "escalated": "critical"},
    "CDET-013": {"base": "high", "escalate_if": ["port_22_or_3389"],
                 "escalated": "critical"},
    "CDET-014": {"base": "critical", "escalate_if": [], "escalated": "critical"},
}


@dataclass
class EnrichedAlert:
    """Alert with all enrichment layers applied."""

    # Original alert fields (pass-through)
    original: dict[str, Any]
    # ATT&CK context
    attack_tactic: str = ""
    attack_technique: str = ""
    attack_technique_name: str = ""
    attack_url: str = ""
    # IAM context (populated via AWS API when available)
    principal_exists: bool | None = None
    principal_create_date: str | None = None
    principal_mfa_active: bool | None = None
    principal_attached_policies: list[str] = field(default_factory=list)
    principal_access_key_count: int | None = None
    principal_console_access: bool | None = None
    # Severity context
    base_severity: str = ""
    enriched_severity: str = ""
    severity_escalation_reason: str = ""
    # Lookup context
    principal_in_approved_list: bool = False
    principal_in_automation_roles: bool = False
    # Investigation helpers
    recommended_queries: list[str] = field(default_factory=list)
    enrichment_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.update(self.original)
        return d


class AlertEnricher:
    """
    Enrich detection alerts with IAM context, ATT&CK mapping, and severity.

    Credentials are resolved via boto3 default chain — uses `aws configure`.
    No credentials are ever accepted as constructor arguments.

    IAM enrichment is best-effort: if the AWS call fails the alert is returned
    with whatever context was available from local lookups.
    """

    def __init__(
        self,
        session: boto3.Session | None = None,
        lookups_dir: Path | None = None,
    ) -> None:
        self._session = session or boto3.Session()
        self._lookups_dir = lookups_dir or Path("splunk/lookups")
        self._approved_principals: set[str] = set()
        self._automation_roles: set[str] = set()
        self._admin_policies: set[str] = set()
        self._load_lookups()

    def enrich(self, alert: dict[str, Any]) -> EnrichedAlert:
        """Apply all enrichment layers to a single alert dict."""
        detection_id = alert.get("detection_id", "")
        log = logger.bind(detection_id=detection_id)

        enriched = EnrichedAlert(original=alert)

        self._apply_attack_context(detection_id, enriched)
        self._apply_severity_context(detection_id, alert, enriched)
        self._apply_lookup_context(alert, enriched)
        self._apply_iam_context(alert, enriched, log)
        self._apply_investigation_queries(detection_id, alert, enriched)

        log.info(
            "enrichment_complete",
            enriched_severity=enriched.enriched_severity,
            principal_exists=enriched.principal_exists,
        )
        return enriched

    # ── enrichment layers ──────────────────────────────────────────────────────

    def _apply_attack_context(self, detection_id: str, enriched: EnrichedAlert) -> None:
        ctx = _ATTACK_CONTEXT.get(detection_id, {})
        enriched.attack_tactic = ctx.get("tactic", "")
        enriched.attack_technique = ctx.get("technique", "")
        enriched.attack_technique_name = ctx.get("technique_name", "")
        enriched.attack_url = ctx.get("tactic_url", "")

    def _apply_severity_context(
        self,
        detection_id: str,
        alert: dict[str, Any],
        enriched: EnrichedAlert,
    ) -> None:
        cfg = _SEVERITY_ESCALATION.get(detection_id, {})
        enriched.base_severity = cfg.get("base", alert.get("severity", "medium"))
        enriched.enriched_severity = enriched.base_severity

        mfa = str(alert.get("mfa_used", "yes")).lower()
        if "no_mfa" in cfg.get("escalate_if", []) and mfa in ("no", "false", "0"):
            enriched.enriched_severity = cfg["escalated"]
            enriched.severity_escalation_reason = "MFA not used by actor"

    def _apply_lookup_context(
        self, alert: dict[str, Any], enriched: EnrichedAlert
    ) -> None:
        arn = alert.get("creator_arn") or alert.get("actor_arn") or ""
        enriched.principal_in_approved_list = arn in self._approved_principals
        enriched.principal_in_automation_roles = arn in self._automation_roles

    def _apply_iam_context(
        self,
        alert: dict[str, Any],
        enriched: EnrichedAlert,
        log: Any,
    ) -> None:
        username = self._extract_username(alert)
        if not username:
            return

        iam = self._session.client("iam")
        try:
            resp = iam.get_user(UserName=username)
            user = resp["User"]
            enriched.principal_exists = True
            enriched.principal_create_date = user.get("CreateDate", "").isoformat() if hasattr(user.get("CreateDate"), "isoformat") else str(user.get("CreateDate", ""))
            enriched.principal_console_access = self._has_console_access(iam, username, enriched)

            keys_resp = iam.list_access_keys(UserName=username)
            enriched.principal_access_key_count = len(keys_resp.get("AccessKeyMetadata", []))

            mfa_resp = iam.list_mfa_devices(UserName=username)
            enriched.principal_mfa_active = len(mfa_resp.get("MFADevices", [])) > 0

            policies_resp = iam.list_attached_user_policies(UserName=username)
            enriched.principal_attached_policies = [
                p["PolicyArn"] for p in policies_resp.get("AttachedPolicies", [])
            ]

            log.info("iam_context_enriched", username=username)

        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                enriched.principal_exists = False
                log.info("iam_principal_not_found", username=username)
            else:
                msg = f"IAM enrichment failed: {code}"
                enriched.enrichment_errors.append(msg)
                log.warning("iam_enrichment_error", error=msg)

    def _apply_investigation_queries(
        self,
        detection_id: str,
        alert: dict[str, Any],
        enriched: EnrichedAlert,
    ) -> None:
        arn = alert.get("creator_arn") or alert.get("actor_arn") or "ACTOR_ARN"
        queries = [
            f'index=aws_cloudtrail "userIdentity.arn"="{arn}" earliest=-7d | head 50',
            f'index=aws_cloudtrail detection_id="{detection_id}" earliest=-24h',
        ]
        if detection_id in ("CDET-001", "CDET-002", "CDET-004"):
            user = alert.get("new_user_name") or alert.get("target_user") or "TARGET_USER"
            queries.append(
                f'index=aws_cloudtrail "requestParameters.userName"="{user}" earliest=-30d'
            )
        enriched.recommended_queries = queries

    # ── helpers ────────────────────────────────────────────────────────────────

    def _extract_username(self, alert: dict[str, Any]) -> str | None:
        for field_name in ("new_user_name", "target_user", "creator_arn", "actor_arn"):
            val = alert.get(field_name, "")
            if not val:
                continue
            if field_name.endswith("_arn") and "/" in val:
                return val.split("/")[-1]
            return val
        return None

    @staticmethod
    def _has_console_access(iam: Any, username: str, enriched: EnrichedAlert) -> bool:
        try:
            iam.get_login_profile(UserName=username)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return False
            enriched.enrichment_errors.append(f"login profile check failed: {exc}")
            return False

    def _load_lookups(self) -> None:
        for filename, target in (
            ("approved_iam_principals.csv", self._approved_principals),
            ("automation_role_arns.csv", self._automation_roles),
            ("admin_policy_arns.csv", self._admin_policies),
        ):
            path = self._lookups_dir / filename
            if not path.exists():
                logger.debug("lookup_not_found", path=str(path))
                continue
            with path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    val = row.get("principal_arn") or row.get("role_arn") or row.get("policy_arn", "")
                    if val:
                        target.add(val.strip())
            logger.debug("lookup_loaded", path=str(path), count=len(target))


# ── unit-test examples ────────────────────────────────────────────────────────

def _example_tests() -> None:
    """Illustrative assertions — run with pytest or directly (no AWS calls made)."""
    enricher = AlertEnricher(lookups_dir=Path("splunk/lookups"))

    alert = {
        "detection_id": "CDET-001",
        "creator_arn": "arn:aws:iam::123456789012:user/attacker",
        "event_source_ip": "203.0.113.45",
        "new_user_name": "backdoor-user",
        "mfa_used": "no",
        "severity": "high",
    }

    enriched = enricher.enrich(alert)

    assert enriched.attack_tactic == "Persistence"
    assert enriched.attack_technique == "T1136.003"
    assert enriched.base_severity == "high"
    # MFA=no should escalate CDET-001 to critical
    assert enriched.enriched_severity == "critical"
    assert enriched.severity_escalation_reason != ""
    assert len(enriched.recommended_queries) >= 2
    assert enriched.original["detection_id"] == "CDET-001"

    print("All enrichment assertions passed.")


if __name__ == "__main__":
    _example_tests()
