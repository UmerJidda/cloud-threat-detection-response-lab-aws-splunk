#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              ATTACK SIMULATION — READ-ONLY ASSESSMENT SCRIPT                ║
║  CDET-006: Root Account Activity Detection Verification                      ║
║  Tactic: Initial Access | T1078.004 — Valid Accounts: Cloud Accounts         ║
║                                                                              ║
║  This script is a READ-ONLY assessment tool. It does NOT simulate root       ║
║  account access (that requires manual console login). Instead it:            ║
║    1. Calls GetCallerIdentity to verify if the current session is root       ║
║    2. Checks CloudTrail configuration for root detection coverage            ║
║    3. Verifies CloudWatch alarms for root activity exist                     ║
║    4. Reviews recent root activity in CloudTrail lookup                      ║
║                                                                              ║
║  For the actual root simulation, use the MANUAL steps in simulation_steps.md ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Full assessment (default):
    python simulate.py

    # Check only if current session is root:
    python simulate.py --check-identity-only

    # Verify detection coverage:
    python simulate.py --verify-coverage

    # Check for recent root activity in CloudTrail:
    python simulate.py --check-recent-activity --lookback-hours 72
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone, timedelta

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
log = logging.getLogger("cdet006-sim")


# ---------------------------------------------------------------------------
# Identity check
# ---------------------------------------------------------------------------


def check_identity(sts_client) -> dict:
    """
    Call GetCallerIdentity to determine if the current session is root.
    This generates a CloudTrail event regardless of whether the caller is root.
    """
    try:
        identity = sts_client.get_caller_identity()
        is_root = identity["Arn"].endswith(":root")
        log.info("=" * 60)
        log.info("Caller Identity:")
        log.info("  UserId:  %s", identity["UserId"])
        log.info("  Account: %s", identity["Account"])
        log.info("  Arn:     %s", identity["Arn"])
        log.info("  IsRoot:  %s", is_root)
        log.info("=" * 60)

        if is_root:
            log.warning("ALERT: Current session IS the root account!")
            log.warning("This GetCallerIdentity call has generated a CloudTrail event")
            log.warning("with userIdentity.type=Root — CDET-006 should fire in ~5 minutes")
        else:
            log.info("Current session is NOT root (%s)", identity["Arn"])
            log.info("To generate a root CloudTrail event, follow manual steps in simulation_steps.md")
        return identity
    except ClientError as exc:
        log.error("GetCallerIdentity failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# CloudTrail coverage verification
# ---------------------------------------------------------------------------


def verify_cloudtrail_coverage(ct_client, logs_client) -> dict:
    """Check CloudTrail configuration for root detection coverage."""
    results = {
        "has_active_trail": False,
        "has_global_service_events": False,
        "has_multi_region_trail": False,
        "has_cloudwatch_logs": False,
        "has_log_file_validation": False,
        "issues": [],
    }

    log.info("Verifying CloudTrail configuration for root detection coverage...")

    try:
        trails = ct_client.describe_trails(includeShadowTrails=False)
        trail_list = trails.get("trailList", [])

        if not trail_list:
            results["issues"].append("CRITICAL: No CloudTrail trails found — no audit logging")
            log.error("No CloudTrail trails found")
            return results

        for trail in trail_list:
            trail_name = trail.get("Name", "unknown")
            try:
                status = ct_client.get_trail_status(Name=trail_name)
                is_logging = status.get("IsLogging", False)
            except ClientError:
                is_logging = False

            log.info(
                "Trail: %s | Logging: %s | MultiRegion: %s | GlobalEvents: %s | CWLogs: %s | Validation: %s",
                trail_name,
                is_logging,
                trail.get("IsMultiRegionTrail", False),
                trail.get("IncludeGlobalServiceEvents", False),
                bool(trail.get("CloudWatchLogsLogGroupArn")),
                trail.get("LogFileValidationEnabled", False),
            )

            if is_logging:
                results["has_active_trail"] = True

            if trail.get("IncludeGlobalServiceEvents", False):
                results["has_global_service_events"] = True
            else:
                results["issues"].append(
                    f"Trail '{trail_name}': IncludeGlobalServiceEvents=False — root IAM API calls may not be logged"
                )

            if trail.get("IsMultiRegionTrail", False):
                results["has_multi_region_trail"] = True
            else:
                results["issues"].append(
                    f"Trail '{trail_name}': Single-region only — root activity in other regions won't be captured"
                )

            if trail.get("CloudWatchLogsLogGroupArn"):
                results["has_cloudwatch_logs"] = True
            else:
                results["issues"].append(
                    f"Trail '{trail_name}': No CloudWatch Logs integration — "
                    "root activity detection latency will be 5-15 minutes (S3 delivery)"
                )

            if trail.get("LogFileValidationEnabled", False):
                results["has_log_file_validation"] = True

    except ClientError as exc:
        log.error("Cannot describe CloudTrail trails: %s", exc)
        results["issues"].append(f"Cannot access CloudTrail: {exc}")

    return results


def verify_cloudwatch_alarms(cw_client) -> dict:
    """Check for CloudWatch alarms covering root activity."""
    results = {
        "has_root_alarm": False,
        "alarm_names": [],
        "alarm_states": {},
    }

    try:
        alarms = cw_client.describe_alarms()
        all_alarms = alarms.get("MetricAlarms", [])

        root_alarms = [
            a for a in all_alarms if "root" in a["AlarmName"].lower() or "Root" in a.get("AlarmDescription", "")
        ]

        if root_alarms:
            results["has_root_alarm"] = True
            for alarm in root_alarms:
                results["alarm_names"].append(alarm["AlarmName"])
                results["alarm_states"][alarm["AlarmName"]] = alarm["StateValue"]
                log.info("Root alarm found: %s (State: %s)", alarm["AlarmName"], alarm["StateValue"])
        else:
            log.warning("No CloudWatch alarms found for root activity")
            log.warning("Recommend creating a CloudWatch alarm as described in simulation_steps.md")

    except ClientError as exc:
        log.error("Cannot check CloudWatch alarms: %s", exc)

    return results


# ---------------------------------------------------------------------------
# Recent root activity check
# ---------------------------------------------------------------------------


def check_recent_root_activity(ct_client, lookback_hours: int = 72) -> list[dict]:
    """Look up recent CloudTrail events from the root account."""
    log.info("Checking for root account activity in the last %d hours...", lookback_hours)

    start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    root_events = []

    try:
        paginator = ct_client.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
            StartTime=start_time,
        ):
            for event in page.get("Events", []):
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                if ct_event.get("userIdentity", {}).get("type") == "Root":
                    root_events.append(
                        {
                            "time": event.get("EventTime"),
                            "eventName": event.get("EventName"),
                            "sourceIP": ct_event.get("sourceIPAddress"),
                            "mfaUsed": ct_event.get("additionalEventData", {}).get("MFAUsed", "Unknown"),
                            "loginResult": ct_event.get("responseElements", {}).get("ConsoleLogin", "Unknown"),
                        }
                    )
    except ClientError as exc:
        log.error("Cannot look up CloudTrail events: %s", exc)

    if root_events:
        log.warning("Found %d root ConsoleLogin event(s) in the last %d hours:", len(root_events), lookback_hours)
        for evt in root_events:
            log.warning(
                "  %s | IP: %s | MFA: %s | Result: %s",
                evt["time"],
                evt["sourceIP"],
                evt["mfaUsed"],
                evt["loginResult"],
            )
    else:
        log.info("No root ConsoleLogin events found in the last %d hours", lookback_hours)

    return root_events


# ---------------------------------------------------------------------------
# Assessment summary
# ---------------------------------------------------------------------------


def print_assessment_summary(
    ct_results: dict,
    cw_results: dict,
    recent_activity: list[dict],
) -> None:
    """Print a formatted assessment summary."""
    log.info("")
    log.info("=" * 70)
    log.info("CDET-006 ROOT ACCOUNT DETECTION ASSESSMENT SUMMARY")
    log.info("=" * 70)

    checks = [
        ("Active CloudTrail trail", ct_results.get("has_active_trail", False)),
        ("Global service events enabled", ct_results.get("has_global_service_events", False)),
        ("Multi-region trail enabled", ct_results.get("has_multi_region_trail", False)),
        ("CloudWatch Logs integration", ct_results.get("has_cloudwatch_logs", False)),
        ("Log file validation enabled", ct_results.get("has_log_file_validation", False)),
        ("CloudWatch alarm for root activity", cw_results.get("has_root_alarm", False)),
    ]

    for check_name, passed in checks:
        status = "PASS" if passed else "FAIL"
        log.info("  [%s] %s", status, check_name)

    if ct_results.get("issues"):
        log.info("")
        log.info("Issues found:")
        for issue in ct_results["issues"]:
            log.warning("  ! %s", issue)

    if recent_activity:
        log.warning("")
        log.warning("  ALERT: %d root activity event(s) found in recent history", len(recent_activity))

    log.info("")
    all_passed = all(passed for _, passed in checks) and not recent_activity
    if all_passed:
        log.info("Assessment result: COVERAGE COMPLETE — root detection is properly configured")
    else:
        log.warning("Assessment result: GAPS FOUND — review issues above and remediate")

    log.info("")
    log.info("To fully test CDET-006, perform the manual root console login test")
    log.info("described in simulation_steps.md and verify the alert fires in Splunk.")
    log.info("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CDET-006: Root account activity detection assessment (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script is READ-ONLY. It does not simulate root access.
For the actual simulation, use the manual steps in simulation_steps.md.

Examples:
  python simulate.py
  python simulate.py --check-identity-only
  python simulate.py --verify-coverage
  python simulate.py --check-recent-activity --lookback-hours 168
        """,
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--check-identity-only",
        action="store_true",
        default=False,
        help="Only call GetCallerIdentity — check if current session is root",
    )
    parser.add_argument(
        "--verify-coverage",
        action="store_true",
        default=False,
        help="Only verify CloudTrail and CloudWatch alarm coverage",
    )
    parser.add_argument(
        "--check-recent-activity",
        action="store_true",
        default=False,
        help="Only check for recent root activity in CloudTrail",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=72,
        help="Hours to look back for recent root activity (default: 72)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Build boto3 session — no hardcoded credentials
    session = boto3.Session(region_name=args.region)
    sts = session.client("sts")
    ct = session.client("cloudtrail")
    cw = session.client("cloudwatch")

    log.info("CDET-006 Root Account Detection Assessment")
    log.info("This is a read-only assessment — no write operations will be performed")

    # Run selected checks
    if args.check_identity_only:
        check_identity(sts)
        return 0

    if args.verify_coverage:
        ct_results = verify_cloudtrail_coverage(ct, None)
        cw_results = verify_cloudwatch_alarms(cw)
        print_assessment_summary(ct_results, cw_results, [])
        return 0

    if args.check_recent_activity:
        recent = check_recent_root_activity(ct, args.lookback_hours)
        log.info("Found %d root activity events", len(recent))
        return 0

    # Full assessment (default)
    log.info("Running full root detection coverage assessment...")
    check_identity(sts)
    ct_results = verify_cloudtrail_coverage(ct, None)
    cw_results = verify_cloudwatch_alarms(cw)
    recent_activity = check_recent_root_activity(ct, args.lookback_hours)
    print_assessment_summary(ct_results, cw_results, recent_activity)

    return 0


if __name__ == "__main__":
    sys.exit(main())
