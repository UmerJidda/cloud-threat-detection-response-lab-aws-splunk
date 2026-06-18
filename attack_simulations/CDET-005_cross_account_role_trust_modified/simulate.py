#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              ATTACK SIMULATION — AUTHORIZED USE ONLY                        ║
║  CDET-005: Cross-Account Role Trust Relationship Modified                    ║
║  Tactic: Privilege Escalation | T1484.002 — Trust Modification               ║
║                                                                              ║
║  This script simulates modifying an IAM role trust policy to grant           ║
║  cross-account access to an external AWS account.                            ║
║  Run ONLY in authorized test environments with explicit written approval.    ║
║  Unauthorized use against production systems may violate computer fraud laws.║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Dry-run (default — prints actions only):
    python simulate.py --role-name TestRole --external-account-id 999999999999

    # Execute with existing role:
    python simulate.py --role-name TestRole --external-account-id 999999999999 --execute

    # Execute by creating a new simulation role:
    python simulate.py --external-account-id 999999999999 --execute --create-role

    # Execute with cleanup:
    python simulate.py --role-name TestRole --external-account-id 999999999999 --execute --cleanup

    # Cleanup only (restore original trust policy):
    python simulate.py --role-name TestRole --execute --cleanup-only
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
log = logging.getLogger("cdet005-sim")

SIMULATION_ROLE_NAME = "cdet005-simulation-target-role"


# ---------------------------------------------------------------------------
# Helper: build trust policy documents
# ---------------------------------------------------------------------------

def build_initial_trust_policy(account_id: str) -> dict:
    """Build a minimal trust policy allowing current account's root."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def build_modified_trust_policy(
    original_policy: dict, external_account_id: str
) -> dict:
    """Add an external account principal to an existing trust policy."""
    modified = json.loads(json.dumps(original_policy))  # Deep copy
    external_statement = {
        "Sid": "ExternalAccessCdet005Simulation",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{external_account_id}:root"},
        "Action": "sts:AssumeRole",
    }
    modified["Statement"].append(external_statement)
    return modified


# ---------------------------------------------------------------------------
# Core simulation functions
# ---------------------------------------------------------------------------

def create_simulation_role(
    iam_client,
    account_id: str,
    dry_run: bool,
) -> Optional[str]:
    """
    Create a simulation target role with a minimal trust policy.
    CloudTrail event: CreateRole
    """
    trust_policy = build_initial_trust_policy(account_id)

    if dry_run:
        log.info("[DRY-RUN] Would call: iam.create_role(RoleName='%s', AssumeRolePolicyDocument=...)", SIMULATION_ROLE_NAME)
        log.info("[DRY-RUN] CloudTrail event: CreateRole")
        return SIMULATION_ROLE_NAME

    log.warning("EXECUTING: iam.create_role(RoleName='%s')", SIMULATION_ROLE_NAME)
    try:
        iam_client.create_role(
            RoleName=SIMULATION_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="CDET-005 simulation target role — safe to delete",
            Tags=[
                {"Key": "SimulationId", "Value": "CDET-005"},
                {"Key": "SafeToDelete", "Value": "true"},
            ],
        )
        log.info("Created simulation role: %s", SIMULATION_ROLE_NAME)
        return SIMULATION_ROLE_NAME
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityAlreadyExists":
            log.info("Role '%s' already exists — using it", SIMULATION_ROLE_NAME)
            return SIMULATION_ROLE_NAME
        log.error("Failed to create role: %s", exc)
        return None


def get_current_trust_policy(
    iam_client,
    role_name: str,
) -> Optional[dict]:
    """Read the current trust policy of a role (for backup before modification)."""
    try:
        response = iam_client.get_role(RoleName=role_name)
        trust_policy = response["Role"]["AssumeRolePolicyDocument"]
        log.info("Retrieved current trust policy for role: %s", role_name)
        return trust_policy
    except ClientError as exc:
        log.error("Cannot get role '%s': %s", role_name, exc)
        return None


def modify_trust_policy(
    iam_client,
    role_name: str,
    external_account_id: str,
    original_policy: dict,
    dry_run: bool,
) -> bool:
    """
    Modify the role's trust policy to add an external account principal.

    WARNING: This allows any principal in external_account_id to assume this role.
    CloudTrail event: UpdateAssumeRolePolicy
    """
    modified_policy = build_modified_trust_policy(original_policy, external_account_id)

    if dry_run:
        log.info(
            "[DRY-RUN] Would call: iam.update_assume_role_policy(RoleName='%s', PolicyDocument=...)",
            role_name,
        )
        log.info("[DRY-RUN] Adding external account %s to trust policy", external_account_id)
        log.info("[DRY-RUN] Modified policy: %s", json.dumps(modified_policy, indent=2))
        log.info("[DRY-RUN] CloudTrail event: UpdateAssumeRolePolicy")
        return True

    # WARNING: This modifies the role trust policy to allow cross-account access.
    log.warning(
        "EXECUTING: iam.update_assume_role_policy(RoleName='%s')",
        role_name,
    )
    log.warning(
        "Adding external account %s to trust policy — any principal in that account "
        "can now assume role '%s'",
        external_account_id,
        role_name,
    )
    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(modified_policy),
        )
        log.info(
            "Trust policy modified: role '%s' now trusts external account '%s'",
            role_name,
            external_account_id,
        )
        return True
    except ClientError as exc:
        log.error("Failed to update trust policy for '%s': %s", role_name, exc)
        return False


def restore_trust_policy(
    iam_client,
    role_name: str,
    original_policy: dict,
    dry_run: bool,
) -> None:
    """Restore the original trust policy for the role."""
    if dry_run:
        log.info("[DRY-RUN] Would restore original trust policy for role: %s", role_name)
        return

    # WARNING: This calls update_assume_role_policy to restore original trust settings.
    log.warning("EXECUTING: iam.update_assume_role_policy() — restoring original trust policy for '%s'", role_name)
    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(original_policy),
        )
        log.info("Trust policy restored for role: %s", role_name)
    except ClientError as exc:
        log.error("Failed to restore trust policy for '%s': %s", role_name, exc)


def delete_simulation_role(
    iam_client,
    dry_run: bool,
) -> None:
    """Delete the simulation role created by --create-role."""
    if dry_run:
        log.info("[DRY-RUN] Would call: iam.delete_role(RoleName='%s')", SIMULATION_ROLE_NAME)
        return

    log.warning("EXECUTING: iam.delete_role(RoleName='%s')", SIMULATION_ROLE_NAME)
    try:
        iam_client.delete_role(RoleName=SIMULATION_ROLE_NAME)
        log.info("Deleted simulation role: %s", SIMULATION_ROLE_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            log.error("Failed to delete simulation role: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CDET-005: Simulate cross-account role trust modification (T1484.002)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simulate.py --role-name TestRole --external-account-id 999999999999
  python simulate.py --role-name TestRole --external-account-id 999999999999 --execute --cleanup
  python simulate.py --external-account-id 999999999999 --execute --create-role --cleanup
        """,
    )
    parser.add_argument(
        "--role-name",
        type=str,
        help="Existing IAM role name to modify (mutually exclusive with --create-role)",
    )
    parser.add_argument(
        "--external-account-id",
        type=str,
        default="999999999999",
        help="AWS account ID to add to the role trust policy (simulated attacker account, default: 999999999999)",
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
        "--create-role",
        action="store_true",
        default=False,
        help="Create a new simulation role instead of modifying an existing one",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        default=False,
        help="Restore original trust policy after simulation (requires --execute)",
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        default=False,
        help="Only restore original trust policy, skip simulation (requires --execute and --role-name)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dry_run = not args.execute

    if not args.role_name and not args.create_role and not args.cleanup_only:
        print("ERROR: Specify --role-name <name> or use --create-role to create a simulation role")
        return 1

    if dry_run:
        log.info("=" * 70)
        log.info("DRY-RUN MODE — No AWS API calls will be made")
        log.info("=" * 70)
    else:
        log.warning("=" * 70)
        log.warning("EXECUTE MODE — Real AWS API calls WILL be made")
        log.warning("Ensure you are running in an authorized test environment")
        log.warning("=" * 70)
        time.sleep(2)

    # Build boto3 session — no hardcoded credentials
    session = boto3.Session(region_name=args.region)
    iam = session.client("iam")
    sts = session.client("sts")

    try:
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        log.info("Running as: %s (Account: %s)", identity["Arn"], account_id)
    except ClientError as exc:
        log.error("Cannot determine caller identity: %s", exc)
        return 1

    # Determine target role name
    role_name = args.role_name or SIMULATION_ROLE_NAME

    # Cleanup-only mode
    if args.cleanup_only:
        if not args.role_name:
            log.error("--cleanup-only requires --role-name")
            return 1
        original = get_current_trust_policy(iam, role_name)
        if original:
            # In cleanup-only we can't know the original — just log a warning
            log.warning(
                "Cleanup-only mode: current trust policy has %d statements. "
                "Manually verify the policy is correct after cleanup.",
                len(original.get("Statement", [])),
            )
            log.warning("Current policy: %s", json.dumps(original, indent=2))
        return 0

    # Create simulation role if requested
    if args.create_role:
        role_name = create_simulation_role(iam, account_id, dry_run) or SIMULATION_ROLE_NAME

    # Capture original trust policy
    original_policy: dict = {}
    if not dry_run:
        captured = get_current_trust_policy(iam, role_name)
        if captured is None:
            log.error("Cannot read trust policy for role '%s' — aborting", role_name)
            return 1
        original_policy = captured
    else:
        original_policy = build_initial_trust_policy(account_id)
        log.info("[DRY-RUN] Simulated original policy: %s", json.dumps(original_policy))

    log.info("Target role: %s | External account to add: %s", role_name, args.external_account_id)

    # Execute modification
    success = modify_trust_policy(iam, role_name, args.external_account_id, original_policy, dry_run)
    if not success:
        return 1

    log.info("Simulation complete.")
    log.info(
        "Expected CDET-005 alert: index=aws_cloudtrail eventName=UpdateAssumeRolePolicy "
        "requestParameters.roleName=%s",
        role_name,
    )

    # Optional cleanup
    if args.cleanup:
        log.info("Cleanup: waiting 30 seconds for CloudTrail event propagation...")
        if not dry_run:
            time.sleep(30)

        restore_trust_policy(iam, role_name, original_policy, dry_run)

        if args.create_role:
            delete_simulation_role(iam, dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
