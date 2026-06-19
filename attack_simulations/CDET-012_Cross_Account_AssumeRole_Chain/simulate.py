#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Use only in AWS Organizations you own or have
explicit written permission to test. Attempting to assume roles in accounts
you do not own is unauthorized access and may be illegal.

CDET-012 — Cross-Account AssumeRole Chain Simulator
Tactic: Lateral Movement | T1550.001

This script performs read-only reconnaissance:
- Lists accessible accounts via AWS Organizations
- Attempts AssumeRole into a specified test role in each account
- Reports which accounts are accessible (role assumption succeeded)
- Generates AssumeRole CloudTrail events in each attempted account

In execute mode, actually assumes into a specified test role and reports
the resulting credentials' identity (GetCallerIdentity).

Usage:
    # Read-only: enumerate org accounts and test role accessibility
    python simulate.py --target-role OrganizationAccountAccessRole

    # Execute: assume into a specific test role and confirm identity
    python simulate.py --execute --target-account 111111111111 --target-role TestRole

    # Chain test: assume hop1, then use those credentials for hop2
    python simulate.py --execute --target-account 111111111111 --target-role Role1 --chain-to-account 222222222222 --chain-to-role Role2
"""

import argparse
import logging
import sys
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet012")

COMMON_TARGET_ROLES = [
    "OrganizationAccountAccessRole",
    "AWSControlTowerExecution",
    "AdminRole",
    "administrator",
    "SecurityAuditRole",
    "TerraformRole",
    "DeployRole",
]


def get_org_accounts(session: boto3.Session) -> list[dict]:
    """List all active accounts in the AWS Organization."""
    org = session.client("organizations")
    accounts = []
    try:
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page.get("Accounts", []):
                if account.get("Status") == "ACTIVE":
                    accounts.append(account)
        log.info("Found %d active accounts in organization", len(accounts))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            log.warning("This account is not part of an AWS Organization")
        elif code == "AccessDenied":
            log.warning("AccessDenied on organizations:ListAccounts — not in management account or missing permissions")
        else:
            log.warning("Could not list org accounts: %s", code)
    return accounts


def try_assume_role(
    sts_client,
    role_arn: str,
    session_name: str,
    duration: int = 900,
) -> Optional[dict]:
    """
    Attempt to assume a role. Returns credentials dict or None on failure.
    Generates a CloudTrail AssumeRole event in the target account.
    """
    try:
        resp = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration,
        )
        return resp["Credentials"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "UnauthorizedAccess"):
            return None  # Expected for inaccessible accounts
        else:
            log.debug("AssumeRole to %s failed: %s", role_arn, code)
            return None


def get_caller_identity_with_creds(creds: dict, region: str) -> Optional[dict]:
    """Use assumed credentials to call GetCallerIdentity."""
    try:
        temp_session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
        sts = temp_session.client("sts")
        return sts.get_caller_identity()
    except ClientError as e:
        log.warning("GetCallerIdentity with assumed creds failed: %s", e.response["Error"]["Code"])
        return None


def enumerate_accessible_accounts(
    session: boto3.Session,
    target_role: str,
    region: str,
    accounts: list[dict],
    current_account: str,
) -> list[dict]:
    """
    Attempt AssumeRole in each account and report accessibility.
    This is the core reconnaissance function — generates AssumeRole events.
    """
    sts = session.client("sts")
    accessible = []

    print()
    print(f"Attempting AssumeRole with role '{target_role}' in {len(accounts)} accounts:")
    print("-" * 70)

    for account in accounts:
        account_id = account["Id"]
        account_name = account.get("Name", "unknown")

        # Skip the current account
        if account_id == current_account:
            log.debug("Skipping current account %s", account_id)
            continue

        role_arn = f"arn:aws:iam::{account_id}:role/{target_role}"
        session_name = f"cdet012-recon-{account_id[-6:]}"

        creds = try_assume_role(sts, role_arn, session_name, duration=900)

        if creds:
            identity = get_caller_identity_with_creds(creds, region)
            accessible.append(
                {
                    "account_id": account_id,
                    "account_name": account_name,
                    "role": target_role,
                    "assumed_arn": identity.get("Arn") if identity else "unknown",
                }
            )
            log.warning(
                "[ACCESSIBLE] Account: %s (%s) — Role: %s",
                account_id,
                account_name,
                target_role,
            )
        else:
            log.info("[BLOCKED]    Account: %s (%s)", account_id, account_name)

    return accessible


def execute_single_assume(
    session: boto3.Session,
    target_account: str,
    target_role: str,
    region: str,
    current_arn: str,
) -> Optional[dict]:
    """Assume a single specified role and return credentials."""
    sts = session.client("sts")
    role_arn = f"arn:aws:iam::{target_account}:role/{target_role}"
    session_name = "cdet012-execute-test"

    log.info("Attempting AssumeRole: %s", role_arn)
    log.info("Caller identity: %s", current_arn)

    creds = try_assume_role(sts, role_arn, session_name, duration=3600)

    if creds:
        identity = get_caller_identity_with_creds(creds, region)
        if identity:
            log.info(
                "AssumeRole SUCCESS — new identity: %s",
                identity.get("Arn", "unknown"),
            )
            log.info(
                "CloudTrail AssumeRole event generated in account %s",
                target_account,
            )
        return creds
    else:
        log.error(
            "AssumeRole FAILED for %s — AccessDenied or role not found",
            role_arn,
        )
        log.info("AccessDenied AssumeRole attempts are still recorded in CloudTrail")
        return None


def execute_role_chain(
    hop1_creds: dict,
    chain_to_account: str,
    chain_to_role: str,
    region: str,
) -> Optional[dict]:
    """
    Use credentials from hop1 to assume a role in a second account (role chaining).
    Generates a second AssumeRole event with userIdentity.type = AssumedRole.
    """
    # Create a session using the first-hop credentials
    hop1_session = boto3.Session(
        aws_access_key_id=hop1_creds["AccessKeyId"],
        aws_secret_access_key=hop1_creds["SecretAccessKey"],
        aws_session_token=hop1_creds["SessionToken"],
        region_name=region,
    )

    hop1_sts = hop1_session.client("sts")
    hop1_identity = hop1_sts.get_caller_identity()
    log.info("Using hop-1 credentials: %s", hop1_identity.get("Arn"))
    log.info("Attempting hop-2 AssumeRole chain to account %s", chain_to_account)

    # This is the chain — AssumedRole credentials assuming another role
    # CloudTrail will record this with userIdentity.type = "AssumedRole"
    role_arn = f"arn:aws:iam::{chain_to_account}:role/{chain_to_role}"
    session_name = "cdet012-chain-hop2"

    creds = try_assume_role(hop1_sts, role_arn, session_name, duration=3600)

    if creds:
        identity = get_caller_identity_with_creds(creds, region)
        if identity:
            log.info(
                "Role chain hop-2 SUCCESS — final identity: %s",
                identity.get("Arn", "unknown"),
            )
            log.warning(
                "CDET-012 should detect: AssumedRole principal (%s) assuming role in account %s",
                hop1_identity.get("Arn"),
                chain_to_account,
            )
        return creds
    else:
        log.warning(
            "Chain hop-2 FAILED — AccessDenied for %s in account %s",
            chain_to_role,
            chain_to_account,
        )
        log.info("The failed attempt is still recorded in CloudTrail as an AssumeRole event")
        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-012: Cross-Account AssumeRole Chain Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target-role",
        default="OrganizationAccountAccessRole",
        help="Role name to attempt in each org account. Default: OrganizationAccountAccessRole",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually assume the role. Without this flag, only org account listing is performed.",
    )
    parser.add_argument(
        "--target-account",
        default=None,
        help="Specific account ID for single-account assumption (requires --execute).",
    )
    parser.add_argument(
        "--chain-to-account",
        default=None,
        help="Account ID for the second hop in a role chain (requires --execute --target-account).",
    )
    parser.add_argument(
        "--chain-to-role",
        default="OrganizationAccountAccessRole",
        help="Role name for the second hop chain. Default: OrganizationAccountAccessRole",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile name. Default: boto3 default chain.",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region. Default: us-east-1",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("CDET-012 — Cross-Account AssumeRole Chain Simulator")
    print("Tactic: Lateral Movement | MITRE T1550.001")
    if args.execute:
        print("Mode: EXECUTE (will perform real AssumeRole calls)")
    else:
        print("Mode: RECON (org enumeration + accessibility check)")
    print("=" * 60)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        log.error("Failed to create boto3 session: %s", e)
        sys.exit(1)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        current_account = identity["Account"]
        current_arn = identity["Arn"]
        log.info("Authenticated as: %s (Account: %s)", current_arn, current_account)
    except NoCredentialsError:
        log.error("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)

    # Always enumerate org accounts (read-only reconnaissance)
    accounts = get_org_accounts(session)

    if not accounts:
        log.warning(
            "No organization accounts found. "
            "If this account is in an org, check organizations:ListAccounts permissions."
        )
        if args.execute and args.target_account:
            log.info("Proceeding with direct assume-role to specified target account")
            accounts = [{"Id": args.target_account, "Name": "specified-target", "Status": "ACTIVE"}]

    if args.execute:
        if args.target_account:
            # Single target execution
            hop1_creds = execute_single_assume(session, args.target_account, args.target_role, args.region, current_arn)

            if hop1_creds and args.chain_to_account:
                # Chain to second account
                log.info("Proceeding with role chain to second account...")
                execute_role_chain(
                    hop1_creds,
                    args.chain_to_account,
                    args.chain_to_role,
                    args.region,
                )
        elif accounts:
            # Enumerate all org accounts
            accessible = enumerate_accessible_accounts(
                session, args.target_role, args.region, accounts, current_account
            )

            print()
            print("=" * 60)
            print("ROLE CHAIN RECONNAISSANCE RESULTS")
            print("=" * 60)
            print(f"Total accounts checked:  {len(accounts)}")
            print(f"Accounts accessible:     {len(accessible)}")
            print()

            if accessible:
                print("ACCESSIBLE ACCOUNTS:")
                for acc in accessible:
                    print(f"  Account: {acc['account_id']} ({acc['account_name']})")
                    print(f"    Role:   {acc['role']}")
                    print(f"    ARN:    {acc['assumed_arn']}")
                print()
                print(
                    f"[ALERT] {len(accessible)} accounts accessible via role chain. "
                    "CDET-012 should have fired for each cross-account AssumeRole event."
                )
            else:
                print("No accounts were accessible with the specified role.")
                print("This is the expected result in a well-configured organization.")
        else:
            log.error("No accounts to test. Provide --target-account or ensure org permissions.")
    else:
        # Dry-run: just show what would be done
        print()
        print("=" * 60)
        print("DRY-RUN: Organization Account Discovery")
        print("=" * 60)
        if accounts:
            print(f"\nFound {len(accounts)} active accounts in organization:")
            for acc in accounts[:20]:
                print(f"  {acc['Id']:<15} {acc.get('Name', 'unknown')}")
            if len(accounts) > 20:
                print(f"  ... and {len(accounts) - 20} more")

            print()
            print(f"In execute mode, would attempt AssumeRole with role '{args.target_role}'")
            print("in each of these accounts.")
            print()
            print("Common target roles:")
            for role in COMMON_TARGET_ROLES:
                print(f"  - {role}")
        else:
            print("No org accounts found. Add --execute --target-account ACCOUNT_ID")
            print("to test a specific account directly.")


if __name__ == "__main__":
    main()
