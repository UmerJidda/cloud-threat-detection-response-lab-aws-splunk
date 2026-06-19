#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              ATTACK SIMULATION — IMDS ASSESSMENT SCRIPT                     ║
║  CDET-007: EC2 Instance Metadata Credential Abuse Assessment                 ║
║  Tactic: Credential Access | T1552.005 — Cloud Instance Metadata API         ║
║                                                                              ║
║  This script is an ASSESSMENT TOOL — it does NOT steal or use credentials.  ║
║  It performs the following READ-ONLY or INFORMATIONAL actions:               ║
║    1. Checks if the current instance has IMDSv1 enabled (metadata endpoint) ║
║    2. Lists EC2 instance profiles to identify attack surface                 ║
║    3. Identifies instances with IMDSv1 still enabled account-wide            ║
║    4. Prints recommendations for enforcing IMDSv2                            ║
║                                                                              ║
║  For the actual simulation steps (curl commands, external credential use),  ║
║  refer to simulation_steps.md.                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    # Full assessment (default):
    python simulate.py

    # Check IMDS version on current instance (if running on EC2):
    python simulate.py --check-imds-local

    # Enumerate instances with IMDSv1 enabled:
    python simulate.py --enumerate-imdsv1 --region us-east-1

    # Check instance profiles (identify high-value targets):
    python simulate.py --list-instance-profiles

    # Generate IMDSv2 enforcement report:
    python simulate.py --remediation-report
"""

import argparse
import logging
import sys
import urllib.request
import urllib.error

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
log = logging.getLogger("cdet007-sim")

IMDS_BASE_URL = "http://169.254.169.254"
IMDS_TIMEOUT_SECONDS = 2


# ---------------------------------------------------------------------------
# IMDS check (safe — only checks metadata, does NOT retrieve credentials)
# ---------------------------------------------------------------------------


def is_running_on_ec2() -> bool:
    """Check if we are running on an EC2 instance by probing the IMDS endpoint."""
    try:
        req = urllib.request.Request(
            f"{IMDS_BASE_URL}/latest/meta-data/instance-id",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=IMDS_TIMEOUT_SECONDS) as resp:
            return resp.status == 200
    except Exception:
        return False


def check_imdsv1_enabled() -> dict:
    """
    Check if IMDSv1 is accessible on the current instance.

    This makes a GET request to the metadata service WITHOUT a session token.
    If it succeeds, IMDSv1 is enabled (the instance is vulnerable).
    If it returns 401, IMDSv2 is required (the instance is hardened).

    IMPORTANT: This does NOT retrieve any credentials — only the instance ID.
    """
    result = {
        "on_ec2": False,
        "imdsv1_accessible": False,
        "imdsv2_accessible": False,
        "instance_id": None,
        "role_names": [],
    }

    if not is_running_on_ec2():
        log.info("Not running on an EC2 instance — IMDS check skipped")
        log.info("To run this check, execute the script on an EC2 instance")
        return result

    result["on_ec2"] = True
    log.info("Running on EC2 instance — checking IMDS version availability")

    # Test IMDSv1 (no token required)
    try:
        req = urllib.request.Request(
            f"{IMDS_BASE_URL}/latest/meta-data/instance-id",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=IMDS_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                result["imdsv1_accessible"] = True
                result["instance_id"] = resp.read().decode()
                log.warning("IMDSv1 is ACCESSIBLE — instance is vulnerable to SSRF-based credential theft")
                log.warning("Instance ID: %s", result["instance_id"])
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            log.info("IMDSv1 is NOT accessible (401 response) — IMDSv2 is required (hardened)")
        else:
            log.warning("Unexpected IMDS response code: %d", exc.code)
    except Exception as exc:
        log.warning("IMDS probe failed: %s", exc)

    # Test IMDSv2 (with token)
    try:
        token_req = urllib.request.Request(
            f"{IMDS_BASE_URL}/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "10"},
        )
        with urllib.request.urlopen(token_req, timeout=IMDS_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                token = resp.read().decode()
                result["imdsv2_accessible"] = True
                log.info("IMDSv2 is accessible (token obtained successfully)")

                # Use the token to list role names ONLY (not retrieve credentials)
                roles_req = urllib.request.Request(
                    f"{IMDS_BASE_URL}/latest/meta-data/iam/security-credentials/",
                    method="GET",
                    headers={"X-aws-ec2-metadata-token": token},
                )
                try:
                    with urllib.request.urlopen(roles_req, timeout=IMDS_TIMEOUT_SECONDS) as roles_resp:
                        roles_data = roles_resp.read().decode().strip()
                        if roles_data:
                            result["role_names"] = [r for r in roles_data.split("\n") if r]
                            log.info(
                                "Instance has role(s) attached (role names visible — NOT retrieving credentials): %s",
                                result["role_names"],
                            )
                        else:
                            log.info("Instance has no IAM role attached")
                except Exception:
                    log.info("No IAM role attached to this instance")
    except Exception as exc:
        log.warning("IMDSv2 token request failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Account-wide IMDS assessment
# ---------------------------------------------------------------------------


def enumerate_imdsv1_instances(
    ec2_client,
    region: str,
) -> list[dict]:
    """
    Enumerate EC2 instances with IMDSv1 enabled (HttpTokens=optional).
    This is a read-only operation using the EC2 API.
    """
    log.info("Enumerating EC2 instances with IMDSv1 enabled in region: %s", region)
    vulnerable_instances = []

    try:
        paginator = ec2_client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]
                    metadata_options = instance.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "unknown")
                    http_endpoint = metadata_options.get("HttpEndpoint", "unknown")
                    state = instance.get("State", {}).get("Name", "unknown")

                    # Get instance name from tags
                    name = next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        "unnamed",
                    )

                    # Get attached IAM role (if any)
                    iam_profile = instance.get("IamInstanceProfile", {})
                    role_arn = iam_profile.get("Arn", "none")

                    is_imdsv1 = http_tokens == "optional" and http_endpoint == "enabled"

                    if is_imdsv1 and state == "running":
                        vulnerable_instances.append(
                            {
                                "instance_id": instance_id,
                                "name": name,
                                "state": state,
                                "http_tokens": http_tokens,
                                "role_arn": role_arn,
                                "private_ip": instance.get("PrivateIpAddress", "N/A"),
                            }
                        )
    except ClientError as exc:
        log.error("Cannot enumerate EC2 instances: %s", exc)

    return vulnerable_instances


def list_instance_profiles_with_permissions(iam_client) -> list[dict]:
    """
    List IAM instance profiles and their attached roles.
    Identifies high-value targets (roles with broad permissions).
    Read-only operation.
    """
    log.info("Enumerating IAM instance profiles and associated role permissions...")
    profiles = []

    PRIVILEGED_KEYWORDS = ["Admin", "FullAccess", "PowerUser"]

    try:
        paginator = iam_client.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            for profile in page["InstanceProfiles"]:
                for role in profile.get("Roles", []):
                    role_name = role["RoleName"]

                    # Check attached policies for privilege level
                    try:
                        attached = iam_client.list_attached_role_policies(RoleName=role_name)
                        privileged_policies = [
                            p["PolicyName"]
                            for p in attached.get("AttachedPolicies", [])
                            if any(kw in p["PolicyName"] for kw in PRIVILEGED_KEYWORDS)
                        ]
                    except ClientError:
                        privileged_policies = []

                    profiles.append(
                        {
                            "profile_name": profile["InstanceProfileName"],
                            "role_name": role_name,
                            "role_arn": role["Arn"],
                            "privileged_policies": privileged_policies,
                            "is_high_value": len(privileged_policies) > 0,
                        }
                    )
    except ClientError as exc:
        log.error("Cannot enumerate instance profiles: %s", exc)

    return profiles


# ---------------------------------------------------------------------------
# Remediation report
# ---------------------------------------------------------------------------


def print_remediation_report(
    imds_result: dict,
    vulnerable_instances: list[dict],
    profiles: list[dict],
) -> None:
    """Print a consolidated IMDSv2 enforcement recommendation report."""
    log.info("")
    log.info("=" * 70)
    log.info("CDET-007 IMDS SECURITY ASSESSMENT REPORT")
    log.info("=" * 70)

    # Local instance check
    if imds_result["on_ec2"]:
        if imds_result["imdsv1_accessible"]:
            log.warning("[FAIL] Current instance: IMDSv1 is ENABLED — vulnerable to SSRF credential theft")
        else:
            log.info("[PASS] Current instance: IMDSv1 is NOT accessible — IMDSv2 enforced")
    else:
        log.info("[INFO] Not running on EC2 — skipping local instance check")

    # Account-wide vulnerable instances
    log.info("")
    if vulnerable_instances:
        log.warning("[FAIL] %d running EC2 instance(s) with IMDSv1 enabled:", len(vulnerable_instances))
        for inst in vulnerable_instances:
            has_role = inst["role_arn"] != "none"
            risk = "HIGH RISK" if has_role else "LOW RISK"
            log.warning(
                "  [%s] %s (%s) | IP: %s | Role: %s",
                risk,
                inst["instance_id"],
                inst["name"],
                inst["private_ip"],
                inst["role_arn"] if has_role else "no role attached",
            )
    else:
        log.info("[PASS] No running instances with IMDSv1 enabled found in current region")

    # High-value instance profiles
    log.info("")
    high_value = [p for p in profiles if p["is_high_value"]]
    if high_value:
        log.warning(
            "[INFO] %d high-privilege instance profile(s) — prime targets if IMDSv1 is enabled:", len(high_value)
        )
        for p in high_value:
            log.warning(
                "  Profile: %s | Role: %s | Policies: %s",
                p["profile_name"],
                p["role_name"],
                ", ".join(p["privileged_policies"]),
            )
    else:
        log.info("[INFO] No high-privilege instance profiles found")

    # Recommendations
    log.info("")
    log.info("REMEDIATION RECOMMENDATIONS:")
    log.info("  1. Enforce IMDSv2 on all instances:")
    log.info("     aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required")
    log.info("  2. Set account-level IMDSv2 default for new instances:")
    log.info("     aws ec2 modify-instance-metadata-defaults --http-tokens required")
    log.info("  3. Use SCP to deny ec2:RunInstances without IMDSv2:")
    log.info('     Condition: {"StringNotEquals": {"ec2:MetadataHttpTokens": "required"}}')
    log.info("  4. Enable GuardDuty for InstanceCredentialExfiltration detection")
    log.info("  5. Apply least-privilege to all instance roles")
    log.info("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CDET-007: EC2 IMDS security assessment — identifies IMDSv1 exposure (read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This is a READ-ONLY assessment script. It does NOT retrieve or use credentials.

Examples:
  python simulate.py
  python simulate.py --check-imds-local
  python simulate.py --enumerate-imdsv1
  python simulate.py --list-instance-profiles
  python simulate.py --remediation-report
        """,
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region to enumerate (default: us-east-1)",
    )
    parser.add_argument(
        "--check-imds-local",
        action="store_true",
        default=False,
        help="Check IMDS version on the local EC2 instance (must be run ON an EC2 instance)",
    )
    parser.add_argument(
        "--enumerate-imdsv1",
        action="store_true",
        default=False,
        help="Enumerate all EC2 instances with IMDSv1 enabled in the region",
    )
    parser.add_argument(
        "--list-instance-profiles",
        action="store_true",
        default=False,
        help="List IAM instance profiles and identify high-value targets",
    )
    parser.add_argument(
        "--remediation-report",
        action="store_true",
        default=False,
        help="Run full assessment and print remediation recommendations",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    log.info("CDET-007 EC2 IMDS Assessment — Read-Only Script")
    log.info("This script does NOT retrieve or use EC2 instance credentials")

    # Build boto3 session — no hardcoded credentials
    session = boto3.Session(region_name=args.region)
    ec2 = session.client("ec2")
    iam = session.client("iam")
    sts = session.client("sts")

    # Verify caller identity (generates a GetCallerIdentity event — always safe)
    try:
        identity = sts.get_caller_identity()
        log.info("Running as: %s (Account: %s)", identity["Arn"], identity["Account"])
    except ClientError as exc:
        log.error("Cannot determine caller identity: %s", exc)
        return 1

    # Local IMDS check only
    if args.check_imds_local:
        result = check_imdsv1_enabled()
        if result["on_ec2"]:
            if result["imdsv1_accessible"]:
                log.warning("FINDING: IMDSv1 is enabled — this instance is vulnerable")
                log.warning(
                    "Fix: aws ec2 modify-instance-metadata-options --instance-id %s --http-tokens required",
                    result.get("instance_id", "<instance-id>"),
                )
            else:
                log.info("IMDSv2 is enforced on this instance — not vulnerable")
        return 0

    # Enumerate IMDSv1 instances only
    if args.enumerate_imdsv1:
        vulnerable = enumerate_imdsv1_instances(ec2, args.region)
        if vulnerable:
            log.warning("Found %d instance(s) with IMDSv1 enabled:", len(vulnerable))
            for inst in vulnerable:
                log.warning("  %s (%s) | Role: %s", inst["instance_id"], inst["name"], inst["role_arn"])
        else:
            log.info("No instances with IMDSv1 enabled found in %s", args.region)
        return 0

    # List instance profiles only
    if args.list_instance_profiles:
        profiles = list_instance_profiles_with_permissions(iam)
        high_value = [p for p in profiles if p["is_high_value"]]
        log.info("Total instance profiles: %d | High-value: %d", len(profiles), len(high_value))
        for p in profiles:
            marker = "*** " if p["is_high_value"] else "    "
            log.info(
                "%s%s (Role: %s) — Policies: %s",
                marker,
                p["profile_name"],
                p["role_name"],
                ", ".join(p["privileged_policies"]) or "none with privileged keywords",
            )
        return 0

    # Full assessment (default or --remediation-report)
    imds_result = check_imdsv1_enabled()
    vulnerable_instances = enumerate_imdsv1_instances(ec2, args.region)
    profiles = list_instance_profiles_with_permissions(iam)
    print_remediation_report(imds_result, vulnerable_instances, profiles)

    return 0


if __name__ == "__main__":
    sys.exit(main())
