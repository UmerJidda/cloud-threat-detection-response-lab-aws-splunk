#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Use only in AWS accounts you own or have explicit
written permission to test. In execute mode with --confirm, this script
PERMANENTLY DELETES S3 objects. Deleted objects from unversioned buckets
CANNOT be recovered. Only run against dedicated test buckets with no real data.

CDET-010 — Mass S3 Object Deletion Simulator
Tactic: Impact | T1485

Dry-run (default): Calls list_objects_v2 to count and list objects that
WOULD be deleted. No deletion occurs.

Execute mode (--execute --confirm): Deletes objects from the specified test
bucket. Requires BOTH --execute AND --confirm flags as a safety mechanism.

Usage:
    # Dry-run — count objects that would be deleted
    python simulate.py --bucket my-test-bucket

    # Execute — delete objects (REQUIRES BOTH FLAGS — IRREVERSIBLE)
    python simulate.py --bucket my-test-bucket --execute --confirm

    # Assess bucket protections only (read-only)
    python simulate.py --bucket my-test-bucket --assess-only
"""

import argparse
import logging
import sys
from typing import Generator

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet010")

BATCH_SIZE = 1000  # S3 DeleteObjects maximum per call


def list_all_objects(s3_client, bucket: str) -> Generator[dict, None, None]:
    """Paginate through all objects in a bucket."""
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            yield obj


def assess_bucket_protections(s3_client, bucket: str) -> dict:
    """Check protective controls and report vulnerability status."""
    assessment = {
        "versioning": "unknown",
        "object_lock": "disabled",
        "mfa_delete": "unknown",
        "public_access_blocked": "unknown",
        "vulnerable_to_permanent_deletion": True,
    }

    # Check versioning and MFA delete
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket)
        versioning_status = resp.get("Status", "Disabled")
        mfa_delete = resp.get("MFADelete", "Disabled")
        assessment["versioning"] = versioning_status
        assessment["mfa_delete"] = mfa_delete
    except ClientError as e:
        log.warning("Could not check versioning: %s", e.response["Error"]["Code"])

    # Check Object Lock
    try:
        resp = s3_client.get_object_lock_configuration(Bucket=bucket)
        lock_config = resp.get("ObjectLockConfiguration", {})
        lock_enabled = lock_config.get("ObjectLockEnabled", "Disabled")
        assessment["object_lock"] = lock_enabled
        default_retention = lock_config.get("Rule", {}).get("DefaultRetention", {})
        if default_retention:
            assessment["default_retention"] = default_retention
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"):
            assessment["object_lock"] = "disabled"
        else:
            log.warning("Could not check Object Lock: %s", code)

    # Determine overall vulnerability
    versioning_enabled = assessment["versioning"] == "Enabled"
    mfa_delete_enabled = assessment["mfa_delete"] == "Enabled"
    object_lock_enabled = assessment["object_lock"] == "Enabled"

    if object_lock_enabled:
        assessment["vulnerable_to_permanent_deletion"] = False
        assessment["protection_level"] = "STRONG (Object Lock enabled)"
    elif versioning_enabled and mfa_delete_enabled:
        assessment["vulnerable_to_permanent_deletion"] = False
        assessment["protection_level"] = "STRONG (Versioning + MFA Delete)"
    elif versioning_enabled:
        assessment["vulnerable_to_permanent_deletion"] = True  # Versioning can be bypassed
        assessment["protection_level"] = "PARTIAL (Versioning only — can be bypassed with version IDs)"
    else:
        assessment["vulnerable_to_permanent_deletion"] = True
        assessment["protection_level"] = "NONE — any deletion is permanent"

    return assessment


def print_assessment(bucket: str, assessment: dict) -> None:
    print()
    print("=" * 60)
    print(f"BUCKET PROTECTION ASSESSMENT: {bucket}")
    print("=" * 60)
    print(f"  Versioning:                  {assessment['versioning']}")
    print(f"  MFA Delete:                  {assessment['mfa_delete']}")
    print(f"  Object Lock:                 {assessment['object_lock']}")
    if "default_retention" in assessment:
        print(f"  Default Retention:           {assessment['default_retention']}")
    print()
    protection = assessment.get("protection_level", "unknown")
    vulnerable = assessment["vulnerable_to_permanent_deletion"]
    if vulnerable:
        print(f"  [VULNERABLE] Protection: {protection}")
        print()
        print("  Recommendation: Enable S3 Object Lock (Compliance mode) for")
        print("  critical data buckets. At minimum enable versioning.")
    else:
        print(f"  [PROTECTED] Protection: {protection}")
    print()


def dry_run(s3_client, bucket: str) -> int:
    """List objects that would be deleted and return count."""
    print()
    print("=" * 60)
    print(f"CDET-010 DRY-RUN — Objects that WOULD be deleted from: {bucket}")
    print("=" * 60)

    count = 0
    sample_keys = []

    for obj in list_all_objects(s3_client, bucket):
        count += 1
        if len(sample_keys) < 20:
            sample_keys.append(obj["Key"])

    if count == 0:
        log.info("Bucket %s is empty — no objects to delete", bucket)
        return 0

    print(f"\nTotal objects found: {count}")
    print(f"Batches required (1000/call): {(count + BATCH_SIZE - 1) // BATCH_SIZE}")
    print()
    print("Sample of objects that WOULD be deleted (first 20):")
    for key in sample_keys:
        print(f"  - {key}")
    if count > 20:
        print(f"  ... and {count - 20} more objects")

    print()
    print(f"[DRY-RUN] No objects deleted. Add --execute --confirm to actually delete.")
    print(f"[WARNING] This operation would be IRREVERSIBLE without versioning.")
    return count


def execute_deletion(s3_client, bucket: str) -> None:
    """Execute batch deletion of all objects in bucket."""
    log.info("Starting batch deletion from bucket: %s", bucket)

    batch: list[dict] = []
    total_deleted = 0
    total_errors = 0
    batch_num = 0

    for obj in list_all_objects(s3_client, bucket):
        batch.append({"Key": obj["Key"]})

        if len(batch) == BATCH_SIZE:
            batch_num += 1
            deleted, errors = _delete_batch(s3_client, bucket, batch, batch_num)
            total_deleted += deleted
            total_errors += errors
            batch.clear()

    # Delete remaining objects
    if batch:
        batch_num += 1
        deleted, errors = _delete_batch(s3_client, bucket, batch, batch_num)
        total_deleted += deleted
        total_errors += errors

    print()
    log.info("Deletion complete: %d deleted, %d errors", total_deleted, total_errors)
    log.info("CloudTrail events generated: %d DeleteObjects events", batch_num)
    log.info("CDET-010 detection should fire on this activity")

    if total_errors > 0:
        log.warning("%d objects could not be deleted (check permissions)", total_errors)


def _delete_batch(
    s3_client, bucket: str, batch: list[dict], batch_num: int
) -> tuple[int, int]:
    """Execute a single DeleteObjects call for up to 1000 objects."""
    try:
        resp = s3_client.delete_objects(
            Bucket=bucket,
            Delete={"Objects": batch, "Quiet": False},
        )
        deleted = len(resp.get("Deleted", []))
        errors = len(resp.get("Errors", []))
        log.info("Batch %d: deleted %d objects, %d errors", batch_num, deleted, errors)
        for err in resp.get("Errors", []):
            log.warning(
                "  Error deleting %s: %s — %s",
                err.get("Key"), err.get("Code"), err.get("Message"),
            )
        return deleted, errors
    except ClientError as e:
        log.error("DeleteObjects batch %d failed: %s", batch_num, e.response["Error"]["Code"])
        return 0, len(batch)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-010: Mass S3 Object Deletion Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--bucket",
        required=True,
        help="S3 bucket name to target (MUST be a dedicated test bucket with no real data)",
    )
    parser.add_argument(
        "--assess-only",
        action="store_true",
        help="Only check bucket protections (versioning, Object Lock). Read-only.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Enable execution mode (MUST also provide --confirm).",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm you understand deletion is PERMANENT and IRREVERSIBLE. "
             "Required together with --execute.",
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
    print("CDET-010 — Mass S3 Object Deletion Simulator")
    print("Tactic: Impact | MITRE T1485")
    if args.execute and args.confirm:
        print("Mode: EXECUTE — OBJECTS WILL BE PERMANENTLY DELETED")
    elif args.assess_only:
        print("Mode: ASSESS ONLY (read-only)")
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
        log.info("Authenticated as: %s (Account: %s)", identity["Arn"], identity["Account"])
    except NoCredentialsError:
        log.error("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)

    s3 = session.client("s3")

    # Verify bucket exists
    try:
        s3.head_bucket(Bucket=args.bucket)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchBucket"):
            log.error("Bucket does not exist: %s", args.bucket)
        else:
            log.error("Cannot access bucket %s: %s", args.bucket, code)
        sys.exit(1)

    # Always show protection assessment
    assessment = assess_bucket_protections(s3, args.bucket)
    print_assessment(args.bucket, assessment)

    if args.assess_only:
        return

    if args.execute and args.confirm:
        print("=" * 60)
        print("DATA LOSS WARNING")
        print("=" * 60)
        print(f"About to PERMANENTLY DELETE all objects in: {args.bucket}")
        print(f"Protection level: {assessment.get('protection_level', 'unknown')}")
        if assessment["vulnerable_to_permanent_deletion"]:
            print("This bucket HAS NO EFFECTIVE PROTECTION against permanent deletion.")
            print("Deleted objects CANNOT be recovered.")
        print()

        # Final safety check — require typing bucket name to confirm
        confirm_name = input(f"Type the bucket name to confirm deletion: ")
        if confirm_name != args.bucket:
            log.error("Bucket name mismatch. Aborting.")
            sys.exit(1)

        execute_deletion(s3, args.bucket)

    elif args.execute and not args.confirm:
        log.error("--execute requires --confirm flag. This prevents accidental data destruction.")
        log.error("Add --confirm only if you are absolutely sure this is a test bucket with no real data.")
        sys.exit(1)
    else:
        dry_run(s3, args.bucket)


if __name__ == "__main__":
    main()
