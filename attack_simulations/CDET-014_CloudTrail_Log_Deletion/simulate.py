#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. This script is PURELY READ-ONLY and does NOT
delete any CloudTrail logs. It is a protective control assessment tool that
evaluates whether CloudTrail logs are adequately protected against deletion
attacks. It reports vulnerabilities to help organizations improve their
CloudTrail log protection posture.

CDET-014 — CloudTrail Log File Deleted from S3 — Protective Control Assessment
Tactic: Defense Evasion | T1070.004

This script:
- Discovers all CloudTrail trails and their S3 log buckets
- Checks each bucket for S3 Object Lock (Compliance mode recommended)
- Checks for versioning and MFA Delete configuration
- Checks for restrictive bucket policies (deny DeleteObject)
- Checks if S3 data events are enabled (required to detect CDET-014)
- Checks if cross-account log delivery is configured
- Reports an overall vulnerability score for each trail/bucket

Does NOT delete anything — this is a defensive assessment tool.

Usage:
    python simulate.py
    python simulate.py --profile my-security-profile
    python simulate.py --region us-west-2
    python simulate.py --output-json assessment.json
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet014")


# ---------------------------------------------------------------------------
# Control check functions
# ---------------------------------------------------------------------------
def check_object_lock(s3_client, bucket: str) -> dict:
    """Check S3 Object Lock configuration."""
    result: dict[str, Any] = {
        "enabled": False,
        "mode": None,
        "default_retention_days": None,
        "finding": "Object Lock NOT configured — permanent deletion is possible",
        "severity": "CRITICAL",
        "pass": False,
    }

    try:
        resp = s3_client.get_object_lock_configuration(Bucket=bucket)
        config = resp.get("ObjectLockConfiguration", {})
        if config.get("ObjectLockEnabled") == "Enabled":
            result["enabled"] = True
            rule = config.get("Rule", {})
            retention = rule.get("DefaultRetention", {})
            mode = retention.get("Mode")
            days = retention.get("Days") or retention.get("Years", 0) * 365

            result["mode"] = mode
            result["default_retention_days"] = days

            if mode == "COMPLIANCE":
                result["finding"] = f"Object Lock COMPLIANCE mode — immutable for {days} days"
                result["severity"] = "PASS"
                result["pass"] = True
            elif mode == "GOVERNANCE":
                result["finding"] = "Object Lock GOVERNANCE mode — can be bypassed with s3:BypassGovernanceRetention"
                result["severity"] = "MEDIUM"
                result["pass"] = False
            else:
                result["finding"] = (
                    "Object Lock enabled but no default retention rule — individual objects may lack protection"
                )
                result["severity"] = "HIGH"
        # else: ObjectLockEnabled = Disabled or absent

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"):
            pass  # Default result already captures this
        elif code == "AccessDenied":
            result["finding"] = "Could not check Object Lock — AccessDenied"
            result["severity"] = "UNKNOWN"
        else:
            result["finding"] = f"Error checking Object Lock: {code}"
            result["severity"] = "UNKNOWN"

    return result


def check_versioning(s3_client, bucket: str) -> dict:
    """Check S3 versioning and MFA Delete."""
    result: dict[str, Any] = {
        "versioning_status": "Disabled",
        "mfa_delete": "Disabled",
        "finding": "Versioning NOT enabled — deletions are permanent",
        "severity": "HIGH",
        "pass": False,
    }

    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket)
        status = resp.get("Status", "Disabled")
        mfa_delete = resp.get("MFADelete", "Disabled")

        result["versioning_status"] = status
        result["mfa_delete"] = mfa_delete

        if status == "Enabled" and mfa_delete == "Enabled":
            result["finding"] = "Versioning + MFA Delete enabled — strong protection"
            result["severity"] = "PASS"
            result["pass"] = True
        elif status == "Enabled":
            result["finding"] = (
                "Versioning enabled but MFA Delete is disabled — "
                "versioned deletions (with VersionId) can bypass versioning protection"
            )
            result["severity"] = "MEDIUM"
            result["pass"] = False
        elif status == "Suspended":
            result["finding"] = "Versioning is SUSPENDED — new objects are not versioned"
            result["severity"] = "HIGH"

    except ClientError as e:
        code = e.response["Error"]["Code"]
        result["finding"] = f"Error checking versioning: {code}"
        result["severity"] = "UNKNOWN"

    return result


def check_bucket_policy_for_delete_deny(s3_client, bucket: str) -> dict:
    """Check if the bucket policy has an explicit deny on DeleteObject."""
    result: dict[str, Any] = {
        "has_policy": False,
        "has_delete_deny": False,
        "finding": "No bucket policy — no explicit deny on DeleteObject",
        "severity": "HIGH",
        "pass": False,
    }

    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket)
        policy_str = resp.get("Policy", "{}")
        policy = json.loads(policy_str)
        result["has_policy"] = True

        # Look for explicit Deny on s3:DeleteObject or s3:DeleteObjectVersion
        statements = policy.get("Statement", [])
        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Check if any deny statement covers DeleteObject
            delete_actions = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:*", "s3:Delete*"]
            has_deny = effect == "Deny" and any(a in delete_actions for a in actions)

            if has_deny:
                # Verify it's not conditioned in a way that allows bypass
                conditions = stmt.get("Condition", {})
                result["has_delete_deny"] = True
                result["finding"] = "Bucket policy has explicit Deny on delete operations"
                result["severity"] = "PASS"
                result["pass"] = True
                if conditions:
                    result["finding"] += f" (with conditions: {list(conditions.keys())})"
                break

        if not result["has_delete_deny"]:
            result["finding"] = "Bucket policy exists but NO explicit Deny on DeleteObject"
            result["severity"] = "MEDIUM"

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchBucketPolicy":
            pass  # Default result
        elif code == "AccessDenied":
            result["finding"] = "Could not check bucket policy — AccessDenied"
            result["severity"] = "UNKNOWN"
        else:
            result["finding"] = f"Error checking bucket policy: {code}"
            result["severity"] = "UNKNOWN"

    return result


def check_s3_data_events(ct_client, trail_arn: str) -> dict:
    """Check if S3 data events are enabled for the CloudTrail trail."""
    result: dict[str, Any] = {
        "data_events_enabled": False,
        "covers_all_s3": False,
        "finding": "S3 data events NOT enabled — DeleteObject events will NOT be recorded",
        "severity": "HIGH",
        "pass": False,
    }

    try:
        resp = ct_client.get_event_selectors(TrailName=trail_arn)

        # Check classic event selectors
        for selector in resp.get("EventSelectors", []):
            for data_resource in selector.get("DataResources", []):
                if data_resource.get("Type") == "AWS::S3::Object":
                    values = data_resource.get("Values", [])
                    result["data_events_enabled"] = True
                    if "arn:aws:s3" in str(values) and "" in str(values):
                        # Covers all S3
                        result["covers_all_s3"] = True
                        rw_type = selector.get("ReadWriteType", "All")
                        result["finding"] = f"S3 data events enabled for all buckets (ReadWriteType: {rw_type})"
                        result["severity"] = "PASS"
                        result["pass"] = True
                    else:
                        result["finding"] = f"S3 data events enabled but only for specific buckets: {values}"
                        result["severity"] = "MEDIUM"

        # Check advanced event selectors
        for adv_selector in resp.get("AdvancedEventSelectors", []):
            for field_selector in adv_selector.get("FieldSelectors", []):
                if field_selector.get("Field") == "resources.type" and "AWS::S3::Object" in field_selector.get(
                    "Equals", []
                ):
                    result["data_events_enabled"] = True
                    result["covers_all_s3"] = True
                    result["finding"] = "S3 data events enabled (advanced event selectors)"
                    result["severity"] = "PASS"
                    result["pass"] = True

    except ClientError as e:
        code = e.response["Error"]["Code"]
        result["finding"] = f"Could not check event selectors: {code}"
        result["severity"] = "UNKNOWN"

    return result


def check_cross_account_delivery(ct_client, trail: dict, account_id: str) -> dict:
    """Check if logs are delivered to a different account (resilient architecture)."""
    # Extract bucket owner account from the trail's S3BucketName context
    # We can infer cross-account if trail is from an org-level trail
    is_org_trail = trail.get("IsOrganizationTrail", False)
    has_log_file_validation = trail.get("LogFileValidationEnabled", False)

    result: dict[str, Any] = {
        "is_org_trail": is_org_trail,
        "log_file_validation": has_log_file_validation,
        "finding": "Single-account log delivery — a compromised account can delete its own logs",
        "severity": "MEDIUM",
        "pass": False,
    }

    if is_org_trail:
        result["finding"] = "Organization trail — logs span all org accounts"
        result["severity"] = "INFO"

    if has_log_file_validation:
        result["log_validation_note"] = (
            "Log file validation enabled — tampering with existing logs is detectable "
            "via digest chain verification even if files are deleted"
        )

    return result


def assess_trail(
    session: boto3.Session,
    trail: dict,
    account_id: str,
) -> dict:
    """Run all control checks for a single CloudTrail trail."""
    trail_name = trail.get("Name", "unknown")
    bucket = trail.get("S3BucketName", "")
    trail_arn = trail.get("TrailARN", "")

    log.info("Assessing trail: %s (bucket: %s)", trail_name, bucket)

    s3 = session.client("s3")
    ct = session.client("cloudtrail")

    assessment = {
        "trail_name": trail_name,
        "trail_arn": trail_arn,
        "bucket": bucket,
        "multi_region": trail.get("IsMultiRegionTrail", False),
        "controls": {},
        "overall_risk": "UNKNOWN",
        "vulnerable_to_deletion": True,
    }

    if not bucket:
        assessment["overall_risk"] = "UNKNOWN"
        log.warning("Trail %s has no S3 bucket configured", trail_name)
        return assessment

    # Run all checks
    assessment["controls"]["object_lock"] = check_object_lock(s3, bucket)
    assessment["controls"]["versioning"] = check_versioning(s3, bucket)
    assessment["controls"]["bucket_policy_deny"] = check_bucket_policy_for_delete_deny(s3, bucket)
    assessment["controls"]["s3_data_events"] = check_s3_data_events(ct, trail_arn)
    assessment["controls"]["cross_account"] = check_cross_account_delivery(ct, trail, account_id)

    # Determine overall risk
    controls = assessment["controls"]
    if controls["object_lock"].get("pass") and controls["object_lock"].get("mode") == "COMPLIANCE":
        assessment["overall_risk"] = "LOW"
        assessment["vulnerable_to_deletion"] = False
        assessment["summary"] = "PROTECTED: S3 Object Lock Compliance mode prevents all deletion"
    elif controls["object_lock"].get("pass") or (
        controls["versioning"].get("pass") and controls["bucket_policy_deny"].get("pass")
    ):
        assessment["overall_risk"] = "MEDIUM"
        assessment["vulnerable_to_deletion"] = False
        assessment["summary"] = "PARTIALLY PROTECTED: Some deletion controls present, but not fully hardened"
    else:
        assessment["overall_risk"] = "HIGH"
        assessment["vulnerable_to_deletion"] = True
        assessment["summary"] = "VULNERABLE: Insufficient controls — logs can be permanently deleted"

    return assessment


def print_trail_assessment(assessment: dict) -> None:
    """Print formatted trail assessment."""
    risk_icons = {"LOW": "[PROTECTED]", "MEDIUM": "[PARTIAL]", "HIGH": "[VULNERABLE]", "UNKNOWN": "[UNKNOWN]"}
    icon = risk_icons.get(assessment.get("overall_risk", "UNKNOWN"), "[?]")

    print()
    print(f"Trail: {assessment['trail_name']}")
    print(f"  Bucket: {assessment['bucket']}")
    print(f"  Risk:   {icon} {assessment.get('overall_risk')} — {assessment.get('summary', '')}")
    print()

    controls = assessment.get("controls", {})
    check_labels = {
        "object_lock": "S3 Object Lock",
        "versioning": "Versioning + MFA Delete",
        "bucket_policy_deny": "Bucket Policy Deny",
        "s3_data_events": "S3 Data Events (CDET-014 detection)",
        "cross_account": "Cross-Account Delivery",
    }

    for key, label in check_labels.items():
        if key not in controls:
            continue
        ctrl = controls[key]
        sev = ctrl.get("severity", "UNKNOWN")
        finding = ctrl.get("finding", "")
        status = "PASS" if ctrl.get("pass") else sev
        print(f"  [{status:<8}] {label}: {finding}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-014: CloudTrail Log Deletion — Protective Control Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script performs a READ-ONLY assessment of CloudTrail log bucket protections.
It does NOT delete any log files. It reports whether the organization is vulnerable
to CDET-014 (CloudTrail log deletion) and identifies specific control gaps.
        """,
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
    parser.add_argument(
        "--output-json",
        metavar="FILE",
        default=None,
        help="Write full assessment results to a JSON file.",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("CDET-014 — CloudTrail Log Deletion Protective Assessment")
    print("Tactic: Defense Evasion | MITRE T1070.004")
    print("Mode: READ-ONLY (assessment only — no deletions)")
    print("=" * 60)
    print()
    print("This script assesses whether CloudTrail logs are protected")
    print("against deletion attacks. It does NOT delete any log files.")
    print()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        log.error("Failed to create boto3 session: %s", e)
        sys.exit(1)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        log.info("Authenticated as: %s (Account: %s)", identity["Arn"], account_id)
    except NoCredentialsError:
        log.error("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)

    # Discover all trails
    ct = session.client("cloudtrail")
    try:
        resp = ct.describe_trails(includeShadowTrails=True)
        trails = resp.get("trailList", [])
        log.info("Found %d CloudTrail trail(s)", len(trails))
    except ClientError as e:
        log.error("Could not describe CloudTrail trails: %s", e.response["Error"]["Code"])
        sys.exit(1)

    if not trails:
        print()
        print("[CRITICAL] No CloudTrail trails found!")
        print("CloudTrail is NOT enabled in this account/region.")
        print("This account has no audit logging — not just a deletion risk, but no logging at all.")
        sys.exit(0)

    # Assess each trail
    all_assessments = []
    for trail in trails:
        # Only assess trails in the home region (avoid duplicate assessments for multi-region trails)
        home_region = trail.get("HomeRegion", args.region)
        if home_region != args.region and not trail.get("IsMultiRegionTrail", False):
            log.debug("Skipping trail %s — home region is %s", trail.get("Name"), home_region)
            continue

        assessment = assess_trail(session, trail, account_id)
        all_assessments.append(assessment)

    # Print results
    print()
    print("=" * 60)
    print("ASSESSMENT RESULTS")
    print("=" * 60)

    for assessment in all_assessments:
        print_trail_assessment(assessment)

    # Overall summary
    vulnerable_trails = [a for a in all_assessments if a.get("vulnerable_to_deletion")]
    s3_data_events_missing = [
        a for a in all_assessments if not a.get("controls", {}).get("s3_data_events", {}).get("pass", False)
    ]

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Trails assessed:                    {len(all_assessments)}")
    print(f"Trails vulnerable to log deletion:  {len(vulnerable_trails)}")
    print(f"Trails missing S3 data events:      {len(s3_data_events_missing)}")
    print()

    if vulnerable_trails:
        print("[ACTION REQUIRED] Vulnerable trails found. Recommended remediation:")
        print()
        print("  1. Enable S3 Object Lock in COMPLIANCE mode on the log bucket")
        print("     (requires bucket recreation — Object Lock cannot be added after creation)")
        print("  2. If Object Lock is not possible, enable versioning + add bucket policy")
        print("     explicit Deny on s3:DeleteObject from all principals")
        print("  3. Deliver logs to a separate security account (cross-account architecture)")
        print("  4. Enable S3 data events on the CloudTrail trail to detect CDET-014")
        print()
        print("  AWS CLI to enable S3 data events:")
        print("    aws cloudtrail put-event-selectors \\")
        print("      --trail-name <trail-name> \\")
        print("      --event-selectors '[{")
        print('        "ReadWriteType": "WriteOnly",')
        print('        "IncludeManagementEvents": true,')
        print('        "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]}]')
        print("      }]'")
    else:
        print("[PROTECTED] All trails have adequate deletion protection.")

    if s3_data_events_missing:
        print()
        print("[WARNING] S3 data events not enabled on some trails.")
        print("  Without S3 data events, DeleteObject events for CloudTrail log files")
        print("  will NOT appear in CloudTrail — CDET-014 detection will not fire.")

    # Save JSON results
    if args.output_json:
        output = {
            "assessment_timestamp": datetime.utcnow().isoformat() + "Z",
            "account_id": account_id,
            "region": args.region,
            "script": "CDET-014",
            "trails": all_assessments,
            "vulnerable_count": len(vulnerable_trails),
            "missing_data_events_count": len(s3_data_events_missing),
        }
        with open(args.output_json, "w") as f:
            json.dump(output, f, indent=2, default=str)
        log.info("Assessment results written to: %s", args.output_json)


if __name__ == "__main__":
    main()
