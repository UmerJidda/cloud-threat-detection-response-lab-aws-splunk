#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Use only in AWS accounts you own or have explicit
written permission to test. Unauthorized use against accounts you do not own
is illegal and unethical.

CDET-008 — Excessive API Enumeration Simulator
Tactic: Discovery | T1580

NOTE: This script is FULLY READ-ONLY. It only calls List/Describe/Get APIs
and never creates, modifies, or deletes any AWS resource. It is safe to run
with SecurityAudit or ReadOnlyAccess permissions.

IMPORTANT: Running this script WILL generate real CloudTrail events that
should trigger the CDET-008 detection rule (>=50 API calls, >=5 unique APIs
in 2 hours). This is intentional — the purpose is to generate test data for
your detection pipeline.

Unlike other CDET simulation scripts, this script does NOT require --execute
because all operations are read-only. The script always runs enumeration.

Usage:
    python simulate.py
    python simulate.py --profile my-test-profile
    python simulate.py --region us-west-2
    python simulate.py --output-json results.json
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet008")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class EnumerationResults:
    """Accumulates findings from all enumeration phases."""

    def __init__(self) -> None:
        self.api_call_count: int = 0
        self.unique_apis: set[str] = set()
        self.findings: dict[str, Any] = {
            "identity": {},
            "iam": {"users": [], "roles": [], "groups": []},
            "s3": {"buckets": []},
            "ec2": {
                "instances": [],
                "security_groups": [],
                "vpcs": [],
                "snapshots": [],
            },
            "lambda": {"functions": []},
            "rds": {"instances": [], "clusters": []},
            "other": {},
            "risk_findings": [],
        }

    def record_call(self, service: str, api: str) -> None:
        self.api_call_count += 1
        self.unique_apis.add(f"{service}:{api}")

    def add_risk(self, severity: str, resource: str, finding: str) -> None:
        self.findings["risk_findings"].append(
            {"severity": severity, "resource": resource, "finding": finding}
        )


def safe_call(results: EnumerationResults, service: str, api: str, func, **kwargs):
    """Call a boto3 API, record it, and handle errors gracefully."""
    results.record_call(service, api)
    try:
        return func(**kwargs)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "UnauthorizedAccess"):
            log.warning("[%s:%s] AccessDenied — insufficient permissions", service, api)
        else:
            log.warning("[%s:%s] ClientError: %s", service, api, code)
        return None
    except Exception as e:
        log.warning("[%s:%s] Unexpected error: %s", service, api, e)
        return None


# ---------------------------------------------------------------------------
# Enumeration phases
# ---------------------------------------------------------------------------
def enumerate_identity(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 1: Identity Confirmation ===")
    sts = session.client("sts")
    resp = safe_call(results, "sts", "GetCallerIdentity", sts.get_caller_identity)
    if resp:
        identity = {
            "account": resp.get("Account"),
            "user_id": resp.get("UserId"),
            "arn": resp.get("Arn"),
        }
        results.findings["identity"] = identity
        log.info("Account: %s | ARN: %s", identity["account"], identity["arn"])


def enumerate_iam(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 2: IAM Enumeration ===")
    iam = session.client("iam")

    # Users
    resp = safe_call(results, "iam", "ListUsers", iam.list_users)
    if resp:
        users = resp.get("Users", [])
        results.findings["iam"]["users"] = [u["UserName"] for u in users]
        log.info("IAM Users found: %d", len(users))
        for user in users:
            log.info("  User: %s (created %s)", user["UserName"], user.get("CreateDate", "unknown"))

    # Roles
    resp = safe_call(results, "iam", "ListRoles", iam.list_roles)
    if resp:
        roles = resp.get("Roles", [])
        results.findings["iam"]["roles"] = [r["RoleName"] for r in roles]
        log.info("IAM Roles found: %d", len(roles))
        for role in roles:
            # Flag cross-account trust relationships
            trust = json.dumps(role.get("AssumeRolePolicyDocument", {}))
            if '"AWS"' in trust and "arn:aws:iam::" in trust:
                log.warning(
                    "  [CROSS-ACCOUNT TRUST] Role: %s has cross-account trust policy",
                    role["RoleName"],
                )
                results.add_risk(
                    "MEDIUM",
                    f"iam:role/{role['RoleName']}",
                    "Role has cross-account trust relationship",
                )

    # Groups
    resp = safe_call(results, "iam", "ListGroups", iam.list_groups)
    if resp:
        groups = resp.get("Groups", [])
        results.findings["iam"]["groups"] = [g["GroupName"] for g in groups]
        log.info("IAM Groups found: %d", len(groups))

    # Account summary
    resp = safe_call(results, "iam", "GetAccountSummary", iam.get_account_summary)
    if resp:
        summary = resp.get("SummaryMap", {})
        log.info(
            "Account Summary — MFADevices: %d | AccountMFAEnabled: %s",
            summary.get("MFADevices", 0),
            bool(summary.get("AccountMFAEnabled", 0)),
        )
        if not summary.get("AccountMFAEnabled", 0):
            results.add_risk("HIGH", "iam:account", "Root MFA is NOT enabled")

    # Password policy
    safe_call(results, "iam", "GetAccountPasswordPolicy", iam.get_account_password_policy)


def enumerate_s3(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 3: S3 Enumeration ===")
    s3 = session.client("s3")

    resp = safe_call(results, "s3", "ListBuckets", s3.list_buckets)
    if not resp:
        return

    buckets = resp.get("Buckets", [])
    log.info("S3 Buckets found: %d", len(buckets))

    for bucket in buckets:
        name = bucket["Name"]
        bucket_info: dict[str, Any] = {"name": name}

        # Public access block
        resp_pab = safe_call(
            results, "s3", "GetBucketPublicAccessBlock",
            s3.get_bucket_public_access_block, Bucket=name
        )
        if resp_pab:
            pab = resp_pab.get("PublicAccessBlockConfiguration", {})
            all_blocked = all(pab.get(k, False) for k in [
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets"
            ])
            bucket_info["public_access_blocked"] = all_blocked
            if not all_blocked:
                log.warning("  [RISK] Bucket %s: Public access block NOT fully enabled", name)
                results.add_risk("HIGH", f"s3:{name}", "Public access block not fully enabled")
        else:
            log.warning("  [RISK] Bucket %s: Could not verify public access block", name)

        # Encryption
        resp_enc = safe_call(
            results, "s3", "GetBucketEncryption",
            s3.get_bucket_encryption, Bucket=name
        )
        if resp_enc:
            rules = resp_enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            bucket_info["encrypted"] = len(rules) > 0
        else:
            bucket_info["encrypted"] = False
            log.warning("  [RISK] Bucket %s: Encryption NOT configured", name)
            results.add_risk("MEDIUM", f"s3:{name}", "Default encryption not configured")

        # Versioning
        resp_ver = safe_call(
            results, "s3", "GetBucketVersioning",
            s3.get_bucket_versioning, Bucket=name
        )
        if resp_ver:
            status = resp_ver.get("Status", "Disabled")
            bucket_info["versioning"] = status
            if status != "Enabled":
                results.add_risk("LOW", f"s3:{name}", f"Versioning is {status} (ransomware risk)")

        results.findings["s3"]["buckets"].append(bucket_info)
        log.info(
            "  Bucket: %-40s | Public block: %-5s | Encrypted: %-5s | Versioning: %s",
            name,
            bucket_info.get("public_access_blocked", "?"),
            bucket_info.get("encrypted", "?"),
            bucket_info.get("versioning", "?"),
        )


def enumerate_ec2(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 4: EC2 and Networking Enumeration ===")
    ec2 = session.client("ec2")

    # Instances
    resp = safe_call(results, "ec2", "DescribeInstances", ec2.describe_instances)
    if resp:
        instance_count = sum(
            len(r["Instances"]) for r in resp.get("Reservations", [])
        )
        log.info("EC2 Instances: %d", instance_count)
        results.findings["ec2"]["instances"] = []
        for reservation in resp.get("Reservations", []):
            for inst in reservation["Instances"]:
                itype = inst.get("InstanceType", "unknown")
                state = inst.get("State", {}).get("Name", "unknown")
                iid = inst.get("InstanceId", "unknown")
                log.info("  Instance: %s | Type: %s | State: %s", iid, itype, state)
                results.findings["ec2"]["instances"].append(
                    {"id": iid, "type": itype, "state": state}
                )

    # Security Groups — look for 0.0.0.0/0 ingress
    resp = safe_call(results, "ec2", "DescribeSecurityGroups", ec2.describe_security_groups)
    if resp:
        sgs = resp.get("SecurityGroups", [])
        log.info("Security Groups: %d", len(sgs))
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = perm.get("FromPort", "all")
                        log.warning(
                            "  [RISK] SG %s (%s): Port %s open to 0.0.0.0/0",
                            sg["GroupId"], sg.get("GroupName", ""), port,
                        )
                        results.add_risk(
                            "HIGH",
                            f"ec2:sg/{sg['GroupId']}",
                            f"Port {port} open to 0.0.0.0/0",
                        )

    # VPCs
    resp = safe_call(results, "ec2", "DescribeVpcs", ec2.describe_vpcs)
    if resp:
        vpcs = resp.get("Vpcs", [])
        log.info("VPCs: %d", len(vpcs))

    # Snapshots
    resp = safe_call(
        results, "ec2", "DescribeSnapshots",
        ec2.describe_snapshots, OwnerIds=["self"]
    )
    if resp:
        snaps = resp.get("Snapshots", [])
        log.info("EBS Snapshots (owned): %d", len(snaps))
        for snap in snaps:
            if snap.get("Public", False):
                results.add_risk(
                    "CRITICAL",
                    f"ec2:snapshot/{snap['SnapshotId']}",
                    "Snapshot is PUBLICLY accessible",
                )

    # Key pairs
    safe_call(results, "ec2", "DescribeKeyPairs", ec2.describe_key_pairs)
    safe_call(results, "ec2", "DescribeAddresses", ec2.describe_addresses)


def enumerate_lambda(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 5: Lambda Enumeration ===")
    lam = session.client("lambda")

    resp = safe_call(results, "lambda", "ListFunctions", lam.list_functions)
    if not resp:
        return

    functions = resp.get("Functions", [])
    log.info("Lambda Functions: %d", len(functions))

    for fn in functions:
        fname = fn["FunctionName"]
        role = fn.get("Role", "unknown")
        env = fn.get("Environment", {}).get("Variables", {})

        results.findings["lambda"]["functions"].append(
            {"name": fname, "role": role, "env_var_count": len(env)}
        )
        log.info("  Function: %-40s | Role: %s", fname, role)

        if env:
            log.warning(
                "  [RISK] Function %s has %d environment variables (may contain secrets)",
                fname, len(env),
            )
            results.add_risk(
                "MEDIUM",
                f"lambda:{fname}",
                f"Function has {len(env)} env vars — review for embedded credentials",
            )

        # Get policy (resource-based policy)
        safe_call(
            results, "lambda", "GetPolicy",
            lam.get_policy, FunctionName=fname
        )


def enumerate_rds(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 6: RDS Enumeration ===")
    rds = session.client("rds")

    resp = safe_call(results, "rds", "DescribeDBInstances", rds.describe_db_instances)
    if resp:
        instances = resp.get("DBInstances", [])
        log.info("RDS Instances: %d", len(instances))
        for inst in instances:
            db_id = inst.get("DBInstanceIdentifier", "unknown")
            engine = inst.get("Engine", "unknown")
            publicly = inst.get("PubliclyAccessible", False)
            encrypted = inst.get("StorageEncrypted", False)

            log.info(
                "  RDS: %-30s | Engine: %-12s | Public: %-5s | Encrypted: %s",
                db_id, engine, publicly, encrypted,
            )

            if publicly:
                results.add_risk(
                    "HIGH",
                    f"rds:{db_id}",
                    "RDS instance is publicly accessible",
                )
            if not encrypted:
                results.add_risk(
                    "MEDIUM",
                    f"rds:{db_id}",
                    "RDS storage is NOT encrypted",
                )

    resp = safe_call(results, "rds", "DescribeDBClusters", rds.describe_db_clusters)
    if resp:
        clusters = resp.get("DBClusters", [])
        log.info("RDS Clusters (Aurora): %d", len(clusters))

    safe_call(results, "rds", "DescribeDBSnapshots", rds.describe_db_snapshots)


def enumerate_other_services(session: boto3.Session, results: EnumerationResults) -> None:
    log.info("=== Phase 7: Additional Service Enumeration ===")

    # CloudTrail
    ct = session.client("cloudtrail")
    resp = safe_call(results, "cloudtrail", "DescribeTrails", ct.describe_trails)
    if resp:
        trails = resp.get("trailList", [])
        log.info("CloudTrail Trails: %d", len(trails))
        for trail in trails:
            log.info("  Trail: %s | S3: %s", trail.get("Name"), trail.get("S3BucketName"))
            if not trail.get("LogFileValidationEnabled", False):
                results.add_risk(
                    "MEDIUM",
                    f"cloudtrail:{trail.get('Name')}",
                    "Log file validation is NOT enabled",
                )

    # KMS
    kms = session.client("kms")
    safe_call(results, "kms", "ListKeys", kms.list_keys)
    safe_call(results, "kms", "ListAliases", kms.list_aliases)

    # SSM Parameter Store
    ssm = session.client("ssm")
    resp = safe_call(results, "ssm", "DescribeParameters", ssm.describe_parameters)
    if resp:
        params = resp.get("Parameters", [])
        log.info("SSM Parameters: %d", len(params))
        for param in params:
            ptype = param.get("Type", "String")
            name = param.get("Name", "")
            if ptype == "SecureString":
                log.info("  SecureString param: %s", name)
            # Flag sensitive-sounding parameter names
            sensitive_keywords = ["password", "secret", "key", "token", "cred"]
            if any(kw in name.lower() for kw in sensitive_keywords):
                results.add_risk(
                    "INFO",
                    f"ssm:{name}",
                    f"Parameter name suggests sensitive data (type: {ptype})",
                )

    # Secrets Manager
    sm = session.client("secretsmanager")
    resp = safe_call(results, "secretsmanager", "ListSecrets", sm.list_secrets)
    if resp:
        secrets = resp.get("SecretList", [])
        log.info("Secrets Manager secrets: %d", len(secrets))
        for secret in secrets:
            log.info("  Secret: %s", secret.get("Name"))

    # SNS
    sns = session.client("sns")
    safe_call(results, "sns", "ListTopics", sns.list_topics)

    # SQS
    sqs = session.client("sqs")
    safe_call(results, "sqs", "ListQueues", sqs.list_queues)

    # EKS
    try:
        eks = session.client("eks")
        resp = safe_call(results, "eks", "ListClusters", eks.list_clusters)
        if resp:
            clusters = resp.get("clusters", [])
            log.info("EKS Clusters: %d", len(clusters))
    except Exception:
        pass

    # ECS
    try:
        ecs = session.client("ecs")
        resp = safe_call(results, "ecs", "ListClusters", ecs.list_clusters)
        if resp:
            arns = resp.get("clusterArns", [])
            log.info("ECS Clusters: %d", len(arns))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(results: EnumerationResults, output_json: str | None) -> None:
    log.info("=" * 60)
    log.info("ENUMERATION COMPLETE")
    log.info("=" * 60)
    log.info("Total API calls made: %d", results.api_call_count)
    log.info("Unique APIs called:   %d", len(results.unique_apis))
    log.info("Risk findings:        %d", len(results.findings["risk_findings"]))

    print("\n" + "=" * 60)
    print("CDET-008 TRIGGER ASSESSMENT")
    print("=" * 60)
    threshold_calls = results.api_call_count >= 50
    threshold_apis = len(results.unique_apis) >= 5
    print(f"  API calls >= 50:       {'YES ✓' if threshold_calls else 'NO  ✗'} ({results.api_call_count})")
    print(f"  Unique APIs >= 5:      {'YES ✓' if threshold_apis else 'NO  ✗'} ({len(results.unique_apis)})")
    print(f"  Detection expected:    {'YES — CDET-008 should fire' if (threshold_calls and threshold_apis) else 'NO'}")

    if results.findings["risk_findings"]:
        print("\nRISK FINDINGS:")
        by_sev: dict[str, list] = {}
        for f in results.findings["risk_findings"]:
            by_sev.setdefault(f["severity"], []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in by_sev:
                print(f"\n  [{sev}]")
                for finding in by_sev[sev]:
                    print(f"    {finding['resource']}: {finding['finding']}")

    if output_json:
        results.findings["metadata"] = {
            "script": "CDET-008",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "api_call_count": results.api_call_count,
            "unique_api_count": len(results.unique_apis),
            "apis_called": sorted(results.unique_apis),
        }
        with open(output_json, "w") as f:
            json.dump(results.findings, f, indent=2, default=str)
        log.info("Results written to: %s", output_json)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-008: Excessive API Enumeration Simulator (Read-Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
NOTE: This script is entirely read-only. It will always run enumeration.
      No --execute flag is required because no resources are created or modified.

      Running this script WILL generate CloudTrail events that should trigger
      the CDET-008 detection rule in your SIEM.
        """,
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile name (from ~/.aws/credentials). Default: boto3 default chain.",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to enumerate. Default: us-east-1",
    )
    parser.add_argument(
        "--output-json",
        metavar="FILE",
        default=None,
        help="Write findings to a JSON file.",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("CDET-008 — Excessive API Enumeration Simulator")
    print("Tactic: Discovery | MITRE T1580")
    print("Mode: READ-ONLY (always active — no --execute needed)")
    print("=" * 60)
    print()
    print("IMPORTANT: This script will generate real CloudTrail events.")
    print("           Run only in authorized test accounts.")
    print("           Expected to trigger CDET-008 detection rule.")
    print()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        log.error("Failed to create boto3 session: %s", e)
        sys.exit(1)

    # Verify credentials before starting
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        log.info(
            "Authenticated as: %s (Account: %s)",
            identity["Arn"],
            identity["Account"],
        )
    except NoCredentialsError:
        log.error("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)
    except ClientError as e:
        log.error("Authentication failed: %s", e)
        sys.exit(1)

    results = EnumerationResults()

    # Run all enumeration phases
    enumerate_identity(session, results)
    enumerate_iam(session, results)
    enumerate_s3(session, results)
    enumerate_ec2(session, results)
    enumerate_lambda(session, results)
    enumerate_rds(session, results)
    enumerate_other_services(session, results)

    print_summary(results, args.output_json)


if __name__ == "__main__":
    main()
