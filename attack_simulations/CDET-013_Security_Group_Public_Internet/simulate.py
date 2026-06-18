#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Use only in AWS accounts you own or have explicit
written permission to test. In execute mode, this script temporarily opens a
security group rule to 0.0.0.0/0 and immediately revokes it. Even temporary
exposure to 0.0.0.0/0 creates real network risk if applied to a security
group attached to a running instance. Only use dedicated test security groups
with no attached instances.

CDET-013 — Security Group Opened to Public Internet Simulator
Tactic: Defense Evasion | T1562.007

Dry-run (default): Prints what rule would be added to the security group.
Also performs a read-only assessment of all existing overly-permissive SG rules.

Execute mode (--execute): Adds the specified ingress rule (default port 22,
0.0.0.0/0) to the specified security group, then immediately revokes it.
Generates AuthorizeSecurityGroupIngress + RevokeSecurityGroupIngress events.

Usage:
    # Dry-run — show what would be added and assess existing permissive rules
    python simulate.py

    # Execute — add and immediately revoke a rule on a test SG
    python simulate.py --execute --security-group-id sg-0example123

    # Execute with a different port
    python simulate.py --execute --security-group-id sg-0example123 --port 3389

    # Read-only assessment of existing overly-permissive rules
    python simulate.py --assess
"""

import argparse
import logging
import sys
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet013")

HIGH_RISK_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    4444: "Metasploit default",
}


def assess_permissive_rules(session: boto3.Session) -> list[dict]:
    """
    Read-only: find all security groups with 0.0.0.0/0 or ::/0 ingress rules.
    Generates DescribeSecurityGroups CloudTrail events.
    """
    ec2 = session.client("ec2")
    findings = []

    try:
        # Search for security groups with 0.0.0.0/0 rules
        resp = ec2.describe_security_groups(
            Filters=[{"Name": "ip-permission.cidr", "Values": ["0.0.0.0/0"]}]
        )
        for sg in resp.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 65535)
                        protocol = perm.get("IpProtocol", "-1")

                        service = "All traffic" if protocol == "-1" else \
                                  HIGH_RISK_PORTS.get(from_port, f"port {from_port}")

                        severity = "CRITICAL" if (
                            protocol == "-1" or
                            from_port in (22, 3389) or
                            from_port == 0
                        ) else "HIGH"

                        finding = {
                            "sg_id": sg["GroupId"],
                            "sg_name": sg.get("GroupName", ""),
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": "0.0.0.0/0",
                            "service": service,
                            "severity": severity,
                            "description": ip_range.get("Description", ""),
                        }
                        findings.append(finding)

        # Also search for ::/0 (IPv6)
        resp6 = ec2.describe_security_groups(
            Filters=[{"Name": "ip-permission.ipv6-cidr", "Values": ["::/0"]}]
        )
        for sg in resp6.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for ipv6_range in perm.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 65535)
                        protocol = perm.get("IpProtocol", "-1")
                        service = HIGH_RISK_PORTS.get(from_port, f"port {from_port}")

                        findings.append({
                            "sg_id": sg["GroupId"],
                            "sg_name": sg.get("GroupName", ""),
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": "::/0",
                            "service": service,
                            "severity": "HIGH",
                            "description": ipv6_range.get("Description", ""),
                        })

    except ClientError as e:
        log.warning("Could not describe security groups: %s", e.response["Error"]["Code"])

    return findings


def print_assessment(findings: list[dict]) -> None:
    """Print assessment results in a readable format."""
    print()
    print("=" * 60)
    print("OVERLY PERMISSIVE SECURITY GROUP ASSESSMENT")
    print("=" * 60)

    if not findings:
        print("\nNo security groups found with 0.0.0.0/0 or ::/0 ingress rules.")
        print("This account has no globally exposed security groups.")
        return

    print(f"\nFound {len(findings)} overly-permissive rule(s):\n")

    by_severity: dict[str, list[dict]] = {}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        if sev in by_severity:
            print(f"[{sev}]")
            for f in by_severity[sev]:
                print(f"  SG: {f['sg_id']:<20} Name: {f['sg_name']}")
                print(
                    f"    Protocol: {f['protocol']:<6} "
                    f"Port: {f['from_port']}-{f['to_port']:<6} "
                    f"CIDR: {f['cidr']:<20} "
                    f"Service: {f['service']}"
                )
                if f["description"]:
                    print(f"    Description: {f['description']}")
            print()

    print("Remediation: Review each finding and apply least-privilege CIDRs.")
    print("Replace 0.0.0.0/0 with specific IP ranges or remove the rule entirely.")


def get_or_create_test_sg(ec2_client, vpc_id: str) -> str:
    """Get an existing test SG or create a new one."""
    try:
        # Check for existing test SG
        resp = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "tag:Purpose", "Values": ["CDET-013-security-test"]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        if resp["SecurityGroups"]:
            sg_id = resp["SecurityGroups"][0]["GroupId"]
            log.info("Found existing test SG: %s", sg_id)
            return sg_id

        # Create a new one
        resp = ec2_client.create_security_group(
            GroupName=f"cdet013-test-{int(time.time())}",
            Description="CDET-013 Security Test — auto-created, safe to delete",
            VpcId=vpc_id,
        )
        sg_id = resp["GroupId"]
        ec2_client.create_tags(
            Resources=[sg_id],
            Tags=[
                {"Key": "Purpose", "Value": "CDET-013-security-test"},
                {"Key": "AutoDelete", "Value": "true"},
            ],
        )
        log.info("Created test SG: %s", sg_id)
        return sg_id

    except ClientError as e:
        log.error("Could not create test SG: %s", e.response["Error"]["Code"])
        raise


def authorize_rule(
    ec2_client,
    sg_id: str,
    port: int,
    cidr: str = "0.0.0.0/0",
    protocol: str = "tcp",
) -> bool:
    """Add an ingress rule to a security group."""
    try:
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": protocol,
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [
                        {
                            "CidrIp": cidr,
                            "Description": f"CDET-013-test-{port}",
                        }
                    ],
                }
            ],
        )
        log.info(
            "AuthorizeSecurityGroupIngress: %s — port %d/%s from %s",
            sg_id, port, protocol, cidr,
        )
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidPermission.Duplicate":
            log.warning("Rule already exists: port %d from %s on %s", port, cidr, sg_id)
            return True
        log.error(
            "AuthorizeSecurityGroupIngress failed: %s — %s",
            code, e.response["Error"]["Message"],
        )
        return False


def revoke_rule(
    ec2_client,
    sg_id: str,
    port: int,
    cidr: str = "0.0.0.0/0",
    protocol: str = "tcp",
) -> bool:
    """Revoke an ingress rule from a security group."""
    try:
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": protocol,
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{"CidrIp": cidr}],
                }
            ],
        )
        log.info(
            "RevokeSecurityGroupIngress: %s — port %d/%s from %s",
            sg_id, port, protocol, cidr,
        )
        return True
    except ClientError as e:
        log.error(
            "RevokeSecurityGroupIngress failed: %s — %s",
            e.response["Error"]["Code"],
            e.response["Error"]["Message"],
        )
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-013: Security Group Opened to Public Internet Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--security-group-id",
        default=None,
        help="Security group ID to use in execute mode. If not provided, creates a test SG.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="Port to open in execute mode. Default: 22 (SSH). Common choices: 22, 3389, 3306",
    )
    parser.add_argument(
        "--protocol",
        default="tcp",
        choices=["tcp", "udp"],
        help="IP protocol. Default: tcp",
    )
    parser.add_argument(
        "--assess",
        action="store_true",
        help="Read-only: list all existing overly-permissive security group rules.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Add and immediately revoke a rule (generates CloudTrail events for CDET-013).",
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
    print("CDET-013 — Security Group Opened to Public Internet")
    print("Tactic: Defense Evasion | MITRE T1562.007")
    if args.execute:
        print("Mode: EXECUTE (will add and immediately revoke SG rule)")
    elif args.assess:
        print("Mode: ASSESS (read-only — listing permissive rules)")
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

    ec2 = session.client("ec2")

    # Always run the assessment (read-only)
    log.info("Performing read-only assessment of existing permissive rules...")
    findings = assess_permissive_rules(session)
    print_assessment(findings)

    if args.assess:
        return

    if args.execute:
        # Determine target security group
        sg_id = args.security_group_id
        if not sg_id:
            # Find default VPC and create a test SG
            try:
                vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
                if not vpcs["Vpcs"]:
                    log.error(
                        "No default VPC found. Create one or specify --security-group-id."
                    )
                    sys.exit(1)
                vpc_id = vpcs["Vpcs"][0]["VpcId"]
                sg_id = get_or_create_test_sg(ec2, vpc_id)
            except ClientError as e:
                log.error("Could not find VPC: %s", e.response["Error"]["Code"])
                sys.exit(1)

        service_name = HIGH_RISK_PORTS.get(args.port, f"port {args.port}")
        print()
        print("=" * 60)
        print("EXECUTING: Add then immediately revoke SG rule")
        print("=" * 60)
        print(f"  Security Group:  {sg_id}")
        print(f"  Port:            {args.port} ({service_name})")
        print(f"  Protocol:        {args.protocol}")
        print(f"  CIDR:            0.0.0.0/0 (ALL INTERNET)")
        print()
        print("Adding ingress rule...")

        authorized = authorize_rule(ec2, sg_id, args.port, "0.0.0.0/0", args.protocol)

        if authorized:
            log.info(
                "AuthorizeSecurityGroupIngress event generated — CDET-013 should fire"
            )
            log.info("Waiting 2 seconds before revocation (for CloudTrail capture)...")
            time.sleep(2)

            log.info("Immediately revoking the rule (safety measure)...")
            revoked = revoke_rule(ec2, sg_id, args.port, "0.0.0.0/0", args.protocol)

            if revoked:
                log.info("Rule successfully revoked — exposure window was ~2 seconds")
                log.info(
                    "CloudTrail events generated: "
                    "AuthorizeSecurityGroupIngress + RevokeSecurityGroupIngress"
                )
            else:
                log.error(
                    "REVOCATION FAILED — manually revoke port %d 0.0.0.0/0 rule on %s",
                    args.port, sg_id,
                )
                log.error(
                    "Run: aws ec2 revoke-security-group-ingress --group-id %s "
                    "--protocol %s --port %d --cidr 0.0.0.0/0",
                    sg_id, args.protocol, args.port,
                )
                sys.exit(1)

            # Clean up test SG if we created it
            if not args.security_group_id:
                try:
                    ec2.delete_security_group(GroupId=sg_id)
                    log.info("Test security group %s deleted", sg_id)
                except ClientError as e:
                    log.warning(
                        "Could not delete test SG %s: %s — delete manually",
                        sg_id, e.response["Error"]["Code"],
                    )
    else:
        # Dry-run output
        sg_display = args.security_group_id or "sg-XXXXXXXX (new test SG)"
        service_name = HIGH_RISK_PORTS.get(args.port, f"custom port {args.port}")
        print()
        print("=" * 60)
        print("DRY-RUN — Rule that WOULD be added:")
        print("=" * 60)
        print(f"  Security Group:  {sg_display}")
        print(f"  Protocol:        {args.protocol}")
        print(f"  Port:            {args.port} ({service_name})")
        print(f"  CIDR:            0.0.0.0/0 (ALL INTERNET)")
        print()
        print("AWS CLI equivalent:")
        print(f"  aws ec2 authorize-security-group-ingress \\")
        print(f"    --group-id {sg_display} \\")
        print(f"    --protocol {args.protocol} \\")
        print(f"    --port {args.port} \\")
        print(f"    --cidr 0.0.0.0/0")
        print()
        print("[DRY-RUN] No changes made. Add --execute to generate real CloudTrail events.")


if __name__ == "__main__":
    main()
