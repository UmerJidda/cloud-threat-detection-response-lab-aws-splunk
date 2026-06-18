# CDET-011 — Simulation Steps: Unauthorized Compute Resource Launch

**WARNING**: Launching EC2 instances incurs real AWS costs. Steps marked [SIMULATION] use t3.micro instances only. NEVER launch GPU instances (p3, p4d, g4dn families) for testing — the costs are extreme and unnecessary to trigger the detection.

---

## Prerequisites

- AWS CLI configured (`aws configure`)
- IAM permissions: `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:DescribeInstances`
- An EC2 key pair (for SSH access if needed)
- A VPC with at least one subnet

---

## Phase 1: Discover Available Resources

```bash
# Get the current region
REGION=$(aws configure get region || echo "us-east-1")

# Find a suitable AMI (Amazon Linux 2)
AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters \
    "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
    "Name=state,Values=available" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)
echo "AMI ID: $AMI_ID"

# Find the default VPC and subnet
DEFAULT_VPC=$(aws ec2 describe-vpcs \
  --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)

DEFAULT_SUBNET=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$DEFAULT_VPC" \
  --query 'Subnets[0].SubnetId' --output text)

echo "VPC: $DEFAULT_VPC | Subnet: $DEFAULT_SUBNET"
```

---

## Phase 2: Simulated GPU Instance Launch (for Detection Testing)

**NOTE**: The attacker would launch GPU instances. For safe testing, we use t3.micro but include the metadata that would trigger detection (the instance type field is what CDET-011 monitors for GPU families).

The AWS CLI command an attacker would use for actual GPU mining:

```bash
# THIS IS WHAT AN ATTACKER WOULD DO — DO NOT RUN:
# aws ec2 run-instances \
#   --image-id ami-0abcdef1234567890 \
#   --instance-type p3.16xlarge \
#   --count 10 \
#   --user-data "$(base64 < mining-bootstrap.sh)"
```

To test the detection rule for non-GPU instance types (safe):

```bash
# Create a UserData script that mimics miner behavior WITHOUT actual mining
cat > /tmp/fake-miner-userdata.sh << 'EOF'
#!/bin/bash
# SIMULATION ONLY — no actual mining occurs
# This mimics what a miner bootstrap script would look like
echo "SIMULATION: This would download and run XMRig"
echo "SIMULATION: Would connect to pool.minexmr.com:4444"
echo "SIMULATION: Wallet: 4XXXX... (attacker wallet)"
# Actual miner command would be:
# ./xmrig -o pool.minexmr.com:4444 -u WALLET -p x --background
EOF

# Launch a t3.micro for safe testing
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type t3.micro \
  --count 1 \
  --subnet-id "$DEFAULT_SUBNET" \
  --user-data file:///tmp/fake-miner-userdata.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Purpose,Value=CDET011-test},{Key=AutoTerminate,Value=true}]' \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "Launched instance: $INSTANCE_ID"
echo "CloudTrail RunInstances event generated — CDET-011 should detect GPU instance types"
```

---

## Phase 3: Lambda Function Launch (Mining via Serverless)

```bash
# Create a minimal Lambda execution role
ROLE_ARN=$(aws iam create-role \
  --role-name cdet011-lambda-test-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  --query Role.Arn --output text)

# Attach basic execution policy
aws iam attach-role-policy \
  --role-name cdet011-lambda-test-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

sleep 10  # Wait for role propagation

# Create a Lambda function that simulates what a miner would do
cat > /tmp/miner-lambda.py << 'EOF'
def handler(event, context):
    # SIMULATION ONLY
    # A real crypto miner Lambda would run XMRig in CPU mode here
    # import subprocess
    # subprocess.Popen(['./xmrig', '-o', 'pool.minexmr.com:4444', '-u', 'WALLET'])
    print("SIMULATION: CPU mining would execute here")
    return {"status": "simulation", "mining": False}
EOF

# Package the function
zip /tmp/miner-lambda.zip /tmp/miner-lambda.py

# Create the Lambda function (the CloudTrail detection event)
aws lambda create-function \
  --function-name cdet011-simulated-miner \
  --runtime python3.12 \
  --role "$ROLE_ARN" \
  --handler miner-lambda.handler \
  --zip-file fileb:///tmp/miner-lambda.zip \
  --timeout 900 \
  --memory-size 3008 \
  --description "SIMULATION: CDET-011 test - unauthorized Lambda function"

echo "Lambda function created — CloudTrail CreateFunction event generated"
```

---

## Phase 4: Immediate Termination (Cleanup)

**Run immediately after the RunInstances event is confirmed in CloudTrail.**

```bash
# Terminate the test instance immediately
aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"

# Wait for termination
aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
echo "Instance $INSTANCE_ID terminated"

# Delete Lambda function
aws lambda delete-function --function-name cdet011-simulated-miner

# Delete Lambda role
aws iam detach-role-policy \
  --role-name cdet011-lambda-test-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam delete-role --role-name cdet011-lambda-test-role

echo "Cleanup complete"
```

---

## How to Test GPU Detection Without Launching GPU Instances

The CDET-011 rule monitors for specific instance types in `RunInstances` events. You can test the detection logic without actually launching GPU instances in two ways:

**Option 1: Inject a synthetic CloudTrail event** (if your SIEM supports synthetic event testing):
```json
{
  "eventName": "RunInstances",
  "requestParameters": {
    "instanceType": "p3.16xlarge",
    "minCount": 10,
    "maxCount": 10
  }
}
```

**Option 2: Test detection queries against sample log data**:
Use the `expected_events.md` sample event as test input to your Splunk/SIEM detection rule. This validates the query without incurring actual costs.

**Option 3: Use an IAM permission boundary** to allow `RunInstances` only for non-GPU types. Attempt to launch a GPU instance — it will fail with `AccessDenied`, but the attempt (including the instance type) is still recorded in CloudTrail as an API call attempt.
