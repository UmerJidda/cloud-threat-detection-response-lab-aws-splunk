# CDET-006 — Simulation Steps: Root Account Activity

## Important Notes

Root account simulation is fundamentally different from other simulations in this lab. You **cannot** simulate root activity programmatically using boto3 with IAM user credentials — the root account is a separate authentication path. This simulation focuses on:

1. A read-only programmatic verification using the `GetCallerIdentity` API (if you have root credentials — only in isolated sandbox accounts)
2. A manual console login test procedure that any operator can perform safely
3. A CloudWatch alarm and CloudTrail configuration verification procedure

---

## Option A: Manual Console Login Test (Recommended — Safe for Any Environment)

This test verifies that your CDET-006 detection rule fires when someone logs into the AWS Console as root. It uses the AWS Console only and makes no API calls via CLI.

### Pre-requisites
- Root account email address and password (should be stored in your organization's privileged access vault)
- Root MFA device
- A separate browser session (or incognito/private window) to avoid logging out your normal IAM session

### Steps

**Step 1: Prepare your detection verification**
Before logging in as root, prepare your SIEM query so you can verify the alert fires quickly:
```spl
index=aws_cloudtrail userIdentity.type=Root
| table _time, eventName, sourceIPAddress, userAgent, awsRegion
| sort -_time
```

Open your Splunk instance and have this query ready to run.

**Step 2: Log into AWS Console as root**
```
1. Open https://console.aws.amazon.com in an incognito/private browser window
2. Click "Sign in to a different account" if needed
3. Enter your AWS Account ID (12 digits) or account alias
4. On the sign-in page, select "Root user"
5. Enter the root email address
6. Enter the root password
7. Complete MFA authentication
```

**Step 3: Call GetCallerIdentity to generate a traceable API event**
Once logged in as root, open the CloudShell in the AWS Console:
```
1. In the top navigation bar, click the CloudShell icon (>_)
2. In CloudShell, run:
   aws sts get-caller-identity

# Expected output (as root):
# {
#     "UserId": "123456789012",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:root"
# }
# Note: The UserId is the Account ID itself, not an AIDA... value
# Note: The Arn ends in ":root" — this is the CloudTrail signal
```

**Step 4: Log out immediately**
```
1. Click your account name in the top right corner
2. Click "Sign out"
3. Close the incognito window
```

**Step 5: Verify detection fired**
In Splunk, run:
```spl
index=aws_cloudtrail userIdentity.type=Root
| table _time, eventName, sourceIPAddress, awsRegion
| sort -_time
| head 10
```

Expected results: Two events:
1. `ConsoleLogin` — from the browser login
2. `GetCallerIdentity` — from the CloudShell command

If CDET-006 is properly configured, you should have received an alert.

---

## Option B: Verify CloudTrail Records Root ConsoleLogin

This option verifies that root login events ARE being recorded in CloudTrail (without actually logging in as root).

```bash
# Check if ConsoleLogin events from Root are present in the last 30 days
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-30d +%Y-%m-%dT%H:%M:%SZ) \
  --output json | python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
root_events = [e for e in events if 'Root' in (e.get('CloudTrailEvent',''))]
print(f'Total ConsoleLogin events: {len(events)}')
print(f'Root ConsoleLogin events: {len(root_events)}')
for e in root_events[:5]:
    ct = json.loads(e['CloudTrailEvent'])
    print(f\"  {e['EventTime']} - Source IP: {ct.get('sourceIPAddress','unknown')}\")
"

# If root logins are expected to be zero and you see any — investigate immediately
```

---

## Option C: Verify Detection Rule Coverage

Verify that your CloudTrail trail is configured to capture the events needed for CDET-006.

```bash
# Step 1: Verify global service events are enabled (root API calls go to global services)
aws cloudtrail describe-trails \
  --query 'trailList[].{Name:Name, GlobalEvents:IncludeGlobalServiceEvents, MultiRegion:IsMultiRegionTrail, LogFileValidation:LogFileValidationEnabled}' \
  --output table

# Expected: GlobalEvents=True for at least one multi-region trail
# If GlobalEvents=False, root IAM API calls may not appear in the trail

# Step 2: Check if CloudWatch Logs integration is active (critical for fast root detection)
aws cloudtrail describe-trails \
  --query 'trailList[].{Name:Name, CloudWatchGroup:CloudWatchLogsLogGroupArn, RoleArn:CloudWatchLogsRoleArn}' \
  --output table

# Expected: CloudWatchGroup should be non-empty for at least one trail
# Without CloudWatch Logs, root detection relies on S3 delivery (5-15 min delay)

# Step 3: Verify CloudWatch alarm for root activity exists
aws cloudwatch describe-alarms \
  --query 'MetricAlarms[?contains(AlarmName, `root`) || contains(AlarmName, `Root`)].{Name:AlarmName, State:StateValue, Actions:AlarmActions}' \
  --output table
```

---

## Setting Up a CloudWatch Alarm for Root Activity (If Not Present)

```bash
# Step 1: Create a metric filter for root activity on the CloudTrail log group
LOG_GROUP="/aws/cloudtrail/management-events"  # Replace with your log group name

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "RootAccountActivity" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootAccountUsage,metricNamespace=CloudTrailMetrics,metricValue=1

# Step 2: Create an alarm that fires on any root activity
aws cloudwatch put-metric-alarm \
  --alarm-name "CDET-006-RootAccountActivity" \
  --alarm-description "Fires when root account is used — CDET-006" \
  --metric-name RootAccountUsage \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 60 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts"  # Replace with your SNS topic

echo "Root activity alarm created: CDET-006-RootAccountActivity"
```
