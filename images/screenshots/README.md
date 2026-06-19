# Screenshot Capture Guide

## Overview

Screenshots are evidence. In a detection engineering portfolio, the code tells a reviewer what the system does — screenshots prove it actually runs. A hiring manager reviewing this project can read the Python collectors, the SPL detections, and the dashboard XML in the repository, but without screenshots they are reviewing theory, not a working system.

This project can be partially validated offline: the sample log data in `sample_logs/cloudtrail/`, the detection validator script, and the Splunk dashboards all work with synthetic data loaded into a local Splunk instance. However, the most compelling screenshots — collector execution against a live AWS account, real CloudTrail events flowing into Splunk, live alert counts — require an active AWS environment and a connected Splunk instance.

This guide tells you exactly which screenshots to take, what each one must show, and why each one matters to the person reviewing your portfolio.

---

## Prerequisites for Screenshots

Before capturing any screenshot, confirm the following are in place:

1. **Splunk is running** — Splunk Enterprise or Splunk Free (local or remote). The web UI is accessible at `http://localhost:8000` or your Splunk server address.

2. **Indexes exist** — The indexes `aws_cloudtrail`, `aws_security`, and `cdet_alerts` have been created in Splunk Settings > Indexes.

3. **Sample data is loaded** — Run the ingest script to load the sample CloudTrail logs from `sample_logs/cloudtrail/` into the `aws_cloudtrail` index. Dashboards and detection screenshots can be captured with sample data alone.

4. **Dashboards are imported** — The dashboard XML files from `splunk/dashboards/` have been imported into Splunk via Settings > User Interface > Views, or via the Splunk CLI.

5. **AWS credentials are configured** (live screenshots only) — Run `aws configure` with credentials that have at minimum `cloudtrail:LookupEvents`, `ec2:DescribeInstances`, `iam:ListUsers`, and `iam:GetAccountSummary` permissions. Collectors use the boto3 default credential chain — never hardcode credentials.

6. **Python environment is active** — The virtual environment is activated and all dependencies from `requirements.txt` are installed.

---

## Screenshot Catalog

### 01 — Splunk Indexes

**Filename:** `01_splunk_indexes.png`

**Setup steps:**
1. Log in to Splunk.
2. Navigate to **Settings > Indexes**.
3. In the filter box, type `aws` to narrow the list.
4. Confirm that `aws_cloudtrail`, `aws_security`, and `cdet_alerts` all appear with non-zero values in the **Current Size** or **Event Count** column. If event counts are zero, load the sample data first.

**What to capture:**
The full Splunk Settings > Indexes table showing at least the three project indexes. The columns that must be visible are: Index Name, Current Size (or Event Count), Home Path, and Status (Enabled).

**What to show:**
- `aws_cloudtrail` index with event count > 0
- `aws_security` index listed and enabled
- `cdet_alerts` index listed and enabled
- The Splunk navigation chrome visible to confirm this is the Settings panel, not a fabricated screenshot

**Why it matters:**
This is the first check a technical reviewer runs mentally: "Did they actually set up Splunk, or did they just write config files?" Non-zero event counts confirm the pipeline has moved data. The three named indexes match the architecture described in the project documentation, demonstrating deliberate index design rather than using the default index.

---

### 02 — Collector Execution

**Filename:** `02_collector_execution.png`

**Setup steps:**
1. Open a terminal in the project root directory.
2. Activate the Python virtual environment.
3. Run the following command (substitute your actual AWS region):
   ```
   python scripts/aws_collectors/collect_cli.py --all --region us-east-1
   ```
4. Wait for the run to complete. The output should print structured log lines with timestamps, event counts, and source labels for each collector module.

**What to capture:**
The terminal window showing the full collector run output, from the first log line to the final summary line. If the output is longer than one screen, scroll to show the summary section at the bottom, making sure at least two collector modules and their event counts are visible.

**What to show:**
- Command invocation line visible at the top of the terminal
- Structured log output with at least two collector sources (e.g., `cloudtrail`, `guardduty`, or `iam`) showing event counts collected
- A completion or summary line confirming the run finished without errors
- Timestamp fields in the log lines confirming this is a live run

**Why it matters:**
Python collectors that produce no output are impossible to distinguish from collectors that were never run. This screenshot proves the automation works end-to-end: AWS authenticated, API calls made, data returned, data written. For a role in detection engineering or cloud security, the ability to build reliable data collection pipelines is a primary competency this screenshot validates.

---

### 03 — CloudTrail Ingestion

**Filename:** `03_cloudtrail_ingestion.png`

**Setup steps:**
1. Open the Splunk Search & Reporting app.
2. Set the time picker to **Last 1 hour** (or **Last 24 hours** if using sample data that may be older).
3. Run the following search exactly:
   ```
   index=aws_cloudtrail earliest=-1h
   | table _time eventName eventSource sourceIPAddress userIdentity.arn awsRegion
   | head 20
   ```
4. Wait for results to load. Confirm at least 5 rows are visible with all columns populated.

**What to capture:**
The Splunk search interface with the query visible in the search bar and the results table fully loaded below it. The statistics/events count in the Splunk header (e.g., "20 of 847 events") should be visible.

**What to show:**
- The search query in the search bar
- At least 10 rows in the results table
- All five columns populated: `_time`, `eventName`, `eventSource`, `sourceIPAddress`, `userIdentity.arn`
- A variety of `eventName` values (not all the same event) to demonstrate breadth of collection
- The time range selector showing the search window

**Why it matters:**
This screenshot closes the loop on the telemetry pipeline. The collector (screenshot 02) pulls data from AWS. This screenshot confirms that data reached Splunk, was indexed in the correct index, and was normalized so that standard CloudTrail fields are queryable by name. The field names visible (`eventName`, `sourceIPAddress`, `userIdentity.arn`) match AWS CloudTrail schema, demonstrating that field extraction is working correctly.

**Note on sensitive data:** Before capturing, blur or replace any real AWS account IDs in the `userIdentity.arn` column. Substitute the fictional account ID `123456789012`. Replace real IP addresses with addresses from the documentation ranges `192.0.2.0/24` or `198.51.100.0/24`.

---

### 04 — Detection Results

**Filename:** `04_detection_results.png`

**Setup steps:**
1. Confirm sample data is loaded in `aws_cloudtrail` (the sample data includes synthetic attack events that trigger CDET-001).
2. Open the Splunk Search & Reporting app.
3. Open the SPL for detection CDET-001 from `detections/CDET-001_root_account_usage.yml` — copy the `splunk_spl` query field.
4. Paste the query into the Splunk search bar.
5. Set the time range to **All Time** if using sample data, or **Last 24 hours** for live data.
6. Run the search. At least one result row should appear representing a fired alert.

**What to capture:**
The Splunk search results page showing the CDET-001 query in the search bar and at least one alert row in the results table. Capture the full browser window including the Splunk navigation chrome.

**What to show:**
- The detection SPL query visible in the search bar (or the first ~80 characters of it)
- At least one result row with alert fields populated (e.g., `alert_id`, `severity`, `description`, `eventName`, `sourceIPAddress`)
- The event count in the Splunk header confirming results were returned
- If possible, also show zero results returned when benign-only data is used — a side-by-side or second screenshot labeled `04b_detection_no_false_positives.png` is a strong addition

**Why it matters:**
A detection that was written but never fired is not a detection — it is a hypothesis. This screenshot proves the SPL logic executes correctly and fires on malicious behavior. The combination of alerting on attack data and suppressing benign data (if captured) demonstrates that the detection has been tuned, which is the core skill of detection engineering. This is the screenshot most likely to prompt a follow-up interview question about how the detection was validated.

---

### 05 — SOC Dashboard

**Filename:** `05_soc_dashboard.png`

**Setup steps:**
1. Import `splunk/dashboards/soc_dashboard.xml` into Splunk if not already done (Settings > User Interface > Views > Create New View, paste XML, or use `splunk cmd splunk-dashboards import`).
2. Navigate to the dashboard in the Splunk app.
3. Set the dashboard time range to **Last 24 hours** or **All Time** if using sample data.
4. Wait for all panels to load. Panels that show "No results" indicate data is missing for that query — load more sample data or expand the time range.

**What to capture:**
The full SOC dashboard with all panels visible. If the dashboard is taller than one screen, take a full-page screenshot or two overlapping screenshots. Capture at minimum: the alert queue panel with at least one entry, the severity breakdown panel (high/medium/low counts), and the detection health table.

**What to show:**
- Alert queue panel with at least one alert row
- Severity count visualization (chart or single-value panels) showing non-zero values
- Detection health table listing detection IDs and their status
- Dashboard title confirming this is the SOC operational view
- Splunk navigation chrome confirming this is running in Splunk

**Why it matters:**
Detection engineering does not end at writing SPL queries. A SOC operator needs a dashboard to triage alerts, monitor detection health, and prioritize response. This screenshot demonstrates that the project includes operational tooling — not just detection logic — which reflects an understanding of how detection engineering fits into a security operations workflow. For a SOC analyst or detection engineer role, this is the artifact that shows you built something usable, not just theoretically correct.

---

### 06 — Cloud Security Dashboard

**Filename:** `06_cloud_security_dashboard.png`

**Setup steps:**
1. Import `splunk/dashboards/cloud_security_dashboard.xml` into Splunk if not already done.
2. Navigate to the cloud security dashboard.
3. Set the time range to **Last 24 hours** or **All Time** for sample data.
4. Confirm the following panels have data: CloudTrail events by service (chart), IAM high-value events (chart or table), and region activity table.

**What to capture:**
The full cloud security dashboard with charts populated. Prioritize capturing the events-by-service chart and the IAM activity panel in the same screenshot.

**What to show:**
- CloudTrail events grouped by AWS service (e.g., `iam.amazonaws.com`, `ec2.amazonaws.com`, `s3.amazonaws.com`) in a bar or pie chart
- IAM high-value events chart or table with event names like `CreateUser`, `AttachUserPolicy`, `CreateAccessKey`
- Region activity table showing at least one AWS region with event counts
- Dashboard title and Splunk chrome

**Why it matters:**
Cloud security visibility requires knowing which services are generating events, which IAM actions are being taken, and which regions are active. This dashboard screenshot demonstrates that the project provides cloud-native visibility across the AWS environment — not just raw log collection. For a cloud security engineer or detection engineer role focused on AWS, this is evidence that you understand what to monitor in a cloud environment and built the tooling to do it.

---

### 07 — Validation Workflow

**Filename:** `07_validation_workflow.png`

**Setup steps (Option A — terminal output):**
1. Open a terminal in the project root.
2. Activate the Python virtual environment.
3. Run:
   ```
   python scripts/detection_validator.py
   ```
4. Wait for the validation run to complete. The output should show PASS/FAIL results for each CDET detection tested.

**Setup steps (Option B — Splunk saved search):**
1. Confirm the validation saved searches have been loaded into Splunk from `splunk/savedsearches/`.
2. In Splunk Search & Reporting, run:
   ```
   | savedsearch "CDET-ValidationRunSummary"
   ```
3. Or navigate to the saved search results directly if the search runs on a schedule.

**What to capture (Option A):** The terminal showing validation output with PASS results for at least three CDET detections and a summary line showing pass rate (e.g., `Validation complete: 5/5 passed`).

**What to capture (Option B):** The Splunk results table from the validation saved search showing columns including `detection_id`, `test_case`, `result` (PASS), and `pass_rate`.

**What to show:**
- At minimum three CDET detection IDs listed with PASS status
- A summary or aggregate pass rate
- No FAIL results visible (or, if there are known failures, a note in the portfolio explaining why)

**Why it matters:**
Any sufficiently experienced detection engineer will ask: "How do you know your detections actually work?" A validation framework that runs automated tests against known-malicious and known-benign data is the correct answer. This screenshot proves the validation framework exists and produces results. It demonstrates engineering discipline — the project includes tests, not just code. For a mid-to-senior detection engineering role, this is the differentiating artifact that separates a polished project from a collection of untested SPL queries.

---

### 08 — Repository Architecture

**Filename:** `08_repo_architecture.png`

**Setup steps:**
1. Open the GitHub repository in a browser (or push the local repository to GitHub if not already done).
2. Navigate to the repository root page.
3. Expand the directory tree if GitHub is showing a collapsed view. The goal is to show all top-level directories in a single screenshot: `detections/`, `playbooks/`, `attack_simulations/`, `scripts/`, `splunk/`, `validation/` (and others).

**What to capture:**
The GitHub repository root page showing the file and directory listing. The full directory structure should be visible without scrolling if possible. If the repository has a README that renders below the file list, crop to show the file list prominently.

**What to show:**
- All primary project directories visible: `detections/`, `playbooks/`, `attack_simulations/`, `scripts/`, `splunk/`, `validation/`, `sample_logs/`, `images/`
- Commit messages next to each directory/file showing recent activity
- The repository name and owner in the GitHub header
- The branch indicator showing `main`

**Why it matters:**
Repository structure is the first thing a technical reviewer looks at when they open your GitHub link. A well-organized repository signals that the engineer thought about the project as a system, not a collection of scripts. Each directory name is a signal: `detections/` shows detection engineering artifacts, `playbooks/` shows incident response thinking, `attack_simulations/` shows red team awareness, `scripts/` shows automation. This screenshot anchors every other screenshot in the portfolio — it shows the full scope of the project at a glance.

---

## Optional Enhancement Screenshots

These four screenshots are not required but significantly strengthen the portfolio. Capture them if time allows.

### 09 — Alert Enrichment Output

**Filename:** `09_alert_enrichment.png`

Run `python scripts/alert_enrichment.py` with the example test function (`_example_tests()`) invoked. Show the structured enrichment output for a sample alert — IP reputation lookup results, user context, geo data. This demonstrates that the detection pipeline extends beyond alerting into automated enrichment, which is a key capability in mature SOC environments.

### 10 — IOC Extraction Output

**Filename:** `10_ioc_extraction.png`

Run the IOC extraction script against a sample alert or log file. Show the extracted indicators (IPs, ARNs, user agents, hashes) in structured output format. This demonstrates threat intelligence integration capability — that the project can identify and extract indicators for downstream blocking or hunting.

### 11 — Detection Engineering Dashboard

**Filename:** `11_detection_engineering_dashboard.png`

If the project includes a detection engineering metrics dashboard (detection coverage by MITRE tactic, detection age, false positive rate trends), capture it with data populated. This demonstrates that the project includes metrics to manage the detection program itself, not just individual detections.

### 12 — Executive Dashboard

**Filename:** `12_executive_dashboard.png`

If the project includes an executive or leadership-facing dashboard with high-level security posture metrics (total alerts this week, top threat categories, trend lines), capture it. This demonstrates awareness that security programs must communicate risk to non-technical stakeholders, which is relevant for senior individual contributor and lead roles.

---

## Screenshot Quality Standards

Apply these standards to every screenshot before including it in the portfolio.

**Resolution:** Minimum 1920x1080 pixels. Lower-resolution screenshots appear unprofessional when zoomed or displayed on high-DPI monitors. On macOS, use Cmd+Shift+3 (full screen) or Cmd+Shift+4 (selection). On Windows, use the Snipping Tool at 100% zoom or Win+Shift+S.

**File format:** PNG is strongly preferred. PNG is lossless — text, terminal output, and table data remain sharp. JPEG is acceptable only for screenshots that are dominated by charts or images with no text that must be readable.

**Sensitive data — what to remove before capturing:**

| Data type | What to do |
|---|---|
| Real AWS account ID (12 digits) | Replace with `123456789012` before capturing, or blur in post |
| Real IAM usernames | Replace with fictional names like `alice`, `bob`, or `svc-monitor` |
| Real IP addresses | Replace with documentation range IPs: `192.0.2.x` or `198.51.100.x` |
| Real AWS access key IDs | Never visible in screenshots; if visible, the screenshot must be retaken |
| Real S3 bucket names that reveal business context | Replace with generic names like `company-logs-bucket` |
| Real email addresses in IAM ARNs | Replace with `user@example.com` |

**Annotations:** Add a single red rectangle or red arrow pointing to the key element in each screenshot. Do not add multiple annotations that clutter the image. The annotation should answer the question "what am I supposed to look at in this screenshot?" For example: a red box around the event count in screenshot 01, a red arrow pointing to the PASS summary line in screenshot 07.

**Annotation tools:** macOS Preview (markup toolbar), Windows Photos (edit > draw), or any image editor. Do not use browser developer tools to artificially inflate numbers before screenshotting.

**Consistency:** Use the same browser, the same Splunk theme (light or dark — pick one and keep it throughout), and the same terminal font across all screenshots. Inconsistency signals that screenshots were taken at different times or in different environments.
