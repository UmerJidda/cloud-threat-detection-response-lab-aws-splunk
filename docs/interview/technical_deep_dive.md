# Technical Deep Dive — Cloud Threat Detection Lab

Prepared answers for senior and technical interview rounds. All answers are grounded in the actual implementation in this repository.

---

## Detection Engineering Decisions

### "Why did you design the suppression system using Splunk lookup tables instead of hardcoding exceptions in the SPL?"

The core reason is separation of concerns and operational ownership. When exceptions are hardcoded in SPL — typically as `NOT src_user="arn:aws:iam::123456789012:role/TerraformRole"` strings — only a detection engineer with SPL write access can update them. That creates a bottleneck: every time a new CI/CD pipeline role is deployed, someone has to open a search, edit a string, test it, and push a change. A single typo suppresses the wrong thing silently.

In this project, approved principals live in `splunk/lookups/approved_iam_principals.csv` and automation roles in `splunk/lookups/automation_role_arns.csv`. The SOC team or a junior analyst can open those CSVs, add a row with a `reason` and optional `expiry_date` column, and the change is live at the next search execution without touching the SPL at all. The CSV acts as a structured audit trail: every suppressed principal has a documented reason and owner.

The alternative — regex-based suppression (`NOT creator_arn=*terraform*`) — is worse for two reasons. First, it matches on substring patterns that an attacker could exploit by naming a compromised role to contain the suppressed string. Second, regex patterns in SPL are fragile: they do not enforce ARN structure, will silently suppress ARNs that were never intended, and are nearly impossible to review for completeness in a code review.

Lookup-based suppression scales. When this project moves to a multi-account environment, the same CSV files can be extended with an `aws_account_id` column and the SPL lookup call changes by one field. With hardcoded exceptions, that migration would require rewriting every detection.

---

### "How does your Python validator relate to the SPL? Why have both?"

`validation/validator.py` is a pre-Splunk quality gate. It runs offline — no Splunk connection required — and validates the structural contract for each detection: does the YAML metadata contain required fields (`detection_id`, `severity`, `tactic`, `technique`, `data_sources`), does the SPL file exist and is it non-empty, do the NDJSON test-case files exist and contain the fields the detection is supposed to surface?

The SPL saved searches in `splunk/savedsearches/detection_validation.conf` (for example `CDET-ValidatePositive-001` and `CDET-ValidateNegative-001`) are the production runtime gate. They run against real or synthetic log data inside Splunk's actual execution engine, verifying that the search logic itself fires on known-positive inputs and stays silent on known-negative inputs.

The analogy to software testing is direct. `validator.py` is the unit test layer: fast, no infrastructure, catches schema and authoring errors in seconds during development. The Splunk saved searches are the integration test layer: they require a running Splunk instance, a populated test index (`aws_cloudtrail_test`), and the lookup tables to be deployed. Running the integration layer for every small edit to a detection during development would take minutes per cycle. The validator catches 80% of errors in under a second.

There is also a mock-testing risk this design avoids. If you stub out the Splunk search engine in Python tests, you are testing a mock, not SPL. SPL field extraction, lookup join semantics, and `tstats` data model behaviour are not faithfully reproducible in a Python mock. Keeping the Python layer scoped to structure validation and leaving runtime validation to real Splunk means each layer tests what it can test reliably.

---

### "How do you handle edge cases in your detections?"

Edge cases are handled at three levels in this project.

At the authoring level, each detection YAML in `detections/<tactic>/<detection_id>/detection.yaml` contains a `false_positive_notes` block and a `test_cases` array. The test cases list specific expected outcomes: which input file should fire an alert, which should be suppressed, and why. For CDET-001 there are three test cases: unknown interactive principal (expected alert), approved IaC pipeline role (suppressed via `approved_iam_principals` lookup match), and a failed `CreateUser` call (suppressed because `errorCode` is present and the detection targets successful creation only).

At the runtime level, the NDJSON test-case sample files in `data/samples/` represent concrete boundary conditions. The edge case for CDET-001 that requires particular care is an approved role operating in an unusual region: the detection should not fire based on region alone, because an approved pipeline deploying a stack in `ap-southeast-1` for the first time is not an attacker. The suppression lookup is keyed on ARN, not region, so this boundary condition is handled correctly by design.

At the documentation level, the validation schema in `validation/validation_schema.md` and the validation workflow in `validation/validation_workflow.md` describe how edge case coverage is measured across all 14 detections. The validation matrix tracks whether each detection has at least one positive, one negative, and one edge case test, and flags any detection that is missing coverage before it is promoted to production status.

---

## Collector Architecture

### "Why did you choose LookupEvents over S3 polling for CloudTrail collection?"

`LookupEvents` is the CloudTrail management API that returns events within approximately 15 minutes of occurrence. It is the right choice for a SOC analyst workflow for several reasons.

S3 delivery of CloudTrail logs has a nominal delivery time of about 5 minutes, but that figure assumes the delivery pipeline is healthy. In practice S3 delivery requires: S3 read permissions on the logging bucket, code to enumerate and parse the S3 key prefix structure (`AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/`), gzip decompression of each log file, and handling the case where multiple regions write to the same bucket. That is four distinct failure surfaces before you have read a single event. It also requires pre-provisioning an S3 bucket with the correct bucket policy for CloudTrail delivery, which is infrastructure overhead that is not always available in a lab or rapid-response context.

`LookupEvents` via `boto3.client("cloudtrail").lookup_events()` requires only `cloudtrail:LookupEvents` IAM permission, returns structured JSON directly, and has no delivery infrastructure to configure. For a detection engineer validating that a new detection fires correctly, or a SOC analyst pulling the last hour of IAM events during an investigation, the simplicity of `LookupEvents` is the dominant factor.

The trade-off is clear: `LookupEvents` has a 90-day history limit, a 5 requests-per-second API rate limit per region, and only returns management events, not data events (S3 object-level access, Lambda invocations). For a high-volume production environment ingesting billions of events per day, S3 is the right architecture. The ingestion documentation in `ingestion/cloudtrail_ingestion.md` notes this trade-off explicitly and describes the S3 path as the recommended upgrade for multi-account production deployment.

---

### "How would you scale the collectors to a multi-account AWS environment?"

The boto3 collector in this project uses `boto3.Session()` which resolves credentials via the default chain. Scaling to multiple accounts requires substituting a per-account `boto3.Session` constructed with a cross-account assumed role.

The pattern is:

```python
sts = boto3.client("sts")
assumed = sts.assume_role(
    RoleArn="arn:aws:iam::<member-account-id>:role/SecurityAuditRole",
    RoleSessionName="CloudThreatDetectionCollector"
)
credentials = assumed["Credentials"]
session = boto3.Session(
    aws_access_key_id=credentials["AccessKeyId"],
    aws_secret_access_key=credentials["SecretAccessKey"],
    aws_session_token=credentials["SessionToken"],
)
ct_client = session.client("cloudtrail", region_name=region)
```

In an AWS Organizations environment the correct architecture is: enable CloudTrail Organization Trails from the management account, which automatically enables CloudTrail in all member accounts and delivers all logs to a central S3 bucket in the security tooling account. The collector then reads from that single bucket rather than iterating over accounts and regions individually.

The `SecurityAuditRole` in each member account needs `cloudtrail:LookupEvents` and `cloudtrail:DescribeTrails` permissions, and the management account needs `organizations:ListAccounts` to enumerate member accounts dynamically. This avoids hardcoding account IDs in the collector configuration. The security tooling account's execution role needs `sts:AssumeRole` permission targeting the `SecurityAuditRole` in each member account, enforced via an IAM resource policy condition on `aws:PrincipalOrgID`.

---

## ATT&CK Mapping

### "How did you decide which 14 techniques to detect?"

The selection followed a threat modelling process scoped to an attacker operating in an AWS environment after gaining initial access via a compromised credential or misconfigured IAM role.

The first filter was kill chain coverage: the 14 detections span the full attack progression from initial access (root account use, CDET-006) through persistence (IAM user creation, access key creation — CDET-001, CDET-002), privilege escalation (admin policy attachment, trust modification — CDET-004, CDET-005), defense evasion (CloudTrail disabled, security group opened, log file deleted — CDET-003, CDET-013, CDET-014), credential access (instance metadata abuse — CDET-007), discovery (excessive API enumeration — CDET-008), lateral movement (cross-account AssumeRole chaining — CDET-012), exfiltration (S3 replication to external account — CDET-009), and impact (mass S3 deletion, unauthorized compute launch — CDET-010, CDET-011). Covering the full kill chain means that even if an attacker evades one detection, they are likely to trigger another.

The second filter was signal quality: high-impact techniques with a low expected false positive rate were prioritised. Root account console login (CDET-006) has near-zero legitimate use in a well-managed AWS account, so the FP rate is negligible. Mass S3 deletion above a 50-object threshold (CDET-010) is similarly low-noise. Techniques like general IAM API calls were excluded because they fire on every developer session.

The third filter was data availability: all 14 techniques are detectable from CloudTrail management events, which are available without enabling data event logging. This keeps the project deployable at zero additional CloudTrail cost.

---

### "What MITRE ATT&CK techniques would you add next?"

Four techniques are the logical next additions:

**T1530 — Data from Cloud Storage.** An attacker who has compromised an IAM role can enumerate and download S3 objects directly. This requires enabling CloudTrail S3 data events (`GetObject`, `ListObjects`) which are not enabled by default due to volume. The detection would look for high-volume `GetObject` calls from a single principal in a short window, particularly if the caller ARN does not appear in the approved data access list.

**T1619 — Cloud Storage Object Discovery.** Before exfiltrating data, attackers enumerate bucket contents. `ListBuckets` and `ListObjectsV2` calls from a principal that does not routinely access those buckets is a detectable pre-exfiltration signal. This pairs well with T1537 (CDET-009) as a precursor detection.

**T1578 — Modify Cloud Compute Infrastructure.** Attackers who want persistence or to avoid detection modify AMIs, snapshots, or EC2 instance attributes. CloudTrail logs `ModifyInstanceAttribute`, `CreateSnapshot`, and `ModifySnapshotAttribute` events. Detecting snapshot sharing with external account IDs is a high-confidence signal of data staging for exfiltration.

**T1525 — Implant Internal Image.** An attacker with ECR write access can push a backdoored container image to an internal registry. `ecr:PutImage` and `ecr:InitiateLayerUpload` from a principal that does not belong to the container build pipeline is suspicious. This technique is increasingly relevant as organisations move workloads to ECS and EKS.

---

## Splunk Implementation

### "Walk me through a saved search stanza."

Using `CDET-ValidatePositive-001` from `splunk/savedsearches/detection_validation.conf` as the example:

```ini
[CDET-ValidatePositive-001]
description = Positive validation: CDET-001 IAM user creation by non-approved principal.
              Runs against validation_positive test data. Expected result: >= 1 event.
search = search eventName=CreateUser eventSource="iam.amazonaws.com" index=aws_cloudtrail_test
         source=validation_positive*
         | lookup approved_iam_principals creator_arn OUTPUT approved
         | lookup automation_role_arns session_issuer_arn OUTPUT automation_approved
         | where isnull(approved) AND isnull(automation_approved)
         | table _time eventName creator_arn new_user_name region
cron_schedule = 0 6 * * *
dispatch.earliest_time = -24h
dispatch.latest_time = now
enableSched = 1
action.email.useNSSubject = 1
```

Breaking down each field:

- **`[CDET-ValidatePositive-001]`** — The stanza name is the saved search name in Splunk. The naming convention encodes what this search does: it is a positive validation (should return results) for detection CDET-001.
- **`description`** — Human-readable explanation including the expected result count. This is surfaced in the Splunk UI and read by on-call engineers reviewing the validation dashboard.
- **`search`** — The SPL query. Note `index=aws_cloudtrail_test` and `source=validation_positive*`: this targets the test index populated with synthetic positive-case events, not the production index. The lookup joins then apply the same suppression logic as the production detection to confirm it does not incorrectly suppress a true positive.
- **`cron_schedule = 0 6 * * *`** — Runs once per day at 06:00. Validation searches run daily rather than every 15 minutes because they are a quality gate, not a production alert.
- **`dispatch.earliest_time = -24h`** — The search window. Paired with the daily schedule, this ensures every validation run covers exactly the last 24 hours of test data.
- **`dispatch.latest_time = now`** — Closes the search window at the current time.
- **`enableSched = 1`** — Enables the scheduled execution. Setting this to 0 disables the schedule without deleting the search, which is useful for temporarily pausing validation during an index rebuild.
- **`action.email.useNSSubject = 1`** — Uses the non-summary subject line format for alert emails, which preserves the full saved search name in the subject for easier triage.

---

### "How do your lookup joins work for suppression?"

Using the CDET-001 SPL in `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.spl` as the example.

After normalising event fields, the suppression block is:

```spl
| lookup approved_iam_principals arn AS principal_arn OUTPUT approved, suppression_reason
| lookup automation_role_arns arn AS principal_arn OUTPUT approved AS auto_approved
| eval suppressed=if(approved="true" OR auto_approved="true", "true", "false")
| where suppressed!="true"
```

The `lookup` command performs a left outer join: for each event, Splunk looks up the value of `principal_arn` in the `arn` column of `approved_iam_principals.csv` and writes the corresponding `approved` value back into the event. If the ARN is not found in the CSV, the `approved` field is null.

Two lookups are required because there are two suppression lists with different semantics. `approved_iam_principals` contains IAM users and roles that are explicitly approved to create IAM resources — typically IaC provisioning principals. `automation_role_arns` contains CI/CD and automation roles that should be suppressed across all identity detections. Keeping them as separate CSVs means each list has a distinct owner and audit trail.

The `where isnull(approved) AND isnull(automation_approved)` form (used in the validation saved searches) is equivalent to the `eval suppressed` approach and is preferred in shorter searches for readability. The production SPL uses the `eval suppressed` form to make the suppression logic explicit and debuggable: if an alert is suppressed, the analyst can add `| table suppressed suppression_reason` to the end of the search to see which lookup triggered the suppression.

A second lookup block handles the case where the actor is an AssumedRole session whose session issuer is an approved role even if the assumed role ARN itself is not in the lookup. This covers Terraform running via an assumed role that was not individually listed:

```spl
| lookup approved_iam_principals arn AS session_issuer_arn OUTPUT approved AS issuer_approved
| where isnull(issuer_approved) OR issuer_approved!="true"
```

---

## Incident Response Design

### "Why four playbook files per detection instead of one?"

Four files exist because one file serving four audiences fails all four of them.

The four files are: triage, investigation, containment, and lessons learned. Their audiences and time pressures are distinct.

**Triage** is written for the on-call analyst who receives a 2 AM page. It must be completable in 10 minutes or less. It answers exactly one question: is this a true positive or a false positive? It contains three to five Splunk queries to run, a binary yes/no decision gate, and explicit escalation criteria. It deliberately excludes deep investigation steps because reading them under time pressure adds noise.

**Investigation** is written for a Tier-2 analyst who has confirmed a true positive and needs to scope the incident. It can take 30 to 60 minutes. It documents what other systems or resources to check, what IAM permissions the actor has, what else they might have done, and how to build a timeline.

**Containment** is written for a senior analyst or security engineer who has authority to make destructive changes (disable an IAM user, revoke a session, isolate an EC2 instance). It includes explicit approval gates before irreversible actions and rollback notes. This file should not be in the hands of the on-call analyst until they have escalated.

**Lessons learned** is written for the detection engineer after the incident is closed. It documents what tuning is needed, whether the detection fired at the right time, whether any false negatives were identified, and what the suppression lookup update (if any) should be.

Combining these four documents into one file would mean a 2 AM on-call engineer reads past containment and lessons-learned content to find the three triage queries. Progressive disclosure — revealing complexity as the incident matures — reduces cognitive load at the moments when cognitive load is highest.

---

### "How does your enrichment pipeline work?"

`scripts/alert_enrichment.py` implements the `AlertEnricher` class with a single public method `enrich(alert)` that applies five stages in sequence.

**Stage 1 — ATT&CK context** (`_apply_attack_context`): The `_ATTACK_CONTEXT` dictionary in the module maps all 14 detection IDs to their tactic, technique ID, technique name, and ATT&CK URL. This is a local dictionary lookup — no external API call, no network dependency. The method runs in microseconds regardless of network availability.

**Stage 2 — Severity escalation** (`_apply_severity_context`): The `_SEVERITY_ESCALATION` dictionary defines a base severity and a list of escalation conditions per detection. For CDET-001 the base severity is `high`; if `mfa_used` is `no` or `false` in the alert, the severity escalates to `critical` and a human-readable escalation reason is written to `enriched.severity_escalation_reason`. This gives the on-call engineer an instant explanation without having to re-read the detection logic.

**Stage 3 — Lookup context** (`_apply_lookup_context`): The CSVs from `splunk/lookups/` are loaded at `AlertEnricher` initialisation time into Python sets. The method checks whether the actor ARN from the alert is in the approved principals set or the automation roles set and writes boolean flags onto the enriched alert. These flags let the triage playbook include a line like "if `principal_in_approved_list=True`, treat as likely false positive."

**Stage 4 — IAM context** (`_apply_iam_context`): This stage calls the AWS IAM API via boto3 (using the default credential chain — no credentials in constructor arguments). It retrieves whether the principal still exists, when it was created, whether MFA is active, how many access keys are attached, and which managed policies are attached. All of these are best-effort: if the IAM call fails with any error other than `NoSuchEntity`, the error is logged to `enriched.enrichment_errors` and the alert is returned with whatever context was available. The enrichment never blocks alert delivery.

**Stage 5 — Investigation queries** (`_apply_investigation_queries`): The method generates pre-formatted SPL strings using the actor ARN and detection ID from the alert. These strings are written to `enriched.recommended_queries` and surfaced in the triage playbook. The analyst can copy-paste them directly into Splunk rather than constructing queries from scratch under time pressure. For identity detections (CDET-001, CDET-002, CDET-004) a third query is appended that searches for all actions by the created or modified user, supporting a full activity timeline.

---

## Appendix: Quick Reference

| Component | File / Path |
|---|---|
| CDET-001 SPL | `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.spl` |
| CDET-001 metadata | `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.yaml` |
| Validation saved searches | `splunk/savedsearches/detection_validation.conf` |
| Suppression lookups | `splunk/lookups/approved_iam_principals.csv`, `splunk/lookups/automation_role_arns.csv` |
| Alert enrichment | `scripts/alert_enrichment.py` |
| Pre-deployment validator | `validation/validator.py` |
| Ingestion documentation | `ingestion/cloudtrail_ingestion.md` |
