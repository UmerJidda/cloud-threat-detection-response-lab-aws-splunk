# Interview Talking Points: Cloud Threat Detection Lab

---

## "Walk me through your detection engineering process"

> **Scripted answer using CDET-001 (IAM User Created Outside Pipeline) as the example:**

My process has six stages and I can walk through each one using a rule I built end-to-end in this project.

**1. Threat modeling.** I start by asking: what does an attacker actually do, and where in the cloud control plane does that action leave a trace? For CDET-001, the threat is an adversary who has stolen credentials and needs to establish persistence. The canonical technique is T1136.003 — Create Account: Cloud Account. The IAM `CreateUser` API call is the signal. That gives me a concrete event to detect before I touch SPL.

**2. Data source selection.** I looked at what CloudTrail captures for `CreateUser`: `eventSource=iam.amazonaws.com`, `userIdentity` (the acting principal), `requestParameters.userName` (the created user), `sourceIPAddress`, and whether the call succeeded or returned an error. I built `ParsedEvent` in `scripts/cloudtrail_parser.py` to normalize all these fields — including edge cases like AssumedRole sessions where the identity ARN is under `sessionContext.sessionIssuer.arn`, not the top-level `arn` field.

**3. SPL logic design.** The rule in `detections/persistence/CDET-001_iam_user_created_outside_pipeline/detection.spl` uses two lookup joins back-to-back. The first suppresses principals listed in `approved_iam_principals.csv`. The second checks whether the *session issuer* is in that list — which catches the case where Terraform is running via `AssumeRole`: the immediate identity is a temporary role session, not the Terraform ARN itself. Then a `confidence` eval scores the alert: IAM user with no MFA is high confidence, AssumedRole is medium.

**4. Test data creation.** I created three NDJSON files for CDET-001 in `sample_logs/cloudtrail/`: a malicious case (unknown interactive user creating a backdoor account), a benign case (`CDET-001_pipeline_createuser.ndjson` — an approved IaC role doing the same thing, which should be suppressed), and an edge case (`CDET-001_edge_approved_role_unusual_region.ndjson` — an approved role acting from an unusual region). Three test cases prove three properties: it fires when it should, it suppresses when it should, and it handles boundary conditions correctly.

**5. Python validation.** Before this rule touches Splunk, `scripts/detection_validator.py` runs the same filter logic as a Python function. `_detect_001()` filters for `CreateUser` on `iam.amazonaws.com`, excludes errors, and calls `_is_approved()` which reads the same CSV lookups. The result is a `ValidationResult` where `passed` is `should_fire == fired`. Running the validator against all three test files confirms the detection logic before any Splunk involvement.

**6. Playbook integration.** Once the rule is validated, `playbooks/CDET-001_iam_user_created_outside_pipeline/` provides four structured files. `triage.md` tells the analyst whether this is real within 15 minutes. `investigation.md` maps out what IAM queries to run and what timeline to reconstruct. `containment.md` covers disabling the created user and rotating the actor's credentials. `recovery.md` covers scope assessment and control improvement. An analyst who has never seen this alert before has an exact procedure.

---

## "How do you handle false positives?"

False positives in cloud IAM detections almost always come from one of two sources: automation and break-glass procedures.

**Automation** is handled at SPL time through two lookup joins in every identity-related rule. `splunk/lookups/approved_iam_principals.csv` stores the ARNs of IaC pipeline roles — Terraform execution roles, CDK deployment roles, CloudFormation service roles — that legitimately create and modify IAM resources. `splunk/lookups/automation_role_arns.csv` handles the AssumedRole case: when a CI/CD pipeline assumes a role, the immediate identity is a session ARN, not the pipeline ARN. Both lookups are checked so neither path bypasses suppression.

The second suppression layer runs in Python. `_is_approved()` in `scripts/detection_validator.py` reads the same two CSVs and applies the same logic. This means any logic error in SPL suppression is caught offline before the rule reaches production. The two layers also serve different purposes: SPL suppression prevents alerts from firing at all; Python suppression acts as a pre-ingestion quality gate against test data.

**Severity escalation** in `scripts/alert_enrichment.py` provides a third control. Each CDET has a `base` severity and an `escalate_if` condition. CDET-001 has `base: high` and escalates to `critical` only when `no_mfa` is in the escalation conditions. This means an approved principal accidentally left out of the lookup generates a high-severity alert rather than a critical one, giving analysts a calibrated signal rather than a binary fire/no-fire.

**The three-tier test model** — malicious, benign, edge_case — validates all three properties. A detection that only has a malicious test file only proves it fires; it does not prove it suppresses. Every CDET has at minimum one benign test file to prove suppression works.

---

## "Tell me about a detection you built end-to-end"

I will use CDET-001: IAM User Created Outside Approved Pipeline.

**The threat it detects.** An adversary with stolen AWS credentials calling `iam:CreateUser` to create a backdoor account they control. This is MITRE T1136.003 — Persistence via cloud account creation. The goal is durable access that survives credential rotation on the compromised principal.

**The SPL logic.** The rule searches for `eventName=CreateUser` on `eventSource="iam.amazonaws.com"` with no error code (successful calls only). It then does a double lookup suppression — once against `approved_iam_principals` on the acting principal ARN, once against the session issuer ARN to catch AssumedRole sessions from approved pipelines. Unsuppressed results get a `confidence` score based on identity type and MFA status, then detection metadata (CDET-001, severity=high, T1136.003) is attached before the table output.

**The lookup-based suppression.** `splunk/lookups/approved_iam_principals.csv` and `splunk/lookups/automation_role_arns.csv` hold the approved ARNs. Adding a new IaC pipeline to the suppression list is a CSV edit — no SPL change required. This decoupling is intentional: suppression is operational data, detection logic is code.

**The test data files.** Three NDJSON files in `sample_logs/cloudtrail/`:
- `malicious/CDET-001_createuser_unknown.ndjson` — an unknown interactive IAMUser with no MFA
- `benign/CDET-001_pipeline_createuser.ndjson` — an approved pipeline role doing the same API call
- `edge_cases/CDET-001_edge_approved_role_unusual_region.ndjson` — approved role, unusual region

**The playbook files.** Four files in `playbooks/CDET-001_iam_user_created_outside_pipeline/`: `triage.md` covers the initial 15-minute validation. `investigation.md` covers IAM history queries and timeline reconstruction. `containment.md` covers disabling the backdoor user and rotating compromised credentials. `recovery.md` covers scope confirmation and control gap analysis.

**The Python enrichment.** When `scripts/alert_enrichment.py` receives a CDET-001 alert, it attaches ATT&CK context (T1136.003, Persistence), calls IAM `GetUser` and `ListAttachedUserPolicies` on the created user to check whether it already has permissions attached (a severity escalation signal), checks whether the acting principal is in the approved lookup, and generates investigation queries pre-formatted for the analyst.

---

## "What's your approach to Splunk?"

I use Splunk's native strengths and avoid working against them.

**savedsearches.conf structure.** The three conf files in `splunk/savedsearches/` separate concerns: `detection_validation.conf` holds the 14 CDET alert searches, `coverage_reporting.conf` holds ATT&CK coverage and gap reporting searches, and `detection_health.conf` holds operational monitoring searches (search execution latency, lookup staleness). Separating these means a detection engineer and an ops engineer can manage their domains independently.

**SPL lookup joins.** Every identity detection uses `| lookup ... OUTPUT approved` rather than hardcoding ARN lists in the SPL. This is the key pattern for maintainability. The lookup is a CSV in version control; the SPL is detection logic. They change on different cadences for different reasons and should not be coupled.

**`spath` for JSON.** CloudTrail records arrive as nested JSON. I use `spath` to extract fields like `userIdentity.sessionContext.sessionIssuer.arn` rather than regex, because `spath` handles missing fields gracefully (returns null rather than failing the search) and is more readable.

**`stats`/`eval` patterns.** CDET-008 (API enumeration) uses `stats count BY src_user, _time span=5m` to build a sliding window counter, then `where count > 50` to threshold. The `eval` blocks in each rule normalize identity fields with `coalesce` so downstream logic does not need to branch on identity type.

**Coverage and health monitoring.** The `coverage_reporting.conf` searches produce ATT&CK tactic coverage metrics and identify gaps. `detection_health.conf` monitors for searches that have not run or lookups that have not been refreshed. This is the operational layer that keeps the detection program running cleanly.

---

## "How do you use Python in security operations?"

Five scripts, five distinct problems:

- **`cloudtrail_parser.py`** — normalizes the irregularities in CloudTrail JSON (AssumedRole sessions have a different identity structure than IAMUser events; root account events have no ARN) into a consistent `ParsedEvent` dataclass that all downstream code consumes.
- **`detection_validator.py`** — runs detection logic against sample NDJSON data without a Splunk instance, acting as a pre-ingestion quality gate. The `ValidationResult.passed` property compares `should_fire` to `fired` so both positive and negative test cases use the same structure.
- **`ioc_extractor.py`** — scans `ParsedEvent` objects for indicators of compromise (IP addresses, IAM ARNs, access key IDs, EC2 instance IDs, S3 paths) using regex patterns and deduplicates them across events, merging timestamps and source event lists.
- **`alert_enrichment.py`** — takes a raw alert dict and adds ATT&CK context (hardcoded in `_ATTACK_CONTEXT` — no external API required), IAM context (via boto3 `GetUser`), severity escalation reasoning, lookup membership checks, and pre-formatted investigation queries.
- **`incident_report_generator.py`** — produces three outputs from one `EnrichedAlert`: an executive Markdown summary focused on business impact, a technical analyst Markdown report with full event timeline and IOC table, and a JSON blob for SIEM ingestion. The `report_time` parameter makes all output deterministic for testing.

---

## "What AWS services have you worked with?"

All services appear in this project either as telemetry sources, enrichment targets, or detection subjects.

- **CloudTrail** — the primary telemetry source for all 14 detections. Every detection rule fires on a specific CloudTrail event or pattern. The `cloudtrail_collector.py` module in `scripts/aws_collectors/` reads from CloudTrail via the management events API.
- **IAM** — dual role. The `iam_collector.py` collector retrieves user and role metadata for enrichment. IAM events (CreateUser, AttachUserPolicy, CreateAccessKey, UpdateAssumeRolePolicy) are the trigger for CDET-001 through CDET-005.
- **STS** — AssumeRole chains are the subject of CDET-012 (Cross-Account AssumeRole to Unapproved Account). STS events appear throughout as the identity mechanism for cross-account activity.
- **S3** — subject of CDET-009 (replication to external account), CDET-010 (mass object deletion), and CDET-014 (CloudTrail log file deleted from S3). The `cloudtrail_log_buckets.csv` lookup identifies which S3 buckets contain CloudTrail logs.
- **EC2** — subject of CDET-007 (instance metadata credential abuse, where credentials issued by the metadata service appear at a routable source IP) and CDET-011 (unauthorized instance launch with suspicious GPU instance types).
- **GuardDuty** — the `guardduty_collector.py` collector ingests GuardDuty findings for correlation with CloudTrail events.
- **Security Hub** — the `securityhub_collector.py` collector aggregates findings from GuardDuty and other security services into a normalized format for investigation.
- **Security Groups** — the `security_group_collector.py` collector provides context for CDET-013 (security group rule opening ingress to 0.0.0.0/0).

---

## Questions to Ask the Interviewer

1. "How do you measure detection coverage today — do you map against ATT&CK or use another framework, and are there specific cloud technique gaps you are actively trying to close?"

2. "When a detection fires with a high false-positive rate, what is your process for tuning it — do analysts feed back to detection engineers directly, or is there a formal review cycle?"

3. "How is CloudTrail data ingested into your SIEM — are you using direct S3 polling, Kinesis Firehose, or a managed integration — and does the architecture affect how quickly detections can observe recent events?"

4. "What does the ownership model look like for detection rules — do individual engineers own rules end-to-end including playbooks, or is there a separate IR team that owns the response side?"

5. "How do you handle the tension between reducing false positives through suppression and the risk that overly broad suppression causes you to miss real activity from approved principals that have been compromised?"
