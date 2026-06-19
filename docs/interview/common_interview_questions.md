# Common Interview Questions — Cloud Threat Detection Lab

Q&A for SOC analyst, detection engineer, and cloud security engineer interviews. All answers reference specific components of this project.

---

## Detection Engineering

**Q1. What is the detection engineering lifecycle?**

The detection engineering lifecycle is the end-to-end process of identifying a threat, building a detection for it, validating it, deploying it, and maintaining it over time. In this project the lifecycle runs as follows: threat modelling identifies which ATT&CK techniques are relevant to an AWS environment, a detection is authored in SPL (`detection.spl`) with metadata in `detection.yaml`, the pre-deployment validator (`validation/validator.py`) checks structure and field coverage offline, positive and negative test cases in `data/samples/` verify runtime behaviour in Splunk via the saved searches in `splunk/savedsearches/detection_validation.conf`, the detection is promoted to the production index, and the triage and investigation playbooks in `incident_response/playbooks/` are delivered alongside it so the SOC can act on alerts from day one.

---

**Q2. How do you measure detection quality?**

Detection quality has three dimensions: coverage, accuracy, and operability. Coverage is measured by ATT&CK technique mapping — how many of the relevant techniques for this environment have a detection. The MITRE ATT&CK coverage reports in `docs/detection_coverage/` track this across all 14 CDETs. Accuracy is measured by false positive rate and false negative rate: this project uses Splunk saved searches (`CDET-ValidatePositive-*` and `CDET-ValidateNegative-*`) to confirm detections fire on known-bad inputs and stay silent on known-good inputs. Operability is measured by whether on-call engineers can triage an alert in under 10 minutes: the four-file playbook structure in `incident_response/playbooks/` is designed around that constraint.

---

**Q3. What is a false positive rate and what is an acceptable threshold?**

The false positive rate is the proportion of alerts that turn out to be benign activity rather than actual threats. A high FP rate degrades analyst trust in the detection system — alert fatigue causes analysts to stop investigating or to dismiss alerts without proper review, which is how real incidents get missed. An acceptable threshold depends on the detection and the environment. For a high-severity detection like CDET-006 (root account activity), a false positive rate of near zero is expected because legitimate root account use should be functionally zero in a well-managed AWS account. For a detection like CDET-008 (excessive API enumeration), a higher FP rate from developers running automated scripts is acceptable as long as suppression is in place via the lookup tables. In this project, each detection's `false_positive_notes` field in `detection.yaml` documents the expected FP sources and the recommended suppression approach.

---

**Q4. How do you test a detection before deploying it to production?**

Testing in this project uses a three-tier model. The first tier is offline structural validation: `validation/validator.py` checks that the detection YAML contains all required fields, the SPL file is non-empty, and the test-case NDJSON files exist. This runs without a Splunk connection in seconds. The second tier is Splunk runtime validation: synthetic log samples in `data/samples/` are loaded into a separate `aws_cloudtrail_test` index, and the saved searches in `splunk/savedsearches/detection_validation.conf` run the production SPL against those samples. A positive validation search must return at least one event; a negative validation search must return zero events. The third tier is edge-case documentation in `detection.yaml` under `test_cases`, which includes at least one edge-case scenario per detection to confirm boundary conditions are handled correctly.

---

**Q5. What is tuning a detection?**

Tuning is the process of reducing false positives without introducing false negatives. In this project, tuning is operationalised through the lookup-based suppression system. When a detection fires on a legitimate principal — for example, a Terraform execution role creating an IAM user as part of a stack deployment — the response is to add that role's ARN to `splunk/lookups/approved_iam_principals.csv` with a documented reason and an optional expiry date, rather than modifying the SPL. This means tuning changes are auditable CSV edits rather than SPL code changes. The `CDET-ValidateNegative-*` saved searches provide ongoing regression testing: if a tuning change accidentally suppresses true positives, the positive validation search will start returning zero results and raise an alert.

---

## AWS Cloud Security

**Q6. What is AWS CloudTrail and what does it log?**

AWS CloudTrail is the audit logging service for AWS API activity. It records API calls made to AWS services — who made the call, from which IP address, to which service and action, with which parameters, and whether it succeeded or failed. CloudTrail is the primary data source for all 14 detections in this project. The ingestion approach is documented in `ingestion/cloudtrail_ingestion.md` and uses `boto3.client("cloudtrail").lookup_events()` to retrieve events. Every detection in this project keys on CloudTrail fields: `eventName`, `eventSource`, `userIdentity.arn`, `sourceIPAddress`, `awsRegion`, and `errorCode`.

---

**Q7. What is the difference between CloudTrail management events and data events?**

Management events record control-plane API calls: IAM user creation, CloudTrail configuration changes, EC2 instance launches, security group modifications. These are enabled by default in CloudTrail at no additional per-event cost and are the data source for all 14 detections in this project. Data events record data-plane API calls: S3 `GetObject`, S3 `PutObject`, Lambda `Invoke`, DynamoDB operations. Data events are disabled by default because the volume can be orders of magnitude higher than management events, and enabling them incurs additional CloudTrail cost. The `ingestion/cloudtrail_ingestion.md` documentation notes this distinction and explains that techniques like T1530 (Data from Cloud Storage) would require enabling S3 data events, which is identified as the next expansion of this project.

---

**Q8. How would you detect a compromised IAM credential?**

A compromised IAM credential will typically produce one or more observable signals in CloudTrail. In this project, four detections cover the most common patterns. CDET-008 detects excessive API enumeration — a compromised credential being used to discover what the account contains. CDET-007 detects EC2 instance metadata credential abuse — an attacker on a compromised EC2 instance using the IMDSv1 endpoint to steal the instance role's temporary credentials and then using them from an external IP. CDET-001 and CDET-002 detect a compromised credential being used to create persistence (a new IAM user or a second access key). Additionally, `sourceIPAddress` correlation — alerting when a known principal is seen from a new country or ASN — would be a signal layer to add on top of these detections.

---

**Q9. What AWS services does GuardDuty monitor?**

AWS GuardDuty is a managed threat detection service that analyses VPC Flow Logs, DNS logs, CloudTrail management events, CloudTrail S3 data events (when enabled), EKS audit logs, and RDS login activity. It applies AWS-maintained threat intelligence feeds and machine learning models to these sources to produce findings. In this project, GuardDuty is a secondary data source documented in `ingestion/guardduty_ingestion.md`. GuardDuty findings can validate or enrich CDET alerts: for example, a GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding would corroborate a CDET-007 alert about instance metadata credential abuse.

---

**Q10. What is the MITRE ATT&CK framework and how do you use it?**

MITRE ATT&CK is a structured knowledge base of adversary tactics and techniques observed in real-world attacks. Tactics represent the adversary's goal (persistence, privilege escalation, exfiltration); techniques represent the specific method used to achieve it. In this project, ATT&CK serves two purposes. At design time, it was the framework used to select which 14 techniques to detect, ensuring kill-chain coverage from initial access through impact. At runtime, every detection in `detection.yaml` carries a `technique` field (e.g., `T1136.003`) and every alert produced by the detection carries `tactic` and `technique` fields in the Splunk output. The `scripts/alert_enrichment.py` enrichment pipeline injects the full ATT&CK context — technique name, tactic, and URL — into every alert from the `_ATTACK_CONTEXT` dictionary without requiring an external API call.

---

## Splunk / SIEM

**Q11. What is a Splunk saved search?**

A Splunk saved search is a stored SPL query with associated scheduling, alerting, and dispatch configuration. In this project, saved searches serve two roles. Production detections run as scheduled searches on the `aws_cloudtrail` index every 15 minutes (per `cron_schedule` in `detection.yaml`). Validation searches in `splunk/savedsearches/detection_validation.conf` run daily against the `aws_cloudtrail_test` index to confirm detections behave as expected. The stanza format in `.conf` files includes the `search` field (the SPL), `cron_schedule`, `dispatch.earliest_time`, `dispatch.latest_time`, `enableSched`, and `description`.

---

**Q12. How do you join data from a lookup table in SPL?**

The `lookup` command in SPL performs a left outer join between the search results and a CSV-based lookup table. The syntax is `| lookup <table_name> <event_field> AS <lookup_key_field> OUTPUT <output_field>`. In CDET-001's SPL, the call `| lookup approved_iam_principals arn AS principal_arn OUTPUT approved, suppression_reason` matches each event's `principal_arn` field against the `arn` column in `approved_iam_principals.csv` and writes the corresponding `approved` value back into the event. If no match is found, `approved` is null. The subsequent `| where isnull(approved)` filter keeps only events where the principal was not found in the approved list — that is, only potentially unauthorized actors. Two lookup joins are used in CDET-001: one for approved principals and one for automation roles, with a combined suppression condition covering both.

---

**Q13. What is a Splunk index and why do you separate data into different indexes?**

A Splunk index is a named storage partition for event data. Separating data into indexes serves three purposes: access control (different teams can be granted read access to different indexes), retention management (raw CloudTrail data might be retained for 90 days while validated alert data is retained for a year), and search performance (a detection-focused search against `aws_cloudtrail` does not scan the `cdet_alerts` or `cdet_validation_results` indexes). This project uses three indexes: `aws_cloudtrail` for production log data, `aws_cloudtrail_test` for synthetic validation data so test searches never contaminate production results, and `cdet_alerts` for the structured alert output written by each detection. The validation saved search `CDET-ValidationRunSummary` queries `cdet_validation_results` to produce a weekly pass-rate report.

---

**Q14. How do you extract fields from JSON in Splunk?**

Splunk's `spath` command extracts fields from nested JSON. For a CloudTrail event where `userIdentity.arn` is a nested key, `| spath input=_raw path=userIdentity.arn output=principal_arn` writes the nested value into a new field. In this project the detections use `coalesce` in `eval` statements to normalise across field name variants: `eval principal_arn=coalesce('userIdentity.arn', "unknown")`. When the Splunk sourcetype is configured with `KV_MODE=json`, Splunk auto-extracts all JSON keys at index time, making them directly referenceable in SPL as `'userIdentity.arn'` without requiring `spath`. The detection field requirements in `detection.yaml` under `required_fields` document which JSON paths each detection depends on.

---

## Incident Response

**Q15. What is the first thing you do when an alert fires?**

The first action is triage: determine whether the alert is a true positive or a false positive before taking any response action. In this project, the triage playbook for each detection (the first of the four playbook files in `incident_response/playbooks/`) provides three to five specific Splunk queries to run within the first 10 minutes. The triage output is a binary decision: escalate as a true positive, or close as a false positive with a documented suppression action (updating the appropriate CSV in `splunk/lookups/`). No containment actions are taken until triage confirms a true positive. This ordering prevents accidentally disabling a legitimate principal based on a misfire.

---

**Q16. What is the difference between containment and recovery?**

Containment stops the bleeding: it prevents the attacker from causing additional damage without necessarily restoring normal operations. Recovery restores affected systems to a known-good state. For a CDET-001 alert (unauthorized IAM user creation), containment means disabling the created IAM user and revoking any active sessions for the actor who created it. Recovery means reviewing all actions taken by the created user since creation, determining whether any resources were modified, and restoring them to their pre-incident state. The containment playbook file includes explicit approval gates before any destructive action (disabling the user) because that action may interrupt legitimate workflows if triage was incorrect. The recovery playbook describes the rollback steps and how to verify that no additional persistence mechanisms were established.

---

**Q17. How do you decide whether to escalate an incident?**

Escalation criteria in this project are defined per detection in the triage playbook file. The primary escalation triggers are severity (any `critical` severity alert bypasses Tier-1 triage and goes directly to senior on-call), blast radius (if the alert indicates impact to multiple accounts, regions, or services), and detection chain correlation (if two or more detections fire for the same actor ARN within a short window, escalation is automatic — a single technique might be a misconfiguration, but a kill chain is an active incident). The `scripts/alert_enrichment.py` severity escalation logic also assists: CDET-001 alerts where `mfa_used=no` are automatically escalated from `high` to `critical` at enrichment time, which shifts the escalation decision from a manual analyst judgment to an automated rule.

---

## Python / Automation

**Q18. How do you authenticate to AWS in Python without hardcoding credentials?**

All AWS authentication in this project uses the boto3 default credential chain exclusively. `boto3.Session()` with no arguments resolves credentials in this order: environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), the `~/.aws/credentials` file populated by `aws configure`, EC2 instance metadata role, and ECS task role. No credentials are ever passed as constructor arguments or stored in code or configuration files. `scripts/alert_enrichment.py` enforces this design: the `AlertEnricher` class accepts an optional pre-constructed `boto3.Session` but never accepts credential values. This is documented as a non-negotiable constraint in the project's `SECURITY.md` and in the AWS credential rules in the project memory.

---

**Q19. What is boto3 and what can you do with it?**

boto3 is the AWS SDK for Python. It provides a client interface to every AWS service API. In this project, boto3 is used in four contexts: `boto3.client("cloudtrail").lookup_events()` in the ingestion layer to retrieve CloudTrail management events; `boto3.client("iam").get_user()`, `list_access_keys()`, `list_mfa_devices()`, and `list_attached_user_policies()` in `scripts/alert_enrichment.py` to enrich alerts with live IAM state; `boto3.client("sts").assume_role()` as the pattern documented for multi-account expansion; and `boto3.client("guardduty")` in the GuardDuty ingestion layer. boto3 also provides the `botocore.exceptions.ClientError` exception class, which the enrichment pipeline catches to distinguish between expected errors (principal not found) and unexpected errors (permission denied), handling each differently rather than failing the entire enrichment.

---

**Q20. How would you automate the generation of an incident report?**

An incident report requires structured data from three sources: the enriched alert (what fired, when, with what severity), the investigation timeline (what actions were taken and when), and the outcome (true positive or false positive, what was contained, what was recovered). In this project the foundation is already in place. `scripts/alert_enrichment.py` produces a structured `EnrichedAlert` dataclass with ATT&CK context, severity, IAM state, and recommended queries in a dict-serialisable format via `to_dict()`. An automated report generator would consume that output, add a timestamp log of analyst actions from the incident ticket, and render the combination into a report template. The `reports/` directory in this project is the designated output location for such artefacts. The key design principle is that report generation must be non-blocking: if the IAM enrichment API call fails, `enrichment_errors` captures the failure gracefully and the report is generated with the available data rather than blocking on a failed API call.
