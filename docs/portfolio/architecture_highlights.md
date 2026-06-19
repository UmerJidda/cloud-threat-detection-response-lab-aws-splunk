# Architecture Highlights: Cloud Threat Detection Lab

A technical reference for the non-obvious design decisions in this repository. Intended for technical interviewers and hiring engineers who want to understand the reasoning behind implementation choices, not just enumerate what was built.

---

## Design Principle: Detection as Code

Detection rules in this repository are treated as software artifacts, not search strings.

Each detection has a YAML specification (`detection.yaml`) that is the authoritative definition: ATT&CK mapping, required data source fields, suppression lookup references, test case expectations, and a pointer to the response playbook. The YAML is machine-readable — a CI/CD pipeline could parse it to verify that every required lookup exists, that every test case file is present, and that the detection ID is unique. That pipeline does not exist in this lab (see "What Would Be Different in Production"), but the structure supports it.

The SPL rule (`detection.spl`) is a separate file in the same directory, not embedded in the YAML. This matters because SPL and metadata have different change cadences: ATT&CK technique refinements update the YAML without touching SPL; SPL tuning updates the rule without changing metadata. Keeping them as sibling files in version control means both are tracked, diffable, and reviewable independently.

The Python validator (`scripts/detection_validator.py`) implements the detection logic a third time, as a Python function. This is deliberately redundant. The purpose is to create a property that can be tested offline: given these events, does this logic fire? Given these other events, does it stay silent? The validator runs against the three-tier NDJSON test set (malicious, benign, edge_case) as a pre-ingestion quality gate. A detection that passes Python validation has demonstrated its trigger conditions and suppression conditions are both correctly specified before it enters Splunk.

The result is test-driven detection development: write the YAML specification with test cases, write the test NDJSON files, write the Python validator, confirm all three test tiers pass, then write the SPL knowing the logic is already verified.

---

## Design Principle: Credential Security

All nine AWS collector modules in `scripts/aws_collectors/` use the boto3 default credential chain. The pattern appears consistently:

```python
class AlertEnricher:
    def __init__(
        self,
        session: boto3.Session | None = None,
        lookups_dir: Path | None = None,
    ) -> None:
        self._session = session or boto3.Session()
```

`boto3.Session()` with no arguments resolves credentials in this order: environment variables → AWS credentials file (`~/.aws/credentials`) → instance profile → container credential provider. In practice this means the developer runs `aws configure` once and every script works. There are no `.env` files, no `AWS_ACCESS_KEY_ID` assignments, no hardcoded credential strings anywhere in the codebase.

This is not just good hygiene for a portfolio project. It mirrors the pattern required in production environments where static long-lived credentials are prohibited. A developer habit of always using the default chain transfers directly to deploying these collectors on EC2 (instance profile), in Lambda (execution role), or in a container (task role). The code does not change; the credential source changes based on where the code runs.

The optional `session` parameter in constructors serves a second purpose: testability. Tests can inject a `botocore.stub.Stubber`-backed session to exercise enrichment logic without live AWS calls, without any test-specific credential handling.

---

## Design Principle: Layered Suppression

The suppression model is deliberately implemented at two independent layers.

**Layer 1: SPL lookup joins at detection time.** Every identity-based rule (CDET-001 through CDET-006, CDET-011, CDET-012) applies two lookup joins before any events reach analysts:

```spl
| lookup approved_iam_principals arn AS principal_arn OUTPUT approved
| lookup automation_role_arns arn AS principal_arn OUTPUT approved AS auto_approved
| eval suppressed=if(approved="true" OR auto_approved="true", "true", "false")
| where suppressed!="true"
```

The split into two lookups reflects a real operational distinction. `approved_iam_principals.csv` holds human-readable ARNs of specific principals that are explicitly approved. `automation_role_arns.csv` holds role ARNs for CI/CD and automation systems where the immediate acting identity will be an AssumedRole session with a different ARN than the role itself. The rule also checks `session_issuer_arn` against `approved_iam_principals` to catch this second-hop case.

**Layer 2: Python `_is_approved()` at validation time.** `scripts/detection_validator.py` loads the same two CSVs at module level and applies the same check in `_is_approved()`:

```python
def _is_approved(event: ParsedEvent) -> bool:
    arn = event.identity_arn or ""
    issuer = event.session_issuer_arn or ""
    return (
        arn in _APPROVED_PRINCIPALS
        or issuer in _APPROVED_PRINCIPALS
        or any(issuer.endswith(r.split("/")[-1]) for r in _AUTOMATION_ROLES if r)
        or issuer in _AUTOMATION_ROLES
    )
```

The two layers serve different purposes and catch different failure modes. If the SPL lookup is misconfigured — wrong column name, stale CSV, incorrect join key — the Python validator will still suppress correctly against the same test data, and the discrepancy between Python results and Splunk results becomes the diagnostic signal. If the Python logic has a bug, Splunk is unaffected. Neither layer is a fallback for the other; they are parallel implementations of the same specification.

Critically, suppression is data, not logic. To add a new IaC pipeline to the suppression list, an operator updates `approved_iam_principals.csv` and commits it. No SPL is modified. No Python is modified. The detection logic remains unchanged; only the operational data changes. This separation is essential in production environments where detection code is under change control but operational suppression lists need to be updated frequently by people who do not write SPL.

---

## Design Principle: Separation of Concerns

Each component in the pipeline has exactly one job.

| Component | Single Responsibility |
|---|---|
| `scripts/aws_collectors/*.py` | Get data from an AWS API and return it normalized | 
| `scripts/cloudtrail_parser.py` | Accept raw CloudTrail JSON in any format and return `ParsedEvent` objects |
| `scripts/detection_validator.py` | Given events and a detection ID, return `ValidationResult` |
| `scripts/ioc_extractor.py` | Given events or an alert dict, return an `IoCReport` |
| `scripts/alert_enrichment.py` | Given a raw alert dict, return an `EnrichedAlert` with ATT&CK, IAM, and severity context |
| `scripts/incident_report_generator.py` | Given an `EnrichedAlert` and events, produce three audience-specific report formats |
| `playbooks/CDET-*/` | Tell a human analyst what to do at each response phase |

The consequence of this separation is that each component can be tested, replaced, or extended independently. `cloudtrail_parser.py` does not know anything about detection logic. `detection_validator.py` does not know anything about incident reports. `incident_report_generator.py` does not call AWS. This is the architecture that allows a future CI/CD pipeline to run the validator, then run enrichment, then generate reports, without any component needing to be modified to fit into an automated workflow.

The data flow is a linear pipeline: raw CloudTrail JSON → `ParsedEvent` → detection validation → alert dict → `EnrichedAlert` → `IncidentReport`. Each stage consumes the output of the previous stage through a typed interface. No stage reaches back into an earlier stage's raw data.

---

## Interesting Technical Choices

### 1. Why NDJSON (not JSON arrays) for sample data

CloudTrail delivers log files as JSON arrays (`{"Records": [...]}`) but the sample test data uses NDJSON — one JSON object per line. This is intentional. NDJSON is stream-compatible: a single event can be appended to a test file with `>>` without parsing and rewriting the entire array. It is also trivially splittable: each line is self-contained, so a test can read only lines 1-3 without buffering the file. When `cloudtrail_parser.py` needs to support both formats (for the collector that reads real CloudTrail files), it detects format by attempting line-by-line parse first and falling back to array parse. The test data being NDJSON does not constrain the parser's ability to handle real CloudTrail format.

### 2. Why `detection_validator.py` mirrors SPL rather than testing SPL directly

The alternative — running SPL queries against a local Splunk instance in a test environment — requires a running Splunk instance, appropriate index configuration, and data onboarding. That is a significant infrastructure dependency for what is essentially a logic test. The Python mirror allows the detection logic to be tested in a standard `pytest` run with no external dependencies. The tradeoff is that the Python and SPL implementations can diverge if one is updated without the other. In a production environment this is mitigated by running both: Python tests as a fast offline gate, Splunk functional tests against a staging environment before promotion to production.

### 3. Why `ValidationResult.passed` is a property rather than a status field

```python
@property
def passed(self) -> bool:
    return self.should_fire == self.fired
```

Making `passed` a computed property rather than a stored field eliminates an entire class of inconsistency bugs. If `passed` were set at construction time alongside `should_fire` and `fired`, it would be possible to construct a `ValidationResult` where `passed=True` but `should_fire=False` and `fired=True` — a logically inconsistent object. As a property, `passed` is always the correct boolean consequence of the two source-of-truth fields. The same pattern applies to `summary`: it is a property that derives its text from the current state of the object, not a string set at construction time.

### 4. Why `IoCExtractor` skips RFC 5737 TEST-NET ranges

`scripts/ioc_extractor.py` excludes `192.0.2.0/24` (TEST-NET-1), `198.51.100.0/24` (TEST-NET-2), and `203.0.113.0/24` (TEST-NET-3) from its external IP indicator list, alongside RFC 1918 private ranges. The test data throughout this repository uses addresses from these ranges — `198.51.100.77` appears repeatedly as the attacker source IP in sample events. If the extractor did not exclude TEST-NET ranges, running IOC extraction against the sample data would produce a list of TEST-NET addresses as "external indicators," which would be noise in any real investigation workflow. The exclusion list is documented in the `_PRIVATE_NETWORKS` class attribute with an explicit RFC 5737 comment so the reason is visible to anyone reading the code.

### 5. Why `IncidentReportGenerator.generate()` accepts an optional `report_time` parameter

```python
def generate(
    self,
    enriched: EnrichedAlert,
    events: list[ParsedEvent] | None = None,
    report_time: datetime | None = None,
) -> IncidentReport:
    ts = (report_time or datetime.now(timezone.utc)).isoformat()
```

A function that calls `datetime.now()` internally is non-deterministic: the same inputs produce different outputs depending on when the function is called. This makes output testing difficult — any test that checks report content would need to mock the system clock. By accepting `report_time` as an optional parameter, the default behavior (current time) is preserved for production use while tests can inject a fixed timestamp and assert exact output. The example in the module's `__main__` block passes `report_time=datetime(2024, 1, 15, 14, 2, 11, tzinfo=timezone.utc)` to produce deterministic output.

---

## What Would Be Different in Production

This lab is a portfolio demonstration, not a production deployment. The following is an honest assessment of what is missing and how the current architecture supports adding it.

**No live Splunk instance.** All detection validation is offline via the Python heuristic mirror. In production, Splunk saved searches would run on schedule, and functional tests would be run against a Splunk staging environment using the Splunk SDK. The YAML `test_cases` blocks in each `detection.yaml` are structured to feed a Splunk test runner — `input_file`, `expected_alert`, `expected_fields` — but the runner itself is not implemented.

**No real AWS account.** The AWS collector modules are production-quality code, but they run against sample NDJSON data rather than live CloudTrail events. In production, the collectors would run on a schedule against a real account, and the enrichment pipeline would call live IAM APIs to get principal context. The credential chain pattern means this transition requires zero code changes — only `aws configure` with production credentials.

**No CI/CD pipeline running detection tests.** In production, every commit to a detection rule would trigger the Python validator against the associated test files, fail the pull request if any test tier fails, and gate promotion to the Splunk production environment on passing tests. The test structure (three-tier NDJSON, `ValidationResult.passed`, YAML test case specs) is designed to support this pipeline; the pipeline itself is out of scope for a portfolio project.

**No SOAR integration.** The `response_actions` block in `detection.yaml` references Splunk Adaptive Response actions for notification. In production, these would trigger a SOAR platform (Splunk SOAR, Palo Alto XSOAR) to execute containment steps automatically: disabling the IAM user, revoking the session, notifying the security team. The playbook markdown files document what those automations would do; the automations themselves are not wired up.

**No threat intelligence feed enrichment.** `alert_enrichment.py` enriches source IPs with context from the local suppression lookups but does not query a threat intel feed (VirusTotal, Shodan, an internal TIP) for reputation data. In production, the enrichment pipeline would call a TIP API and attach a `threat_intel_hits` field to the `EnrichedAlert`. The `EnrichedAlert` dataclass has open field slots and an `enrichment_errors` list designed to accommodate additional enrichment layers without structural changes.
