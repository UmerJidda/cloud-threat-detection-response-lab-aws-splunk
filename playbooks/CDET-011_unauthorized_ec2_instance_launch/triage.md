---
detection_id: CDET-011
detection_name: Unauthorized EC2 Instance Launch
tactic: Impact
technique: T1496
last_updated: 2026-06-18
---

# CDET-011 — Triage Playbook

**Time target:** Complete within 5–10 minutes of alert receipt.

---

## 1. Confirm Alert Integrity

1. Open the alert in your SIEM/Splunk and note the `eventTime`, `sourceIPAddress`, `userIdentity.arn`, and `requestParameters.instanceType`.
2. Verify the alert fired against **production data** — confirm the Splunk index is `aws_cloudtrail` (not a test or staging index).
3. Check whether the originating account ID matches a known test or sandbox account. Cross-reference `splunk/lookups/aws_accounts.csv`.
   - If the account is tagged `env=sandbox` or `env=dev`, treat with lower urgency but do **not** auto-close — proceed to Step 4.

---

## 2. Validate the Actor Identity

4. Extract `userIdentity.arn` from the CloudTrail event.
5. Look up the ARN in `splunk/lookups/known_service_accounts.csv`.
   - **PASS (likely FP):** ARN is a documented CI/CD pipeline role or auto-scaling service account, and the `instanceType` matches expected pipeline activity.
   - **FAIL (escalate):** ARN is not in the lookup, belongs to a human IAM user, or is an assumed-role session with an unfamiliar role name.
6. Look up the `sourceIPAddress` in `splunk/lookups/approved_ips.csv`.
   - **PASS:** IP is a known corporate egress or VPN range.
   - **FAIL:** IP is residential, foreign, Tor exit node, or a cloud provider IP outside your known automation footprint.

---

## 3. Check Alert Context Fields

Review these fields in the raw CloudTrail event before making an urgency decision:

| Field | What to look for |
|---|---|
| `userIdentity.type` | `AssumedRole` from an unexpected role is high risk |
| `userIdentity.sessionContext.sessionIssuer.arn` | Should match an approved role in `known_service_accounts.csv` |
| `requestParameters.instanceType` | GPU/compute-heavy types (e.g., `p3`, `p4`, `g4dn`) strongly suggest crypto-mining (T1496) |
| `requestParameters.imageId` | Unknown or public AMI IDs warrant deeper scrutiny |
| `requestParameters.maxCount` | Launching large counts (>2) outside a known ASG is suspicious |
| `requestParameters.iamInstanceProfile` | Instance profile grants lateral movement potential |
| `awsRegion` | Regions not in your org's approved regions list are high risk |
| `errorCode` | If present, the action failed — still investigate the attempt |

---

## 4. Urgency Determination

**Escalate immediately if ANY of the following are true:**

- Actor ARN is not in `known_service_accounts.csv`
- `instanceType` is GPU-class (p2, p3, p4, g4dn, g5)
- `awsRegion` is outside approved regions (see `splunk/lookups/approved_regions.csv`)
- `sourceIPAddress` is flagged in threat intelligence feeds
- More than one `RunInstances` event from the same actor within 10 minutes

**Downgrade to standard investigation (no immediate escalation) if ALL of the following are true:**

- Actor is a known service account in `known_service_accounts.csv`
- Instance type matches documented automation patterns
- Region is approved
- IP is in `approved_ips.csv`

---

## 5. PASS / FAIL Criteria

| Outcome | Criteria | Action |
|---|---|---|
| **Real Alert — Escalate** | Unknown actor, GPU instance, unapproved region, or threat-intel IP hit | Escalate to Tier-3 / IR lead; open incident ticket; proceed to `investigation.md` |
| **Benign FP** | All actor, IP, region, and instance-type checks pass against lookups | Document rationale; suppress for this specific pipeline role if recurrent; close alert |
| **Inconclusive** | Some checks pass, some fail | Treat as real alert; proceed to `investigation.md` |

---

## 6. Applicable Lookup CSVs

| Lookup file | Purpose |
|---|---|
| `splunk/lookups/aws_accounts.csv` | Maps account IDs to environment and owner |
| `splunk/lookups/known_service_accounts.csv` | Approved IAM roles and users for automation |
| `splunk/lookups/approved_ips.csv` | Known corporate / VPN egress ranges |
| `splunk/lookups/approved_regions.csv` | Regions approved for EC2 workloads |

---

## 7. Triage Output

Document the following before moving to investigation:

- [ ] Alert is real (not test data)
- [ ] Actor ARN identified and lookup result recorded
- [ ] Source IP lookup result recorded
- [ ] Region and instance type noted
- [ ] Urgency decision made (Escalate / Standard / FP)
- [ ] Incident ticket number assigned (if escalating)
