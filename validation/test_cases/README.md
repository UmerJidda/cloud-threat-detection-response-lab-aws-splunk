# Validation Test Cases

One directory per detection. Each contains:

| File | Purpose |
|------|---------|
| `expected_alert.json` | All fields the Splunk alert must output |
| `positive_case.md` | What malicious input triggers the detection |
| `negative_case.md` | What suppressed/benign input must NOT fire |
| `edge_case.md` | Boundary conditions and partial-suppression scenarios |
| `checklist.md` | Promotion gate — all items must pass before Active status |
