# Handoff Consistency Check

Run these checks before finalizing the SOC handoff. The goal is to catch duplicate findings, missing rows, attribution drift, and parser-differential overclaims.

## 1. Duplicate Key Findings

`soc_handoff.md` Key Findings must not contain duplicates.

```bash
grep "^- " artifacts/soc_handoff.md | sort | uniq -d
```

Empty output is a pass. Any duplicated line must be removed or merged.

## 2. CSV and Handoff Row Count Match

The row count claimed in `soc_handoff.md` must match the actual data rows in `combined_evidence.csv`.

```bash
CSV_ROWS=$(($(wc -l < artifacts/combined_evidence.csv) - 1))
CLAIMED=$(grep "Row Count:" artifacts/soc_handoff.md | grep -o '[0-9]*')
[ "$CSV_ROWS" -eq "$CLAIMED" ] && echo "PASS" || echo "FAIL: CSV=$CSV_ROWS, claimed=$CLAIMED"
```

## 3. Query Windows Cover All Timestamps

Every timestamp in the CSV must fall inside the Query Windows written in `soc_handoff.md`.

```python
import csv
from collections import defaultdict

rows = defaultdict(list)
with open("artifacts/combined_evidence.csv") as f:
    for r in csv.DictReader(f):
        rows[r["protocol"]].append(r["timestamp"])

for proto in sorted(rows):
    ts = sorted(rows[proto])
    print(f"{proto}: {ts[0]} ~ {ts[-1]} ({len(ts)} rows)")
```

Compare the output with the Query Windows section.

## 4. Coverage Matrix Is Complete

`coverage_matrix.md` must include:

- TC-01 through TC-27 when those rows are in scope
- every non-TC helper category that appears in the CSV, such as `BODY-DETECTION`, `SCHEME-PARITY`, `MULTIPART-PARSER`, or `MULTIPART-H2-DOWNGRADE`

```bash
awk -F',' 'NR>1 {print $3}' artifacts/combined_evidence.csv | sort -u
```

Compare the unique `tc` values with `coverage_matrix.md`.

## 5. Finding Transport Attribution Exists

Every finding in `execution_summary.json` must state which transport observed it: `HTTP`, `HTTPS`, `both`, or a more specific protocol label. HTTPS-only rows without inspection visibility remain `visibility-limited`.

## 6. Meta and Markdown Finding Counts Match

`soc_handoff_meta.json` `high_level_findings` count must match the Key Findings bullet count in `soc_handoff.md`.

```bash
META_COUNT=$(python3 -c "import json; print(len(json.load(open('artifacts/soc_handoff_meta.json'))['high_level_findings']))")
HANDOFF_COUNT=$(grep -c "^- " artifacts/soc_handoff.md)
echo "meta=$META_COUNT handoff=$HANDOFF_COUNT"
```

## 7. Parser Differential Backend Evidence Exists

For `TC-27`, `MULTIPART-PARSER`, `MULTIPART-H2-DOWNGRADE`, or any finding that uses parser-differential or bypass language, WAF/IPS logs are not enough. The handoff must include backend-side evidence for the same variant:

- `backend_response_path`, `backend_log_path`, or an equivalent origin artifact path
- `parsed_fields`, selected backend value, or application-consumed value
- `backend_probe_seen=yes|no|unknown`

Fail the handoff check if a parser bypass finding has only WAF/IPS/IDS evidence. If the probe is present only in raw body, epilogue, trailing bytes, or body hex, downgrade the finding to `WAF inspection gap` or `not exploitable against this backend parser`.

## When To Run

Run these checks immediately after Phase 6 (SOC Handoff) artifacts are generated and before the report is finalized.

## Automation

Future work can merge these checks into `scripts/validate_handoff_consistency.py` and call it after `render_soc_handoff.py`.
