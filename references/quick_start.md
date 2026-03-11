# Quick Start

Use this path when you want the fastest first successful run.

## 1. Copy the sample inputs

- `assets/examples/profile.example.yaml`
- `assets/examples/run-config.example.yaml`

Adjust at least these fields before running:

- target `name`
- `domains`
- `critical_endpoints`
- `source_ip`
- `callback_domain`
- `marker_prefix`

## 2. Validate readiness

```bash
python3 scripts/prereq_validator.py \
  --profile assets/examples/profile.example.yaml \
  --run-config assets/examples/run-config.example.yaml
```

If the output shows `blocked`, fix the prerequisite instead of using a weaker fallback.

## 3. Generate a run manifest

```bash
python3 scripts/generate_run_manifest.py \
  --profile assets/examples/profile.example.yaml \
  --run-config assets/examples/run-config.example.yaml \
  --output ./run_manifest.md \
  --json-out ./run_manifest.json
```

See `assets/examples/run_manifest.example.md` for the expected shape.

## 4. Run one probe family

Examples:

- canonicalization:

```bash
python3 scripts/run_tc17_canonical_probe.py \
  --url https://api.example.com/ \
  --output-dir ./tc17
```

- oversize:

```bash
python3 scripts/run_tc12_oversize_probe.py \
  --url https://api.example.com/v1/search \
  --output-dir ./tc12
```

- lax JSON:

```bash
python3 scripts/run_tc15_lax_json_probe.py \
  --url https://api.example.com/v1/submit \
  --output-dir ./tc15
```

## 5. Normalize and hand off

```bash
python3 scripts/merge_normalize_csv.py \
  --input-spec ./tc17/summary.csv::HTTPS \
  --input-spec ./tc12/summary.csv::HTTPS \
  --output ./combined.csv

python3 scripts/render_soc_handoff.py \
  --metadata ./run_manifest.json \
  --csv ./combined.csv \
  --output ./soc_handoff.md
```

See:

- `assets/examples/combined.example.csv`
- `assets/examples/soc_handoff.example.md`
