# docker-coraza-waf-lab

White-box WAF lab for TC-27 multipart grammar differential testing.

Architecture based on:
- HacktronAI vercel-waf-env: https://github.com/HacktronAI/skills/tree/main/environments/vercel-waf-env
- React2Shell bypass research: https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass

```
Probe script -> Coraza WAF :9091 -> busboy backend :3009
                    ^
          Executor :8009 (optional: run probe code via API)
```

## Why white-box matters

Black-box WAF testing burns tokens on guessing. This lab exposes
`waf/coraza.conf` so Claude can read the detection logic,
identify grammar un-equivalence gaps, and design targeted bypass variants.

## Services

| Service | Port | Purpose |
|---|---|---|
| `waf` | 9091 | Coraza WAF proxy (Go-based, custom build) |
| `backend` | 3009 | Node.js busboy backend - returns parsed fields + raw body hex |
| `executor` | 8009 | Flask server - runs sandboxed Python probe code, returns WAF logs |

## Usage

```bash
# Start the lab
docker compose up -d

# Run TC-27 probes against the WAF
python scripts/run_tc27_multipart_probe.py \
  --url http://localhost:9091/ \
  --output-dir /tmp/tc27_results

# Run probes directly against the backend (control: no WAF)
python scripts/run_tc27_multipart_probe.py \
  --url http://localhost:3009/ \
  --output-dir /tmp/tc27_backend_baseline

# Or use the executor to run probe code inside the lab network
curl -s http://localhost:8009/execute \
  -H "Content-Type: application/json" \
  -d '{"code": "import requests, os\nprint(requests.get(os.environ[\"WAF_URL\"]).status_code)"}'

# Stop the lab
docker compose down
```

## Files

- `docker-compose.yml` - service definitions (waf, backend, executor)
- `waf/main.go` - Go Coraza reverse proxy
- `waf/coraza.conf` - detection rules (read this to design bypasses)
- `waf/Dockerfile` - multi-stage Go build
- `backend/server.js` - Node.js busboy backend (returns JSON with headers, parsed fields, raw body hex)
- `backend/package.json` - backend dependencies
- `executor/server.py` - Flask executor for in-network probe code execution

## WAF rules (white-box)

Read `waf/coraza.conf` before designing bypass variants. It documents
the 5 grammar un-equivalence gaps from the React2Shell article inline.

## Interpreting results

Compare WAF responses vs backend-direct responses:

| WAF result | Backend-direct | Interpretation |
|---|---|---|
| 403 | 200 with probe in `parsed_fields` | WAF detected correctly |
| 200 | 200 with probe in `parsed_fields` | Bypass candidate or fail-open, depending on the baseline and rule path |
| 200 | 200 with safe parsed field and probe only in `raw_body_hex` | WAF inspection gap, not exploitable against this backend parser |
| 200 | 200 with empty `parsed_fields` or parser error | WAF fail-open or malformed request; not a bypass unless the target backend consumes equivalent data |
| 400/500 | 200 with probe in `parsed_fields` | Fail-closed or lab error on the WAF path; no bypass through the WAF path |

`failopen_signal=fail-open-confirmed-non-utf8-passed` in `summary.csv`
means the `non_utf8_header_byte` variant passed. Check backend `parsed_fields`
first, not only `raw_body_hex`, before calling the result a bypass.

Never rely on WAF logs alone for TC-27. A bypass verdict requires both a
control-side miss/pass and backend-side parsed-field or application-log evidence
for the same request variant.
