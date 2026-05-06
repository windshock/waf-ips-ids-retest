# docker-coraza-waf-lab

White-box WAF lab for TC-27 multipart grammar differential testing.

Architecture based on:
- HacktronAI vercel-waf-env: https://github.com/HacktronAI/skills/tree/main/environments/vercel-waf-env
- React2Shell bypass research: https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass

```
Probe script → Coraza WAF :9091 → Echo backend :3009
                    ↑
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
| `backend` | 3009 | Python echo server — returns parsed fields + raw body hex |
| `executor` | 8009 | Flask server — runs sandboxed Python probe code, returns WAF logs |

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

- `docker-compose.yml` — service definitions (waf, backend, executor)
- `waf/main.go` — Go Coraza reverse proxy
- `waf/coraza.conf` — detection rules (read this to design bypasses)
- `waf/Dockerfile` — multi-stage Go build
- `backend/echo_server.py` — Python echo server (returns JSON with headers, parsed fields, raw body hex)
- `executor/server.py` — Flask executor for in-network probe code execution

## WAF rules (white-box)

Read `waf/coraza.conf` before designing bypass variants. It documents
the 5 grammar un-equivalence gaps from the React2Shell article inline.

## Interpreting results

Compare WAF responses vs backend-direct responses:

| WAF result | Backend-direct | Interpretation |
|---|---|---|
| 403 | 200 with probe in `parsed_fields` | WAF detected correctly |
| 200 (no probe echo) | 200 with probe | WAF passed without detection — bypass or fail-open |
| 200 (probe echoed) | 200 with probe | WAF not inspecting this variant |
| 400/500 | 200 | WAF or backend rejected malformed request |

`failopen_signal=fail-open-confirmed-non-utf8-passed` in `summary.csv`
means the `non_utf8_header_byte` variant passed — check `raw_body_hex`
in the echo response to confirm the payload arrived intact.
