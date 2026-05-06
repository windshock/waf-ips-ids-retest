# Multipart Parser Differentials

Use this helper when the retest question is whether a WAF, proxy, or backend parses
`multipart/form-data` differently. This is a parser-differential calibration step,
not a React2Shell or framework exploit runner.

## Why this exists

Multipart requests have several independent grammars:

- top-level `Content-Type` parameter parsing
- boundary matching and line-ending handling
- data before or after boundary markers
- per-part `Content-Disposition` and `Content-Type`
- duplicate part headers
- charset decoding inside part bodies

The helper tests whether a control sees the same payload that the backend sees.
If the target path uses HTTP/2, keep the result separate from HTTP/1.1 because the
finding may be an HTTP/2 downgrade or proxy-normalization issue rather than only a
multipart parser issue.

## Docker Lab

The lab is intentionally small:

- `lab-waf`: parses multipart with a limited WAF-like view and blocks the inert attack marker only when it appears in parsed values
- `lab-backend`: parses multipart with a more tolerant backend-like view and echoes parsed fields
- `lab-h2-edge`: TLS HTTP/2 edge that proxies to `lab-waf`, for optional HTTP/2-to-HTTP/1.1 downgrade calibration

Run:

```bash
scripts/docker_multipart_parser_lab.sh up
scripts/docker_multipart_parser_lab.sh probe ./multipart-lab-out
scripts/docker_multipart_parser_lab.sh logs ./multipart-lab-out
scripts/docker_multipart_parser_lab.sh down
```

The wrapper writes:

- `./multipart-lab-out/waf`: HTTP/1.1 probes through the lab WAF
- `./multipart-lab-out/backend`: HTTP/1.1 probes directly to the backend
- `./multipart-lab-out/h2-edge`: HTTP/2 probes through the lab edge and WAF

On Docker Desktop or WSL-style environments, the wrapper automatically prefers
`host.docker.internal` for raw socket probes when it is available. Override with
`LAB_CONNECT_HOST=127.0.0.1` or another host if your Docker networking requires it.

## Direct Runner

Use the direct runner against an approved target only after the request path is safe
to exercise:

```bash
python3 scripts/run_multipart_parser_probe.py \
  --url https://api.example.com/upload \
  --output-dir ./multipart-parser \
  --field-name probe
```

Optional HTTP/2 path:

```bash
python3 scripts/run_multipart_parser_probe.py \
  --url https://api.example.com/upload \
  --output-dir ./multipart-parser-h2 \
  --transport h2 \
  --field-name probe
```

The default `--attack-value` is the inert marker
`__RETEST_MULTIPART_ATTACK_MARKER__`. Do not replace it with an exploit payload
unless the target owner explicitly approved that exact payload and endpoint.

## Probe Families

The runner emits these cases:

| Case | Purpose |
| :---- | :---- |
| `baseline_multipart_safe` | valid multipart safe control |
| `attack_multipart_plain` | positive control that a parsed marker is blocked or observed |
| `duplicate_boundary_parameter` | top-level `boundary` selection difference |
| `garbage_outside_boundary` | data before or after boundary markers |
| `lf_only_line_endings` | LF-only body parsing difference |
| `part_duplicate_content_type` | per-part duplicate `Content-Type` selection |
| `part_utf16le_charset` | per-part charset decoding difference |
| `part_charset_mismatch` | declared charset and body bytes disagree |
| `boundary_end_trailing_space` | end-boundary tolerance difference |
| `content_disposition_filename_star` | `Content-Disposition` parameter handling |

## Interpretation

- Docker lab evidence proves the class of parser differential, not the production target's vulnerability.
- A `403` from the lab WAF is a positive control, not an IPS verdict for a real target.
- HTTP/2 rows use `tc=MULTIPART-H2-DOWNGRADE`; do not merge them mentally with HTTP/1.1 parser rows.
- HTTPS-only target results without inspection visibility are `visibility-limited`.
- A WAF or IPS bypass claim requires a visible transport path plus baseline, plain attack, and mutated attack evidence.
- If the backend echo shows the marker but the WAF path does not block it, report the demonstrated primitive as `multipart parser differential` until the target-specific impact is proven.
