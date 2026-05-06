# TC Matrix

This matrix defines what must be true before each TC is considered valid.

For runner coverage and manual-only gaps, read `execution_coverage.md` with this table.

| TC | Goal | Controls | Prerequisites | Minimum evidence |
| :---- | :---- | :---- | :---- | :---- |
| TC-01 | Unicode or normalization gap | baseline, full escape, partial escape | visible JSON endpoint | request, response, IDS result |
| TC-03 | lookup-structure detection gap | baseline, mild variant, target variant | header or body injection point | request, response, IDS result |
| TC-08 | segmentation or reassembly gap | normal request, split variants | sudo, raw packet, pcap | pcap, segment map, response, IDS result |
| TC-09 | parser-branch or raw request gap | valid content-type, malformed content-type, raw variant | raw relay build, compatible endpoint | raw request artifact, response, IDS result, parser note |
| TC-10 | encrypted visibility gap | plaintext pair, encrypted pair | real encryptor, key material, accepted endpoint | encryptor metadata, request, response, IDS result |
| TC-11 | content-type selection gap | valid content-type, weak variant, target variant | endpoint contract understood | request, response, parser-path note |
| TC-12 | body inspection limit gap | baseline size, intermediate size, target size | payload accepted by endpoint | request size, response, IDS result |
| TC-15 | partial-parse, fallback, or lax JSON gap | valid JSON, syntax-weak JSON, target variant | endpoint contract understood | request, response, IDS result, parser-path note |
| TC-16 | HTTP/2 downgrade ambiguity | baseline H2, downgrade variant | H2 supported, tool ready | tool artifact, response notes, proxy-chain note |
| TC-17 | duplicate header or canonicalization conflict | baseline single header, duplicate conflict, notation variant | override or routing header understood | request artifact, response, chosen-value note |
| TC-18 | compressed body inspection gap | plain body, gzip, deflate, optional br | compression tooling, compatible endpoint | raw body artifact, decoded-size note, response |
| TC-19 | authority/host/forwarded mismatch | aligned baseline, mismatch variant, forwarded variant | proxy chain or routing behavior understood | request, response, routing note |
| TC-20 | cache key poisoning or unkeyed input gap | cacheable baseline, injected variant, replay/revisit | cacheable path or response hint exists | cache indicator, replay result, response diff |
| TC-21 | cookie duplicate or oversize inspection gap | single cookie, duplicate cookie, long chain | cookie-aware endpoint or echoed behavior | request, response, chosen-value note |
| TC-22 | JSON duplicate key ambiguity | unique-key baseline, duplicate-key conflict | endpoint contract understood | request, response, parser-path note |
| TC-23 | charset, BOM, or UTF-16 parsing gap | UTF-8 baseline, BOM/UTF-16 variant | endpoint and content-type understood | raw payload artifact, charset note, response |
| TC-24 | chunk extension or trailer parsing gap | valid chunked baseline, extension variant, trailer variant, quoted-string CRLF variant | raw chunked tooling, compatible endpoint, target-shaped lab when response meaning is ambiguous | raw request, chunk layout, response, parser-ownership note |
| TC-25 | HTTP/3 visibility parity | H1/H2 baseline, H3 comparison | target supports H3 | protocol artifact, parity note, response |
| TC-26 | websocket or upgrade blind spot | HTTP baseline, upgrade handshake, post-handshake probe | websocket or SSE path exists | handshake artifact, frame note, response |
| TC-27 | multipart boundary or field-parsing differential | baseline clean multipart, duplicate-boundary-param, non-UTF8-header-byte, garbage-before-boundary, garbage-after-final, utf16le-part-charset, duplicate-part-content-type, trailing-space-end-marker | multipart-capable POST endpoint; raw socket tooling | raw request per variant, WAF decision (http_code), fail-open signal, body fingerprint diff vs baseline |
| TC-07 | desync or request-smuggling exposure | baseline scan, artifact capture | proxy chain known, tool ready | tool artifact, response notes |
| MULTIPART-PARSER | multipart/form-data parser differential helper | safe multipart, plain marker, parser variants | compatible multipart endpoint or Docker calibration lab | raw request, response, WAF-view vs backend-view note |

## Control Rules

- Use at least one positive or baseline control and one target variant for every core TC
- Do not interpret a target variant by itself
- When the endpoint contract is unclear, downgrade the result to `inconclusive`
- When a captured live contract exists, preserve accepted headers, cookies, and envelope shape for TC-12, TC-15, TC-21, TC-22, and TC-23. Do not treat a generic runner that discards the contract as equivalent evidence.
- Treat edge-origin normalization parity as a regression target whenever the testcase depends on paths, headers, or proxy rewrites
- Treat `Expect`-based parser discrepancy as part of the TC-07/TC-16 desync family, not as a separate execution status
- Treat `MULTIPART-PARSER` rows as calibration helper evidence for TC-09, TC-11, TC-23, and TC-27; use the TC-27 row as the canonical multipart bypass matrix.
- Keep `MULTIPART-H2-DOWNGRADE` rows separate from HTTP/1.1 `MULTIPART-PARSER` rows because H2 edge normalization or downgrade may be the root cause.
- When H3 or websocket capability is absent, record TC-25/26 as `not-run` with `reason=capability-absent`
- For TC-24, distinguish these outcomes explicitly:
  - single-request anomaly with multi-response markers
  - attacker-connection hidden request execution
  - orphan-response or response-queue poisoning
  - fan-out or availability pressure
- Prefer `scripts/run_tc24_smuggling_probe.py` when you need quoted-string CRLF evidence rather than only extension/trailer visibility.
- Prefer `scripts/run_tc24_multiip_probe.sh` when the TC-24 question is about fan-out ceiling, same-IP harness bias, or availability pressure in a local Docker lab.
- Do not call a TC-24 result "session confusion" or "cross-user desync" unless a victim request actually receives an attacker-owned response.
- If you measure TC-24 fan-out or DoS ceiling, do not rely on same-IP load alone. Recheck with distinct client IPs or isolated client namespaces before writing the capacity claim.
- For TC-27, distinguish these outcomes explicitly:
  - fail-open: WAF failed to parse malformed multipart and forwarded without inspection (`failopen_signal=fail-open-confirmed-*` in summary.csv)
  - parsing-differential: WAF and backend disagree on boundary or charset — same status as baseline, different body fingerprint
  - fail-closed: WAF or backend rejected the malformed request (4xx response)
  - connection-drop: inline device dropped the packet before any response
- If `non_utf8_header_byte` variant passes the WAF (same status as baseline), record the result as "fail-open" and re-examine all other TC results for this target — the WAF may be forwarding without inspection across the board.
- For `duplicate_boundary_param`, record both the boundary value the WAF used and the boundary value the backend used (visible in the backend echo response `parsed_fields`). Do not compress these into a single "bypass" label without that evidence.
- Do not claim "WAF bypass confirmed" for TC-27 unless the baseline shows the attack payload is blocked AND a variant shows it is not blocked. A result where both baseline and variant return 200 may indicate the WAF does not inspect multipart at all.
- Run TC-27 on a plaintext `http://` path when IPS/WAF visibility is required. An HTTPS-only TC-27 result is `visibility-limited`, not a confirmed bypass.
