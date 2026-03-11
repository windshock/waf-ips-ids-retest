# TC Matrix

This matrix defines what must be true before each TC is considered valid.

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
| TC-24 | chunk extension or trailer parsing gap | valid chunked baseline, extension variant, trailer variant | raw chunked tooling, compatible endpoint | raw request, chunk layout, response |
| TC-25 | HTTP/3 visibility parity | H1/H2 baseline, H3 comparison | target supports H3 | protocol artifact, parity note, response |
| TC-26 | websocket or upgrade blind spot | HTTP baseline, upgrade handshake, post-handshake probe | websocket or SSE path exists | handshake artifact, frame note, response |
| TC-07 | desync or request-smuggling exposure | baseline scan, artifact capture | proxy chain known, tool ready | tool artifact, response notes |

## Control Rules

- Use at least one positive or baseline control and one target variant for every core TC
- Do not interpret a target variant by itself
- When the endpoint contract is unclear, downgrade the result to `inconclusive`
- Treat edge-origin normalization parity as a regression target whenever the testcase depends on paths, headers, or proxy rewrites
- Treat `Expect`-based parser discrepancy as part of the TC-07/TC-16 desync family, not as a separate execution status
- When H3 or websocket capability is absent, record TC-25/26 as `not-run` with `reason=capability-absent`
