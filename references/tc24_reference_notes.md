# TC-24 Reference Notes

This note records the external references used to shape the TC-24 runners, lab procedure, and interpretation rules.

## Core conceptual framing

### Grammar un-equivalence

The fundamental principle behind this entire skill: a WAF parses an HTTP request one way, while the backend (Node.js, Next.js, nginx, etc.) parses it another way. A payload that looks harmless to the WAF becomes malicious once the backend interprets it.

This framing comes from the React2Shell WAF bypass research:

- ginoah, s1r1us, "**$170k in Bypasses: The Vercel React2Shell Challenge**", Hacktron AI (May 4, 2026)
- URL: https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass
- practical takeaways used in this skill:
  - HTTP is full of messy, context-sensitive grammar — modeling every backend interpretation perfectly is intractable for a generic WAF
  - the gap exists at every layer: WAF, reverse proxy, framework, application server
  - systematic checklist approach: Content-Type parsing, multipart body parsing, form-data field parsing, request smuggling tricks — these map directly to the TC matrix
  - when a WAF fails to parse, it often forwards the request without sanitization ("fail open") — this is why TC results must distinguish "blocked", "missed", and "visibility-limited"
  - AI models find bypasses effectively only when given the right context, feedback loop, and environment to probe — this skill is designed to be that environment for Claude

## Primary external references

### 1. Funky Chunks research

Used for the chunk-extension parsing class, deployment conditions, and the normalization caveat.

- Ben Kallus, "Funky Chunks" and follow-up writing on chunk-extension parsing and request smuggling
- practical takeaway used in this skill:
  - quoted-string and LF/CR handling can create a strong request-smuggling primitive
  - front normalization and forwarding behavior determine whether the primitive survives the proxy chain

### 2. Netty advisory for quoted-string CRLF

Used for the exact `quoted_string_crlf` variant and for validating that the second request can be attacker-controlled.

- GitHub Security Advisory: `GHSA-pwqr-wmgm-9rr8`
- CVE: `CVE-2026-33870`
- practical takeaway used in this skill:
  - the runner should test a real quoted-string CRLF smuggling case, not only generic chunk-extension/trailer probes
  - TC-24 results should distinguish "single-request anomaly" from "hidden second request execution"

### 3. Pingora request smuggling write-up

Used as a public implementation reference for cross-user impact, hidden second request execution, and why deployment shape matters even when the primitive is strong.

- xclow3n, "Breaking Pingora: HTTP Request Smuggling & Cache Poisoning in Cloudflare's Reverse Proxy"
- practical takeaway used in this skill:
  - keep the primitive separate from the strongest possible impact
  - use target-shaped labs and ownership evidence before escalating to cross-user confusion or queue-poisoning claims
  - distinguish front-side reparsing from true orphan-response scenarios

### 4. nginx-devel CRLF discussion

Used to understand why nginx behavior may persist even when the issue is known publicly.

- nginx-devel January 2024 thread discussing stricter CRLF handling in chunk lines
- practical takeaway used in this skill:
  - do not assume a public parser concern was fixed in nginx
  - verify actual runtime behavior with target-shaped labs, front debug logs, and packet capture

## Local validation that shaped the workflow

These are not external references, but they changed the skill behavior and interpretation rules.

### Hidden request execution vs cross-user confusion

Target-shaped nginx plus Spring/Tomcat labs showed:

- hidden second requests could execute
- but response queue poisoning was not demonstrated in the observed nginx path

This is why the skill now separates:

- hidden second request execution
- response queue poisoning
- cross-user session confusion
- fan-out or availability pressure

### Same-IP bias and multi-client reruns

Same-host or same-IP tests understated or destabilized the TC-24 fan-out ceiling in the lab.

This is why the skill now requires:

- distinct lab client IPs or isolated namespaces for concurrency and fan-out claims
- a fresh-lab or cooldown rerun before writing a stable ceiling or DoS number

## TC-27 variant mapping and lab verdict

The bypass verdict requires **both** conditions: (1) WAF passes the request (200), and (2) the backend's parsed fields contain the probe value. The lab uses busboy (the parser used by Next.js) at the backend so that parsing-differential claims are testable against the same parser the article targeted.

Lab: Coraza v3.2.1 (proxy) + busboy ^1.6.0 (backend), `RETEST-TC27-PROBE` value.

| TC-27 variant | Article bypass | WAF | busboy `parsed_fields` | Verdict |
|---|---|---|---|---|
| `baseline_multipart` | — (control) | 200 | `q=SAFE` | control |
| `duplicate_boundary_param` | Bypass 1 | 200 | `q=PROBE` | **BYPASS confirmed** — Coraza uses last `boundary=`, busboy uses first |
| `non_utf8_header_byte` | Bypass 2 | 200 (fail-open) | `{}` (Malformed Content-Type) | not reproduced — busboy also rejects malformed CT; bypass requires a more lenient backend |
| `utf16le_part_charset` | Bypass 3 | 200 | `q=PROBE` | **BYPASS confirmed** — Coraza scans raw bytes; busboy decodes the part charset |
| `duplicate_part_content_type` | Bypass 4 | 200 | `q=PROBE` | **BYPASS confirmed** — busboy honors the first part Content-Type charset |
| `trailing_space_end_marker` | Bypass 5 | 200 | `q=SAFE` (probe in raw only) | not reproduced against busboy — closing marker leniency does not surface in `parsed_fields` |
| `garbage_before_boundary` | — | 403 | (blocked) | WAF correctly blocks — probe lands in a valid ARGS field |
| `garbage_after_final` | — | 200 | `q=SAFE` (probe in raw only) | WAF inspection gap on RFC 2046 epilogue, but busboy also ignores epilogue → not exploitable against standard busboy/Next.js apps |

**Summary**: 3 of 5 article bypasses reproduce against the Coraza + busboy combination. `non_utf8_header_byte` and `trailing_space_end_marker` need a different (more lenient) backend parser to surface as parsed-field bypasses; `garbage_after_final` is a real WAF inspection gap but not exploitable against standard busboy applications because the epilogue never reaches `parsed_fields`.

## Reporting rule

When you cite a TC-24 result, state both:

1. the demonstrated primitive
2. the deployment assumptions needed for any stronger impact claim

Examples:

- "hidden second request execution confirmed in the target-shaped lab"
- "fan-out pressure confirmed in a fresh-lab multi-client run"
- "cross-user session confusion not demonstrated in this nginx path"
