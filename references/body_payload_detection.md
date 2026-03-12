# Body Payload Detection

Use this step when the retest question is "does the target detect or block attack payloads placed in the request body, not just in headers or URLs?"

## When to run

Run body-native detection probes when:

- header-based detection was already confirmed or observed (e.g., JNDI in `X-Test` header caused timeout)
- the target accepts structured JSON request bodies with a known contract
- the question is whether body inspection matches header inspection coverage

## Prerequisites

- a captured or reconstructed request contract (method, URL, headers, JSON envelope)
- a body field where an inert probe value can be placed without breaking the envelope structure
- scheme parity baseline already established (benign `http://` vs `https://` behavior is known)

## Payload categories

Use inert detection-test strings, not weaponized payloads. The goal is to trigger pattern-matching rules, not to exploit.

Minimum categories:

| Category | Example probe value |
| :---- | :---- |
| SQLi UNION | `' UNION SELECT 1,2,3--` |
| SQLi boolean | `' OR '1'='1` |
| SSRF internal | `http://169.254.169.254/latest/meta-data/` |
| SSRF file | `file:///etc/passwd` |
| SSTI Jinja | `{{7*7}}` |
| SSTI FreeMarker | `${7*7}` |
| NoSQLi $ne | `{"$ne": null}` |
| NoSQLi $gt | `{"$gt": ""}` |
| LDAP wildcard | `*)(&` |
| LDAP injection | `*(&#124;(objectClass=*))` |
| RCE pipe | `; cat /etc/passwd` |
| RCE backtick | `` `id` `` |
| XSS script | `<script>alert(1)</script>` |
| XSS event | `<img src=x onerror=alert(1)>` |
| Log4Shell JNDI | `${jndi:ldap://probe.invalid/detect}` |
| Path traversal | `../../../../../../etc/passwd` |

## Procedure

1. Generate a corpus of JSON body files, each placing one probe value into the target field while preserving the full request contract envelope.
2. Send each payload over HTTPS first, then over plaintext HTTP (if reachable), with the same method and headers as the captured contract.
3. Between each payload, wait at least 2–3 seconds. If cumulative rate-based blocking is a concern, insert a benign baseline probe every 4–5 payloads to confirm the source IP is still accepted.
4. Record `curl_rc`, `http_code`, `time_total`, `body_fingerprint`, and transport outcome for each probe.
5. If all probes timeout and the baseline also times out, the run is inconclusive for payload-specific attribution. Mark as `blocking-owner-unknown` with a note about IP/session-level blocking overlap.
6. If some probes timeout while the baseline and other probes return normal responses, the timeouts are stronger evidence of payload-specific body detection.

## Cooldown and IP-block disambiguation

The most common failure mode is running too many attack payloads in sequence without cooldown, causing the source IP or session to be rate-limited or banned. When this happens:

- all probes including benign baseline will timeout
- the result is `blocking-owner-unknown`, not `detected`
- to disambiguate, wait for cooldown (10–30 minutes or IP change), then retest with one payload at a time, confirming baseline between each

## Reporting rules

- Do not write "body inspection detected all attack categories" if the benign baseline also timed out at the same time.
- Do write "body-level detection or rate-based blocking is active" when all attack payloads timed out.
- Distinguish payload-specific detection from IP/session blocking in the notes column.
- Record each payload category as a separate row in the evidence CSV with `tc=BODY-DETECTION`.
- When payload-specific detection is confirmed (baseline passes, specific payload times out), use `ids_status=detected`.
- When disambiguation is incomplete, use `ids_status=blocking-owner-unknown`.

## Integration with existing TCs

Body detection probes are supplementary to existing TCs. They provide attribution evidence for the "does the target inspect body content?" question, which is implicit in TC-12, TC-15, and TC-18 but not directly tested by them.

Body detection results should be reported alongside scheme parity findings, since the same probe value may behave differently over plaintext HTTP vs HTTPS.
