# Scheme Parity

Use this note when the same endpoint might be reachable over both plaintext `http://` and `https://`.

## Why this matters

- A timeout on `https://` does not prove that plaintext `http://` also timed out.
- A visible `400` or `404` over one scheme does not mean an inline IPS handled the other scheme the same way.
- Many incidents are misreported because `HTTP` is used loosely to mean both plaintext `http://` and `HTTP/1.1 over TLS`.

## Minimum procedure

1. Start with a safe reachability probe on the read-only path.
2. Run `scripts/run_scheme_parity_probe.py` with the exact `https://` URL.
3. If plaintext is on a different host or port, pass `--http-url` explicitly.
4. If your real question is about an attack payload or suspicious parser input, rerun the same helper with the same method, repeated headers, and body bytes that triggered the HTTPS symptom.
5. Record:
   - `curl_rc`
   - `stderr`
   - `time_total`
   - `http_code`
   - `body_fingerprint`
6. Report the schemes separately.

## Payload parity requirement

Do not write any of these unless you actually sent the same payload across both schemes:

- "HTTP도 timeout"
- "HTTP/HTTPS 둘 다 차단"
- "plaintext HTTP also triggers the IPS"

If the HTTPS concern came from a header payload, pass the same header with repeated `--header` flags.

If the HTTPS concern came from a body payload, pass the same body bytes with `--body-file`.

Examples:

```bash
python3 scripts/run_scheme_parity_probe.py \
  --https-url https://api.example.com/v1/search \
  --header 'X-Test: ${jndi:ldap://lab/a}' \
  --output-dir ./scheme-parity-header
```

```bash
python3 scripts/run_scheme_parity_probe.py \
  --https-url https://api.example.com/v1/submit \
  --method POST \
  --header 'Content-Type: application/json' \
  --body-file ./payload.json \
  --output-dir ./scheme-parity-body
```

## Interpretation rules

- safe benign parity and attack parity are separate findings; one does not prove the other
- `http:// timeout` + `https:// 200/400/404`:
  - plaintext and TLS behavior differ
  - do not claim "both blocked"
- `http:// 200` + `https:// timeout`:
  - do not call the timeout an app response
  - consider inline control, TLS path policy, or routing differences
- both schemes return HTTP responses:
  - compare code family and body fingerprint before inferring a security control
- both schemes time out:
  - still do not label as IPS without transport evidence such as packet capture, reset patterns, or inline lab comparison
