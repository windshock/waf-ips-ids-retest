# Environment Modes

Classify the run before interpreting any result.

## Mode A: HTTPS Visibility Available

- SSL Mirror or equivalent HTTPS decryption exists
- IDS can inspect decrypted HTTPS payloads
- HTTPS evidence can be used for IDS verdicts

Use when:

- SOC confirms decrypted traffic reaches IDS
- IDS zone coverage for body/header is known

## Mode B: HTTPS Visibility Unavailable, HTTP or Raw Visibility Available

- SSL Mirror is absent
- HTTPS results remain useful for application behavior only
- IDS verdicts must come from HTTP, raw, inline blocking, or plaintext endpoints

Use when:

- HTTPS is operational but not visible to IDS
- Some HTTP, raw socket, or plaintext traffic still exists

## Mode C: HTTPS Visibility Unavailable and Callback Reliability Low

- SSL Mirror is absent
- Callback infrastructure is unstable or non-deterministic
- External callback becomes auxiliary evidence only

Use when:

- `interactsh` or equivalent frequently expires or disconnects
- Egress controls, DNS sinkholes, or outbound proxies may hide callback evidence

## Callback States

- `callback observed`: keep as positive external execution evidence
- `callback not observed`: do not translate to non-execution
- `callback infra unstable`: record as environment limitation
- `callback interpretation not reliable`: record when callback semantics are compromised by environment

## Interpretation Rules

- Never mix application response with IDS visibility
- Never upgrade HTTPS response-only evidence into IDS proof in Mode B or C
- Never treat missing callback as proof that the payload never executed
- Verify where TLS is decrypted, how decrypt failures behave, and whether decryption coverage is measured for critical paths
- Record whether HTTP/2 is normalized or downgraded before inspection
