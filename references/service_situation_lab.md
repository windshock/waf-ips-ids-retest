# Service Situation Lab

Use this step when direct target testing produced status codes or transport symptoms whose meaning is ambiguous for the service shape you observed.

## When this step is required

Run a target-shaped local lab before final reporting when you see a mix such as:

- `302` on one host and `200` on another
- short `400` HTML bodies that could come from a front web tier
- `403` that could be nginx, app, or edge generated
- `200` with generic HTML shell fallback instead of route-specific content
- `200` with structured app JSON errors
- timeout or no-response only for some payloads or schemes

## Minimum lab shape

Mirror the target's predicted service structure from confirmed facts, not just generic response families. Start from the captures, APK/static analysis, observed hosts, ports, route types, and fallback behavior you actually confirmed. Reproduce the smallest structure that explains the responses you saw. For example:

1. public web redirector on the observed host
2. front proxy short `400` or static `403` anchor family
3. route-specific Next.js or SPA shell on the observed auth host
4. host-mismatch fallback shell if the target actually showed one
5. app JSON envelope on the observed API host and port
6. static asset host with cache headers if static behavior was in scope
7. hold/no-response path
8. optional inline-drop control leg when timeout meaning matters

## Procedure

1. Extract the confirmed hosts, ports, path families, and fallback behaviors from the target run and supporting evidence.
2. Build a small local Docker lab that recreates that predicted structure, not just the status codes.
3. Probe the lab with the same helper scripts used on the target, or with simple `curl` cases when enough.
4. Run `scripts/classify_response_origin.py` on the lab outputs.
5. If timeout/no-response is a material finding, also run the inline-drop comparison lab from `references/suricata_inline_lab.md`.
6. Compare target artifacts to the lab fingerprints before writing the final interpretation.

## Reporting rule

The final report should say when a conclusion was calibrated against a service-situation lab and what confirmed target facts were mirrored into that lab. This is especially important for:

- `400/403` ownership claims
- `200` fallback HTML interpretation
- timeout vs app-response meaning

Origin-shape lab and inline-drop lab serve different purposes:

- origin-shape lab: interpret `400/403/200`, fallback HTML, structured app JSON
- inline-drop lab: interpret whether a no-response/timeout symptom belongs to the same family as an inline security control drop

## Sample multi-host example

If the target has a multi-host architecture, include:

- `www.example-target.local`-like public web redirector
- `static.example-target.local`-like static asset host
- `auth.example-target.local`-like auth host with route-specific page and host-mismatch shell fallback
- `api.example-target.local:27000`-like JSON API host and port with `ResData.ResHeader` envelope
- a short front-side `400` anchor family
- a hold/no-response path for payload-induced timeout comparison
- and, when timeout meaning matters, an inline-drop comparison leg so timeout is not inferred only from user expectation
