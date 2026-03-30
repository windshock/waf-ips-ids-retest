# TC-24 Reference Notes

This note records the external references used to shape the TC-24 runners, lab procedure, and interpretation rules.

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

## Reporting rule

When you cite a TC-24 result, state both:

1. the demonstrated primitive
2. the deployment assumptions needed for any stronger impact claim

Examples:

- "hidden second request execution confirmed in the target-shaped lab"
- "fan-out pressure confirmed in a fresh-lab multi-client run"
- "cross-user session confusion not demonstrated in this nginx path"
