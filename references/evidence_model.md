# Evidence Model

Use one execution-status field and one security-interpretation field.

If the result depends heavily on premises, target-shaped labs, or competing explanations, use this file to keep fact, premise, hypothesis, and conclusion separate in the experiment record.

## Execution Status

- `pass`
- `fail`
- `blocked`
- `not-run`
- `inconclusive`

## Security Interpretation

- `detected`
- `missed`
- `visibility-limited`
- `not-found`
- `control-gap`
- `blocking-owner-unknown`

## Core Evidence Fields

Capture these fields for every executed request:

- request timestamp
- target domain
- TC id
- zone
- payload type
- protocol
- application response
- IDS or IPS result
- callback state
- response headers
- response body fingerprint
- likely response owner
- canonical value chosen by edge or origin when duplicates exist
- decoded-body state when compression or charset changes meaning
- cache indicator or cache-hit note when cache behavior matters
- notes

Capture these interpretation fields whenever a finding depends on deployment assumptions or a target-shaped lab:

- confirmed facts used for the interpretation
- unverified premises still in play
- hypotheses tested in the lab
- which premise was validated, falsified, or left open
- whether the conclusion is target-proven, lab-proven, or still hypothesis-only

## Additional Evidence for High-Risk TCs

- segmentation: pcap and segment layout
- HRS or H2: tool artifact, payload file, side-effect note
- encrypted visibility: encryptor metadata and accepted endpoint details
- sensor health: packet-drop, memory, reassembly-limit, restart, and failover notes when relevant
- compressed body: raw payload, decoded size, content-encoding note
- cache poisoning: replay evidence, cross-user reflection note
- cookie or duplicate-key ambiguity: chosen-value note
- chunk or trailer parsing: raw request artifact and chunk layout

## Conservative Rules

- Missing callback is not proof of non-execution
- Missing IDS alert is not proof of a gap if visibility is unknown
- HTTPS-only evidence is not an IDS verdict when decryption is absent
- Parser mismatch claims require endpoint-contract context
- A `403` is not an IPS verdict by itself
- Repeated identical HTML error pages across unrelated TCs usually indicate a front proxy or shared error renderer, not framework-specific app logic
- `Server: nginx` narrows the visible responder but does not prove the app was uninvolved; reverse proxies can intercept or rewrite upstream errors
- H3 and websocket coverage checks are parity tests first; do not overstate them as exploit proofs
- Duplicate header, cookie, or JSON-key claims require both the sent duplicates and the observed chosen value or behavior
- Do not promote a lab-only explanation to a target conclusion unless the required premises were confirmed
- When a stronger impact depends on an extra condition, write the demonstrated primitive and the conditional impact separately
