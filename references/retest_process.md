# Retest Process

Run the retest as a controlled QA-style process.

If the main difficulty is choosing the next experiment or separating a proven primitive from a conditional impact claim, treat this file as the parent execution order and keep fact, premise, hypothesis, and conclusion separate in the experiment notes.

## Phase 1: Readiness Remediation

Confirm:

- environment mode
- IDS or IPS inline status
- TLS visibility design, certificate health, and decrypt coverage
- source IP registration or unblock path
- callback health
- time synchronization
- raw packet permissions
- crypto prerequisites for encrypted endpoints

Exit only when:

- the environment mode is recorded
- each planned TC is marked `ready` or `blocked`
- the run manifest exists

## Phase 2: Reproduction

Reproduce previously observed findings with the smallest valid set of requests.

Use:

- baseline request
- comparison variant
- target variant

Exit only when:

- each key finding is marked `reproduced`, `changed`, or `inconclusive`
- request and response timestamps are preserved

## Phase 3: Confirmation

Tighten the interpretation of the reproduced findings.

Examples:

- confirm Unicode normalization gaps with plain vs escaped payloads
- confirm segmentation behavior with actual raw packet evidence
- confirm encrypted endpoint visibility with the real app encryptor
- confirm proxy or origin interpretation differences when paths, rewrites, or framing are involved
- confirm who most likely generated repeated `4xx/5xx` responses by comparing headers, body fingerprints, static error pages, and timeout/reset behavior
- separate confirmed observations from premises and turn each open premise into a concrete lab question
- improve the local lab when the current lab cannot decide between competing hypotheses

Exit only when:

- the minimum evidence set exists per TC
- the outcome is no longer dependent on a single weak signal
- repeated `403/401/500` responses have an owner label such as `front-nginx-likely`, `upstream-app-likely`, `edge-waf-likely`, or `unknown`
- any remaining high-impact statement is either directly demonstrated or explicitly marked as conditional on a still-open premise

## Phase 4: Coverage Expansion

Execute previously skipped or weakly evidenced TCs only after readiness is satisfied.

Examples:

- HRS
- HTTP/2 downgrade
- raw multipart or Content-Type variants
- duplicate header or cookie canonicalization
- compressed body inspection
- cache key poisoning or unkeyed input
- charset, chunk trailer, and conditional H3 or websocket parity
- upgraded target-shaped labs that test the next premise rather than repeating the same inconclusive setup

Exit only when:

- each candidate TC is `executed`, `blocked`, or `not-run`
- capability-gated TCs such as H3 or websocket are marked `not-run` when the target does not use them

## Phase 5: Regression Comparison

Compare the current run against prior runs.

Use:

- `reproduced`
- `changed`
- `expanded`
- `inconclusive`

## Phase 6: SOC Handoff

Deliver:

- merged evidence log
- run manifest
- coverage matrix
- conservative summary

Never hide `blocked`, `visibility-limited`, or `callback-infra-unstable` outcomes.
