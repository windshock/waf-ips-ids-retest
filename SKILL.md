---
name: waf-ips-ids-retest
description: Use when rerunning WAF, IPS, or IDS bypass tests and you need readiness checks, conservative result interpretation, and SOC-ready evidence.
---

# WAF IPS IDS Retest

## Overview

Use this skill to turn ad hoc retests into a controlled verification cycle. Treat it as a retest framework, not a generic scanner: confirm environment readiness first, record evidence in a fixed model, then normalize outputs for SOC or blue-team correlation.

If this is your first run with the skill, start with `references/quick_start.md`. It points to the example inputs and outputs under `assets/examples/`.

`agents/openai.yaml` is UI metadata for skill pickers. You do not need it during normal execution unless you are maintaining the skill package itself.

## Workflow

### 0. Separate facts, premises, hypotheses, and conclusions

This section defines the minimum discipline for this skill. Use it whenever the hard part is no longer "which probe do I run?" but "what is fact vs premise vs hypothesis, and how should I improve the lab next?"

Before you build a lab or explain a finding, separate these four buckets explicitly:

- confirmed fact: directly observed target behavior, capture, log, code path, or config
- premise: an unverified deployment assumption that may matter, such as backend type, cache placement, same-IP bias, or whether an endpoint normally accepts chunked requests
- hypothesis: a causal claim you intend to test, such as "nginx reparses the hidden request on the attacker connection" or "same-IP load is understating the TC-24 ceiling"
- conclusion: only the portion that remains true after the premise was checked or the lab was improved to test it

Do not collapse a premise into a conclusion. If an interpretation depends on a premise, either verify that premise directly or mark the statement as a hypothesis and build the next lab iteration around it.

### 1. Classify the environment first

Before interpreting any result, determine whether the target is in one of these modes:

- HTTPS visibility available
- HTTPS visibility unavailable but HTTP or raw traffic still observable
- HTTPS visibility unavailable and callback infrastructure unreliable

Read:

- `references/quick_start.md` if you need a minimal runnable example
- `references/environment_modes.md`
- `references/target_profile_schema.md`
- `references/dependencies.md` if you need tool prerequisites or failure hints

Run:

- `scripts/prereq_validator.py` to validate the target profile and run configuration before testing
- `scripts/generate_run_manifest.py` to capture run id, source IP, callback state, SSL visibility, and tool metadata
- `scripts/run_scheme_parity_probe.py` when the target may expose the same path over plaintext `http://` and `https://`; use it before calling a timeout "IPS" just because the TLS path behaved differently

### 2. Refuse fallback execution

Do not silently replace missing prerequisites with weaker substitutes.

- If HTTPS visibility is absent, do not treat HTTPS responses as IDS verdicts
- If callback infrastructure is unstable, do not treat callback absence as proof of non-execution
- If an encrypted endpoint requires a real app encryptor and key material is missing, mark the TC as `blocked`
- If a plaintext `http://` path is reachable, compare plaintext and TLS behavior separately before writing "HTTP also timed out" or "IPS blocked both"
- **If you claim "IPS/WAF does not detect X" or "X bypasses inspection", you must have tested on an IPS-visible transport path (e.g., plaintext HTTP). An HTTPS-only result in Mode B can only be labeled `visibility-limited`, never `control-gap` or `ips-bypass`.** Read `references/visibility_aware_finding.md` for the 4-cell verification matrix and attribution rules.
- **Never assume IPS behavior — verify it.** If you observe an app-level gap (e.g., app parses JSON regardless of Content-Type), do NOT assume the IPS shares that gap. Test the same technique on the IPS-visible path before writing the finding. Example: send the same attack body with different Content-Types via plaintext HTTP to see if IPS detection depends on CT.

**Before marking any TC as `not-run` or `blocked`, verify the prerequisite gap is real:**

- Check `run-config.yaml` capabilities — if it says `ready: true`, the tool exists. Do not claim otherwise.
- If the prerequisite is a script or relay that doesn't exist yet, **build it** (Python raw socket relay, scapy probe, etc.) rather than marking the TC blocked.
- `not-run` is ONLY valid when (a) the target genuinely lacks the capability (e.g., HTTP/3, WebSocket) or (b) testing would cause irreversible production damage requiring explicit approval.
- "범위 외" (out of scope) is NOT a valid reason to skip a TC unless the customer explicitly excluded it. All TCs in `tc_scope.core` are mandatory.
- If a TC was attempted and the network dropped packets, that IS a finding — record it as evidence, not as `blocked`.

Read:

- `references/retest_process.md`
- `references/evidence_model.md`
- `references/visibility_aware_finding.md`

### 3. Execute in test-process order

Run the retest in this order:

1. Readiness remediation
2. Reproduction
3. Confirmation
4. Coverage expansion
5. Regression comparison
6. SOC handoff

Keep `baseline -> comparison variant -> target variant` ordering for core TCs. For TC-specific expectations and prerequisites, load `references/tc_matrix.md`.

If you need to know which TCs are fully automated, partially automated, or intentionally manual, read `references/execution_coverage.md` before deciding whether a missing runner is a bug or an explicit limitation.

When TC-08 needs stronger evidence than a generic split replay, run `scripts/run_tc08_contract_probe.py` to compare `baseline -> plain -> unicode` against the same endpoint and accepted app headers while saving pcaps and segmented raw requests.

When TC-24 needs stronger evidence than a generic chunk/trailer check, run `scripts/run_tc24_smuggling_probe.py` for the `quoted_string_crlf` and escaped LF/CR variants. Use it when you need to know whether the target shows:

- single-request multi-response markers
- hidden second request execution signals
- implementation-specific handling differences between quoted CRLF and escaped LF/CR

When the TC-24 question is about concurrency, fan-out, or whether same-IP harnessing is biasing the result, run `scripts/run_tc24_multiip_probe.sh` against a target-shaped Docker lab. Use it only when clients can be placed on distinct lab IPs or isolated namespaces. Do not use a Docker multi-client harness to claim distinct public source IPs against an external production host.

For expanded edge-surface coverage, add canonicalization, compressed-body, cache-key, cookie, duplicate-key, charset, and chunk-trailer probes before concluding that parsing gaps are limited to the request body. For any TC that tests a potential inspection bypass technique (TC-08 split-packet, TC-12 oversize, TC-15 malformed JSON, TC-18 compression, TC-23 charset), run the 4-cell verification matrix from `references/visibility_aware_finding.md` on the IPS-visible transport before claiming bypass. Treat HTTP/3 and websocket checks as conditional parity tests that run only when the target actually uses those protocols.

When the retest question includes "does the target detect attack payloads in the request body?", run `scripts/run_body_detection_probe.py` with the captured contract and a target body field. This probe sends inert detection-test strings (SQLi, SSRF, SSTI, NoSQLi, LDAP, RCE, XSS, Log4Shell, path traversal) one at a time with cooldown and periodic baseline checks to distinguish payload-specific detection from IP/session-level rate blocking. Read `references/body_payload_detection.md` for the procedure, disambiguation rules, and reporting constraints.

When a live app or auth request contract is available, do not run the stock generic body-mutation runners directly against that endpoint if doing so would discard accepted headers, envelope shape, cookies, or auth semantics. For TC-12, TC-15, TC-21, TC-22, and TC-23, preserve the captured request contract first, then mutate inside that contract. Use `scripts/run_contract_json_mutation_probe.py` or build a target-specific wrapper before continuing. If you skip this and report only the first-wave families, that is a workflow failure, not an acceptable scope reduction.

When TC-24 or other request-smuggling style tests appear to create many hidden follow-up requests, do not jump directly from "single-request anomaly" to "cross-user desync" or "DoS". First determine which family you actually reproduced:

- attacker-connection reparsing or client-side request splitting
- hidden second request execution without queue poisoning
- orphan-response or response-queue poisoning
- fan-out driven availability pressure

For TC-24 specifically:

- do not treat same-source-IP ceiling tests as definitive; same-IP harnesses can understate capacity or trigger host-side artifacts
- if you are interpreting fan-out or DoS potential, rerun with distinct client IPs or isolated client network namespaces
- if you are writing a stable fan-out ceiling or DoS number, confirm it from a fresh lab state or after an explicit cooldown/reset; repeated high-fan-out runs can degrade due to lab socket churn or upstream connect exhaustion rather than a change in the protocol primitive
- if you are interpreting session confusion, gather front debug logs or pcap evidence to prove whether the hidden response stays on the attacker connection or becomes orphaned
- if a target-shaped lab shows hidden request execution but not cross-user confusion, report it as a strong primitive with limited demonstrated impact, not as proven session hijacking

When a target might expose both plaintext `http://` and `https://` for the same path, run `scripts/run_scheme_parity_probe.py` first on the safest read-only endpoint. If the reporting question is "does the attack payload also time out over plaintext HTTP?", run the same helper a second time with the identical method, headers, and payload that triggered concern on HTTPS. Do not infer attack-path parity from a benign probe. Record `curl_rc`, timeout symptoms, response code, and body fingerprint for both schemes. Do not collapse these into one bucket called "HTTP". In reports, distinguish:

- plaintext `http://`
- `https://` over TLS using raw `HTTP/1.1`
- `https://` over TLS using `HTTP/2`

When non-200 responses appear, do not stop at the status code. Classify whether the response most likely came from:

- the edge or reverse proxy
- an inline blocking device
- the upstream application
- an unknown owner

Read `references/response_origin_triage.md` and run `scripts/classify_response_origin.py` against saved headers and bodies before calling a `403`, `401`, or `500` an IPS, WAF, nginx, Tomcat, or Spring result.

Before writing the final report, if the target shows mixed status meaning such as `302 redirect`, short `400`, generic `200` fallback HTML, structured `200` app JSON, or timeout/no-response, build a small service-situation lab that mirrors the predicted target structure from confirmed facts. Use observed hosts, ports, path families, and fallback behavior from captures, APK analysis, or direct probes. Do not stop at a generic “response family” lab if the target shape is already known well enough to model more closely.

Read `references/service_situation_lab.md` for the minimum lab shape and when to require it.

If you still need a concrete inline IPS comparison, use the local Suricata lab:

- read `references/suricata_inline_lab.md`
- run `scripts/docker_suricata_inline_lab.sh up`
- probe with `scripts/docker_suricata_inline_lab.sh probe <output_dir>`
- compare client symptoms and `eve.json` drops before labeling a real-world timeout or block as IPS behavior

### 4. Normalize evidence before reporting

After execution, normalize logs into the common evidence model.

If status meaning is still ambiguous after direct triage, run the target-shaped local lab first and include its conclusions in the notes before rendering the final handoff.

When the first lab does not answer the real question, improve the lab instead of stretching the interpretation. Typical examples:

- same-IP load gives an unstable or suspiciously low ceiling -> rerun with distinct client IPs or isolated client namespaces
- hidden request execution is visible but cross-user impact is not -> add victim flows, stronger ownership markers, and connection-level logging
- cache poisoning depends on whether the path is inherently cache-unsafe -> split the cache finding from the desync finding and retest them separately
- a claim depends on backend type or proxy chain -> mirror that confirmed chain in the lab before escalating the impact statement

Before finalizing the handoff, run the consistency checks in `references/handoff_consistency_check.md`:

- No duplicate Key Findings in SOC handoff
- CSV row count matches claimed Row Count
- Query Windows cover all timestamps in the CSV
- Coverage matrix includes all TC and helper test categories
- Every finding has transport attribution (`tested_transport`, `ips_visible`)
- `soc_handoff_meta.json` finding count matches `soc_handoff.md`

Run:

- `scripts/merge_normalize_csv.py` to merge or reshape CSV logs into a single schema
- `scripts/render_soc_handoff.py` to render the SOC-facing summary from the manifest and merged log
- `scripts/classify_response_origin.py` when you need conservative ownership labels for repeated `4xx/5xx`, static error pages, timeout/reset patterns, or proxy-vs-app interpretation gaps

Use these templates when you need deterministic document structure:

- `assets/templates/run_manifest.md.tmpl`
- `assets/templates/coverage_matrix.md.tmpl`
- `assets/templates/soc_handoff.md.tmpl`

### 5. Keep interpretation conservative

Use separate labels for execution status and security interpretation.

- Execution status: `pass`, `fail`, `blocked`, `not-run`, `inconclusive`
- Security interpretation: `detected`, `missed`, `visibility-limited`, `not-found`, `control-gap`, `blocking-owner-unknown`

For TC-24 and other desync-style probes, keep the impact label narrower than the primitive unless you actually demonstrated the stronger outcome. Examples:

- hidden second request executed -> report as `request-boundary anomaly` or `hidden second request execution`
- same connection fan-out causes target-shaped lab pressure -> report as `fan-out / availability pressure`
- response queue poisoning only if victim actually receives attacker-owned response
- cross-user session confusion only if ownership of the victim response is proven, not inferred

Read `references/evidence_model.md` and `references/soc_handoff.md` before drawing conclusions.

## Resources

### scripts/

- `common.py`: shared helpers for profile loading, mode inference, and template handling
- `manual_stub_common.py`: shared helpers for explicit manual-only or blocked TC stubs
- `prereq_validator.py`: validate environment class, prerequisites, and TC readiness
- `generate_run_manifest.py`: generate a normalized run manifest from run inputs
- `merge_normalize_csv.py`: merge and normalize heterogeneous execution CSVs
- `render_soc_handoff.py`: render SOC handoff Markdown from the manifest and merged evidence
- `classify_response_origin.py`: classify saved error responses as likely edge, inline control, upstream app, or unknown using conservative heuristics
- `http_probe_common.py`: shared helpers for curl-based probes, raw HTTP requests, and artifact saving
- `run_scheme_parity_probe.py`: compare plaintext `http://` and `https://` behavior for the same path before attributing timeouts or drops to IPS
- `run_tc09_manual_stub.py`: emit a manual-only TC-09 skeleton when raw relay work remains target-specific
- `run_tc10_manual_stub.py`: emit a manual-only TC-10 skeleton when a real encryptor and accepted contract are required
- `run_tc08_contract_probe.py`: execute contract-aware TC-08 control and split probes with baseline curl, Scapy raw segments, and pcap capture
- `run_tc12_oversize_probe.py`: compare baseline and progressively larger request bodies against the same endpoint
- `run_tc15_lax_json_probe.py`: compare valid JSON against lax and partial-parse variants
- `run_contract_json_mutation_probe.py`: preserve a captured JSON request contract while running TC-12, TC-15, TC-21, TC-22, or TC-23 style mutations
- `run_tc17_canonical_probe.py`: send duplicate header and canonicalization-conflict probes with raw HTTP artifacts
- `run_tc18_compressed_probe.py`: compare plain, gzip, deflate, and optional br request bodies
- `run_tc19_authority_probe.py`: compare aligned HTTP/2 requests against Host and Forwarded mismatch variants
- `run_tc20_cache_probe.py`: replay baseline and unkeyed-input variants while recording cache indicators
- `run_tc21_cookie_probe.py`: compare duplicate and oversize cookie handling
- `run_tc22_json_duplicate_probe.py`: compare unique-key, duplicate-key, and lax JSON variants
- `run_tc23_charset_probe.py`: compare UTF-8, BOM, UTF-16LE/BE, and charset-mismatch JSON bodies
- `run_tc24_chunk_probe.py`: send raw chunked, chunk-extension, and trailer-header requests with saved artifacts
- `run_tc24_smuggling_probe.py`: send `quoted_string_crlf` and escaped LF/CR smuggling variants and annotate multi-response markers such as `status_chain=...`
- `run_tc24_multiip_probe.sh`: run quoted-string CRLF fan-out probes from multiple isolated Docker clients on the same lab network and summarize full-success vs partial-failure clients
- `docker_suricata_inline_lab.sh`: run a local Suricata NFQUEUE inline lab to compare real IPS-style drops against proxy/app responses
- `docker_sample_origin_lab.sh`: run a sample structure-calibration lab for redirects, short `400`, Next.js fallback, app JSON, static asset, and hold/no-response patterns
- `run_body_detection_probe.py`: send inert body-native attack payloads (SQLi, SSRF, SSTI, NoSQLi, LDAP, RCE, XSS, Log4Shell, path traversal) inside a captured JSON contract with cooldown and baseline checks

### references/

- `quick_start.md`: first-run commands with sample input and output files
- `dependencies.md`: required and optional tooling, plus expected failure behavior
- `execution_coverage.md`: which TCs are automated, mixed, manual-only, or conditional
- `environment_modes.md`: interpret SSL visibility and callback stability correctly
- `scheme_parity.md`: how to compare plaintext `http://` and `https://` behavior without conflating transport layers
- `retest_process.md`: phase order, entry criteria, exit criteria, and blocked handling
- `tc_matrix.md`: TC-specific prerequisites, controls, and minimum evidence
- `evidence_model.md`: required evidence, status model, and conservative interpretation rules
- `response_origin_triage.md`: how to distinguish edge-generated, inline-device, and upstream-app error responses
- `service_situation_lab.md`: how to build a target-shaped local lab before interpreting ambiguous status codes
- `suricata_inline_lab.md`: how to run a local Suricata inline block lab and interpret `drop` vs `403`
- `target_profile_schema.md`: generic target profile schema with an example
- `app-example-profile.md`: example profile showing how to map a real target into the generic schema
- `soc_handoff.md`: what to include when handing evidence to SOC or IDS operators
- `body_payload_detection.md`: how to run body-native attack payload detection probes, disambiguate IP blocking from payload detection, and report results
- `visibility_aware_finding.md`: rules for attributing findings based on transport visibility, 4-cell verification matrix, and HTTPS-only finding interpretation limits
- `handoff_consistency_check.md`: pre-handoff consistency checks for duplicate findings, row counts, query windows, and cross-document sync

### assets/

- `examples/profile.example.yaml`
- `examples/run-config.example.yaml`
- `examples/request_contract.example.json`
- `examples/run_manifest.example.md`
- `examples/combined.example.csv`
- `examples/soc_handoff.example.md`
- `templates/combined-header.csv`
- `templates/run_manifest.md.tmpl`
- `templates/coverage_matrix.md.tmpl`
- `templates/soc_handoff.md.tmpl`
