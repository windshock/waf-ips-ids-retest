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

### 2. Refuse fallback execution

Do not silently replace missing prerequisites with weaker substitutes.

- If HTTPS visibility is absent, do not treat HTTPS responses as IDS verdicts
- If callback infrastructure is unstable, do not treat callback absence as proof of non-execution
- If real segmentation is required but raw packet prerequisites are missing, mark the TC as `blocked`
- If an encrypted endpoint requires a real app encryptor and key material is missing, mark the TC as `blocked`

Read:

- `references/retest_process.md`
- `references/evidence_model.md`

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

For expanded edge-surface coverage, add canonicalization, compressed-body, cache-key, cookie, duplicate-key, charset, and chunk-trailer probes before concluding that parsing gaps are limited to the request body. Treat HTTP/3 and websocket checks as conditional parity tests that run only when the target actually uses those protocols.

When non-200 responses appear, do not stop at the status code. Classify whether the response most likely came from:

- the edge or reverse proxy
- an inline blocking device
- the upstream application
- an unknown owner

Read `references/response_origin_triage.md` and run `scripts/classify_response_origin.py` against saved headers and bodies before calling a `403`, `401`, or `500` an IPS, WAF, nginx, Tomcat, or Spring result.

If you still need a concrete inline IPS comparison, use the local Suricata lab:

- read `references/suricata_inline_lab.md`
- run `scripts/docker_suricata_inline_lab.sh up`
- probe with `scripts/docker_suricata_inline_lab.sh probe <output_dir>`
- compare client symptoms and `eve.json` drops before labeling a real-world timeout or block as IPS behavior

### 4. Normalize evidence before reporting

After execution, normalize logs into the common evidence model.

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
- `run_tc09_manual_stub.py`: emit a manual-only TC-09 skeleton when raw relay work remains target-specific
- `run_tc10_manual_stub.py`: emit a manual-only TC-10 skeleton when a real encryptor and accepted contract are required
- `run_tc08_contract_probe.py`: execute contract-aware TC-08 control and split probes with baseline curl, Scapy raw segments, and pcap capture
- `run_tc12_oversize_probe.py`: compare baseline and progressively larger request bodies against the same endpoint
- `run_tc15_lax_json_probe.py`: compare valid JSON against lax and partial-parse variants
- `run_tc17_canonical_probe.py`: send duplicate header and canonicalization-conflict probes with raw HTTP artifacts
- `run_tc18_compressed_probe.py`: compare plain, gzip, deflate, and optional br request bodies
- `run_tc19_authority_probe.py`: compare aligned HTTP/2 requests against Host and Forwarded mismatch variants
- `run_tc20_cache_probe.py`: replay baseline and unkeyed-input variants while recording cache indicators
- `run_tc21_cookie_probe.py`: compare duplicate and oversize cookie handling
- `run_tc22_json_duplicate_probe.py`: compare unique-key, duplicate-key, and lax JSON variants
- `run_tc23_charset_probe.py`: compare UTF-8, BOM, UTF-16LE/BE, and charset-mismatch JSON bodies
- `run_tc24_chunk_probe.py`: send raw chunked, chunk-extension, and trailer-header requests with saved artifacts
- `docker_suricata_inline_lab.sh`: run a local Suricata NFQUEUE inline lab to compare real IPS-style drops against proxy/app responses

### references/

- `quick_start.md`: first-run commands with sample input and output files
- `dependencies.md`: required and optional tooling, plus expected failure behavior
- `execution_coverage.md`: which TCs are automated, mixed, manual-only, or conditional
- `environment_modes.md`: interpret SSL visibility and callback stability correctly
- `retest_process.md`: phase order, entry criteria, exit criteria, and blocked handling
- `tc_matrix.md`: TC-specific prerequisites, controls, and minimum evidence
- `evidence_model.md`: required evidence, status model, and conservative interpretation rules
- `response_origin_triage.md`: how to distinguish edge-generated, inline-device, and upstream-app error responses
- `suricata_inline_lab.md`: how to run a local Suricata inline block lab and interpret `drop` vs `403`
- `target_profile_schema.md`: generic target profile schema with an example
- `app-example-profile.md`: example profile showing how to map a real target into the generic schema
- `soc_handoff.md`: what to include when handing evidence to SOC or IDS operators

### assets/

- `examples/profile.example.yaml`
- `examples/run-config.example.yaml`
- `examples/run_manifest.example.md`
- `examples/combined.example.csv`
- `examples/soc_handoff.example.md`
- `templates/combined-header.csv`
- `templates/run_manifest.md.tmpl`
- `templates/coverage_matrix.md.tmpl`
- `templates/soc_handoff.md.tmpl`
