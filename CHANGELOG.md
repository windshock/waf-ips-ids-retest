# Changelog

## 2026-05-06

### Added

- `scripts/run_tc27_multipart_probe.py`: automated runner for TC-27 multipart/form-data parsing differentials covering 8 variants (baseline, duplicate-boundary-param, non-UTF8-header-byte, garbage-before-boundary, garbage-after-final, utf16le-part-charset, duplicate-part-content-type, trailing-space-end-marker); includes per-case fail-open classification with `failopen` and `failopen_signal` columns in summary.csv
- `assets/docker-coraza-waf-lab/`: white-box Coraza WAF lab (Executor :8009 → Coraza proxy :9091 → Python echo backend :3009); architecture based on https://github.com/HacktronAI/skills/tree/main/environments/vercel-waf-env; `waf/coraza.conf` is intentionally exposed so Claude can read detection logic and design targeted bypass variants — the key difference from black-box testing
- confirmed new bypass beyond the article's 5: `garbage_after_final` — Coraza v3.2.1 terminates multipart inspection at `--boundary--` and ignores trailing epilogue data; payload hidden after the closing delimiter passes undetected
- TC-27 row to `references/tc_matrix.md` with goal, controls, prerequisites, minimum evidence, and Control Rules for fail-open and parsing-differential outcomes
- TC-27 coverage entry to `references/execution_coverage.md`

### Changed

- added Step 0.5 (WAF Behavior Inference) to `SKILL.md` workflow between Step 0 and Step 1: run TC-27 first when multipart endpoint is in scope; read `coraza-rules/` before designing variants when white-box lab is available
- added TC-27 execution guidance and outcome taxonomy to `SKILL.md` Step 3
- added `run_tc27_multipart_probe.py` and `docker-coraza-waf-lab/` to `SKILL.md` resource lists
- updated `references/tc24_reference_notes.md` with bypass-to-TC-27-variant mapping table linking all 5 article bypass techniques to their corresponding probe cases

## 2026-03-30

### Added

- dedicated `scripts/run_tc24_smuggling_probe.py` runner for `quoted_string_crlf` and escaped LF/CR evidence
- dedicated `scripts/run_tc24_multiip_probe.sh` and `scripts/tc24_multiip_client.py` helpers for isolated multi-client Docker-lab fan-out testing
- `references/tc24_reference_notes.md` documenting the external references used for TC-24 runner design and interpretation updates

### Changed

- expanded `SKILL.md` guidance for TC-24 so single-request anomaly, hidden request execution, response-queue poisoning, and fan-out pressure are reported as distinct outcomes
- added fresh-lab or cooldown rerun guidance before writing a stable TC-24 fan-out ceiling or DoS number
- strengthened `references/retest_process.md` and `references/evidence_model.md` so facts, premises, hypotheses, and conclusions are separated before impact escalation
- updated `references/service_situation_lab.md` and `references/tc_matrix.md` to require distinct client IPs or namespaces when concurrency, fan-out, or cross-user TC-24 claims are in scope
- updated `references/quick_start.md` with TC-24 smuggling and multi-client fan-out examples
- clarified the experiment workflow so repeated TC-24 reruns improve the lab or downgrade the claim instead of stretching a weak interpretation

### Fixed

- corrected the sample origin lab so app role selection, POST handling, upgrade flow, and front-port mapping align with the intended origin-shape calibration workflow
- refreshed the sample Docker origin lab assets so they can be reused for target-shaped parser and response-origin calibration without hand-editing the lab first
