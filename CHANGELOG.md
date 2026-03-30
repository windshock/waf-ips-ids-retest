# Changelog

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
