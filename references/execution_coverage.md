# Execution Coverage

Use this map to understand whether a TC has a direct runner, needs target-specific setup, or is intentionally conditional.

| TC | Coverage | Runner or method | Notes |
| :---- | :---- | :---- | :---- |
| TC-08 | automated | `scripts/run_tc08_contract_probe.py` | strongest for contract-aware segmentation |
| TC-09 | manual-only | `scripts/run_tc09_manual_stub.py` | raw relay build and parser contract are still target-specific |
| TC-10 | manual-only | `scripts/run_tc10_manual_stub.py` | requires a real app encryptor, accepted endpoint contract, and live key flow |
| TC-12 | automated | `scripts/run_tc12_oversize_probe.py` | generic oversize progression |
| TC-15 | automated | `scripts/run_tc15_lax_json_probe.py` | lax JSON and partial parse variants |
| TC-17 | automated | `scripts/run_tc17_canonical_probe.py` | raw duplicate header probes |
| TC-18 | automated | `scripts/run_tc18_compressed_probe.py` | plain vs compressed body variants |
| TC-19 | automated | `scripts/run_tc19_authority_probe.py` | host or forwarded mismatch |
| TC-20 | automated | `scripts/run_tc20_cache_probe.py` | cache indicators still depend on target behavior |
| TC-21 | automated | `scripts/run_tc21_cookie_probe.py` | duplicate and oversize cookie cases |
| TC-22 | automated | `scripts/run_tc22_json_duplicate_probe.py` | duplicate key ambiguity |
| TC-23 | automated | `scripts/run_tc23_charset_probe.py` | charset, BOM, UTF-16 |
| TC-24 | automated | `scripts/run_tc24_chunk_probe.py` | chunk extension and trailer probes |
| TC-25 | conditional | no default runner | only if the target actually supports HTTP/3 |
| TC-26 | conditional | no default runner | only if the target actually uses websocket or SSE |

`manual-only` does not mean optional. It means the generic skill cannot safely automate the target-specific contract without more context.
