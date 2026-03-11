# Dependencies

## Required for the core workflow

- `python3`
- `curl`
- `PyYAML` for YAML profile or run-config files

If `PyYAML` is missing, use JSON files or install it before running `prereq_validator.py` and `generate_run_manifest.py`.

## Required by specific probe families

- `sudo`, `tcpdump`, `scapy`
  - needed for `run_tc08_contract_probe.py`
- raw HTTP capable networking only
  - needed for `run_tc17_canonical_probe.py` and `run_tc24_chunk_probe.py`
- `brotli` Python package
  - optional for the `br` branch of `run_tc18_compressed_probe.py`
- Docker and Docker Compose
  - needed for `docker_response_origin_lab.sh` and `docker_suricata_inline_lab.sh`

## Expected failure behavior

- Missing HTTPS visibility:
  - do not treat HTTPS response codes as IDS verdicts
- Missing callback reliability:
  - do not treat callback absence as proof of non-execution
- Missing raw packet prerequisites:
  - TC-08 should stay `blocked`
- Missing target-specific encryptor or key material:
  - TC-10 should stay `blocked` or use the manual stub
- Missing H3 or websocket capability:
  - TC-25 or TC-26 should be `not-run`, not `blocked`
