#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None


ASSET_DIR = Path(__file__).resolve().parent.parent / "assets" / "templates"


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "on", "enabled", "available", "present"}


def load_structured(path_str: str | None) -> dict[str, Any]:
    if not path_str:
        return {}
    path = Path(path_str)
    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(raw)
    elif suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required to read YAML files")
        data = yaml.safe_load(raw)
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            if yaml is None:
                raise RuntimeError("Unsupported file format; use JSON or install PyYAML")
            data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} did not parse to an object")
    return data


def dump_json(path_str: str, payload: dict[str, Any]) -> None:
    path = Path(path_str)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def get_field(*sources: dict[str, Any], names: list[str], default: Any = "") -> Any:
    for source in sources:
        for name in names:
            if name in source and source[name] not in (None, ""):
                return source[name]
    return default


def infer_environment_mode(profile: dict[str, Any], run_config: dict[str, Any]) -> str:
    explicit = get_field(run_config, profile, names=["environment_mode", "mode"], default="")
    if explicit in {"A", "B", "C"}:
        return str(explicit)

    ssl_visible = truthy(
        get_field(
            run_config,
            profile,
            names=["ssl_visibility", "ssl_mirror", "https_visibility", "https_visible"],
            default=False,
        )
    )
    callback_state = str(
        get_field(run_config, profile, names=["callback_state", "callback_health"], default="")
    ).strip().lower()
    if ssl_visible:
        return "A"
    if callback_state in {"unstable", "infra-unstable", "not-reliable", "unreliable"}:
        return "C"
    return "B"


def get_capability(profile: dict[str, Any], run_config: dict[str, Any], name: str) -> str:
    for source in (run_config, profile):
        capabilities = source.get("capabilities")
        if isinstance(capabilities, dict) and name in capabilities:
            return str(capabilities[name]).strip().lower()
        direct = source.get(f"supports_{name}")
        if direct not in (None, ""):
            value = str(direct).strip().lower()
            if value in {"present", "absent", "unknown"}:
                return value
            return "present" if truthy(direct) else "absent"
    return "unknown"


def compute_tc_readiness(profile: dict[str, Any], run_config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    source = {**profile, **run_config}

    checks = {
        "TC-08": [
            ("sudo", truthy(source.get("use_sudo") or source.get("sudo"))),
            ("raw_packet", truthy(source.get("raw_packet_ready"))),
            ("pcap", truthy(source.get("pcap_ready"))),
        ],
        "TC-09": [
            ("waffled_relay", truthy(source.get("waffled_relay_ready"))),
        ],
        "TC-10": [
            ("encryptor", truthy(source.get("encryptor_ready"))),
            ("keys", truthy(source.get("encryption_keys_ready"))),
            ("endpoint_contract", truthy(source.get("encrypted_endpoint_contract_ready"))),
        ],
        "TC-16": [
            ("http2_supported", truthy(source.get("http2_supported"))),
            ("http2_tooling", truthy(source.get("http2_tooling_ready"))),
        ],
        "TC-18": [
            ("compression_tooling", truthy(source.get("compression_tooling_ready"))),
            ("decoded_body_compare", truthy(source.get("decoded_body_compare_ready"))),
        ],
        "TC-19": [
            ("routing_headers", truthy(source.get("routing_headers_ready")) or bool(profile.get("routing_headers"))),
        ],
        "TC-20": [
            ("cache_probe", truthy(source.get("cache_probe_ready"))),
            ("cacheable_path", bool(source.get("cacheable_paths"))),
        ],
        "TC-24": [
            ("raw_chunked", truthy(source.get("raw_chunked_ready"))),
        ],
    }

    readiness: dict[str, dict[str, Any]] = {}
    for tc, entries in checks.items():
        failed = [name for name, ok in entries if not ok]
        readiness[tc] = {
            "ready": not failed,
            "missing": failed,
            "status": "ready" if not failed else "blocked",
        }

    h3_capability = get_capability(profile, run_config, "http3")
    ws_capability = get_capability(profile, run_config, "websocket")
    readiness["TC-25"] = {
        "ready": h3_capability == "present" and truthy(source.get("http3_tooling_ready")),
        "missing": [] if h3_capability == "present" and truthy(source.get("http3_tooling_ready")) else (
            ["capability-absent"] if h3_capability != "present" else ["http3_tooling"]
        ),
        "status": (
            "ready"
            if h3_capability == "present" and truthy(source.get("http3_tooling_ready"))
            else ("not-run" if h3_capability != "present" else "blocked")
        ),
    }
    readiness["TC-26"] = {
        "ready": ws_capability == "present" and truthy(source.get("websocket_probe_ready")),
        "missing": [] if ws_capability == "present" and truthy(source.get("websocket_probe_ready")) else (
            ["capability-absent"] if ws_capability != "present" else ["websocket_probe"]
        ),
        "status": (
            "ready"
            if ws_capability == "present" and truthy(source.get("websocket_probe_ready"))
            else ("not-run" if ws_capability != "present" else "blocked")
        ),
    }
    return readiness


def normalize_key(value: str) -> str:
    lowered = value.strip().lower().replace("\ufeff", "")
    lowered = re.sub(r"[^a-z0-9가-힣]+", "", lowered)
    return lowered


def render_template(template_text: str, mapping: dict[str, Any]) -> str:
    rendered = template_text
    for key, value in mapping.items():
        rendered = rendered.replace("{{ " + key + " }}", str(value))
    return rendered


def load_template(path_str: str | None, default_name: str) -> str:
    if path_str:
        return Path(path_str).read_text(encoding="utf-8")
    return (ASSET_DIR / default_name).read_text(encoding="utf-8")
