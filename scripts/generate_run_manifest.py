#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from common import (
    compute_tc_readiness,
    dump_json,
    get_field,
    infer_environment_mode,
    load_structured,
    load_template,
    render_template,
    truthy,
)


def build_manifest(profile: dict, run_config: dict) -> dict:
    readiness = compute_tc_readiness(profile, run_config)
    blocked = [tc for tc, info in readiness.items() if info["status"] == "blocked"]
    conditional_not_run = [tc for tc, info in readiness.items() if info["status"] == "not-run"]
    ssl_visible = truthy(
        get_field(run_config, profile, names=["ssl_visibility", "ssl_mirror", "https_visibility"])
    )
    callback_state = str(
        get_field(run_config, profile, names=["callback_state", "callback_health"], default="unknown")
    )
    notes = []
    if not ssl_visible:
        notes.append("HTTPS visibility unavailable")
    if callback_state.lower() in {"unstable", "infra-unstable", "not-reliable", "unreliable"}:
        notes.append("Callback infrastructure unstable")
    if blocked:
        notes.append("Blocked TCs: " + ", ".join(blocked))
    if conditional_not_run:
        notes.append("Conditional TCs not run: " + ", ".join(conditional_not_run))

    tool_versions = get_field(run_config, profile, names=["tool_versions"], default={})
    if isinstance(tool_versions, dict):
        tool_versions_text = ", ".join(f"{k}={v}" for k, v in sorted(tool_versions.items()))
    else:
        tool_versions_text = str(tool_versions)

    return {
        "run_id": get_field(run_config, names=["run_id"], default=datetime.now().strftime("%Y%m%d_%H%M%S")),
        "start_time": get_field(run_config, names=["start_time"], default=datetime.now().isoformat(timespec="seconds")),
        "timezone": get_field(run_config, names=["timezone"], default="UTC"),
        "source_ip": get_field(run_config, names=["source_ip"], default=""),
        "callback_domain": get_field(run_config, names=["callback_domain"], default=""),
        "callback_state": callback_state,
        "environment_mode": infer_environment_mode(profile, run_config),
        "ssl_visibility": "available" if ssl_visible else "unavailable",
        "ids_mode": get_field(run_config, profile, names=["ids_mode", "ids_ips_mode"], default="unknown"),
        "tool_versions": tool_versions_text,
        "ruleset_version": get_field(run_config, profile, names=["ruleset_version", "ids_ruleset_version"], default=""),
        "notes": "; ".join(notes) if notes else "None",
        "blocked_tcs": blocked,
        "not_run_tcs": conditional_not_run,
        "target_name": profile.get("name", ""),
        "domains": profile.get("domains", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a normalized Markdown run manifest.")
    parser.add_argument("--profile", required=True, help="Target profile in JSON or YAML")
    parser.add_argument("--run-config", required=True, help="Run config in JSON or YAML")
    parser.add_argument("--output", required=True, help="Markdown manifest output path")
    parser.add_argument("--json-out", help="Optional JSON sidecar output path")
    parser.add_argument("--template", help="Optional custom Markdown template path")
    args = parser.parse_args()

    profile = load_structured(args.profile)
    run_config = load_structured(args.run_config)
    manifest = build_manifest(profile, run_config)

    template = load_template(args.template, "run_manifest.md.tmpl")
    rendered = render_template(template, manifest)

    output = Path(args.output)
    manifest["manifest_path"] = str(output)
    output.write_text(rendered.rstrip() + "\n", encoding="utf-8")
    if args.json_out:
        dump_json(args.json_out, manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
