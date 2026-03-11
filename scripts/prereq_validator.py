#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys

from common import compute_tc_readiness, get_field, infer_environment_mode, load_structured, truthy


def build_summary(profile: dict, run_config: dict) -> dict:
    mode = infer_environment_mode(profile, run_config)
    readiness = compute_tc_readiness(profile, run_config)

    required_profile = ["name", "domains", "critical_endpoints", "tc_scope"]
    required_run = ["source_ip", "timezone", "marker_prefix"]
    missing_profile = [name for name in required_profile if not profile.get(name)]
    missing_run = [name for name in required_run if not run_config.get(name)]

    ssl_visible = truthy(
        get_field(run_config, profile, names=["ssl_visibility", "ssl_mirror", "https_visibility"])
    )
    callback_state = get_field(run_config, profile, names=["callback_state", "callback_health"], default="unknown")

    return {
        "target": profile.get("name", "unknown"),
        "environment_mode": mode,
        "ssl_visibility": "available" if ssl_visible else "unavailable",
        "callback_state": callback_state,
        "missing_profile_fields": missing_profile,
        "missing_run_fields": missing_run,
        "tc_readiness": readiness,
        "ready_count": sum(1 for item in readiness.values() if item["status"] == "ready"),
        "blocked_count": sum(1 for item in readiness.values() if item["status"] == "blocked"),
        "not_run_count": sum(1 for item in readiness.values() if item["status"] == "not-run"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate retest prerequisites and classify readiness.")
    parser.add_argument("--profile", required=True, help="Target profile in JSON or YAML")
    parser.add_argument("--run-config", required=True, help="Run config in JSON or YAML")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    try:
        profile = load_structured(args.profile)
        run_config = load_structured(args.run_config)
        summary = build_summary(profile, run_config)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    print(f"Target: {summary['target']}")
    print(f"Environment mode: {summary['environment_mode']}")
    print(f"SSL visibility: {summary['ssl_visibility']}")
    print(f"Callback state: {summary['callback_state']}")
    if summary["missing_profile_fields"]:
        print("Missing profile fields: " + ", ".join(summary["missing_profile_fields"]))
    if summary["missing_run_fields"]:
        print("Missing run-config fields: " + ", ".join(summary["missing_run_fields"]))
    print("")
    print("TC readiness:")
    for tc, info in summary["tc_readiness"].items():
        if info["status"] == "ready":
            print(f"- {tc}: ready")
        elif info["status"] == "not-run":
            print(f"- {tc}: not-run ({', '.join(info['missing'])})")
        else:
            print(f"- {tc}: blocked ({', '.join(info['missing'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
