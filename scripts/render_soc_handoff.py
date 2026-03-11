#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from common import load_structured, load_template, render_template


def load_rows(path: str) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def build_query_windows(rows: list[dict[str, str]]) -> str:
    windows: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in rows:
        ts = row.get("timestamp", "")
        proto = row.get("protocol", "") or "UNKNOWN"
        date_key = ts[:10] if ts else "unknown-date"
        windows[(date_key, proto)].append(ts)

    lines = []
    for (date_key, proto), timestamps in sorted(windows.items()):
        timestamps = [ts for ts in timestamps if ts]
        start = min(timestamps) if timestamps else ""
        end = max(timestamps) if timestamps else ""
        lines.append(f"- {date_key} {proto}: {start} ~ {end} ({len(timestamps)} rows)")
    return "\n".join(lines) if lines else "- No timestamps available"


def build_key_findings(metadata: dict, rows: list[dict[str, str]]) -> str:
    findings = metadata.get("high_level_findings")
    if isinstance(findings, list) and findings:
        return "\n".join(f"- {item}" for item in findings)

    tcs = sorted({row.get("tc", "") for row in rows if row.get("tc", "")})
    return "\n".join(
        [
            f"- Total rows: {len(rows)}",
            f"- Distinct TCs: {', '.join(tcs) if tcs else 'none'}",
            f"- Environment mode: {metadata.get('environment_mode', 'unknown')}",
            f"- SSL visibility: {metadata.get('ssl_visibility', 'unknown')}",
            f"- Callback state: {metadata.get('callback_state', 'unknown')}",
        ]
    )


def build_constraints(metadata: dict) -> str:
    bits = []
    if metadata.get("ssl_visibility") == "unavailable":
        bits.append("HTTPS visibility unavailable")
    if str(metadata.get("callback_state", "")).lower() in {
        "unstable",
        "infra-unstable",
        "not-reliable",
        "unreliable",
    }:
        bits.append("Callback infrastructure unstable")
    blocked = metadata.get("blocked_tcs") or []
    if blocked:
        bits.append("Blocked TCs: " + ", ".join(blocked))
    return "\n".join(f"- {bit}" for bit in bits) if bits else "- None"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render SOC handoff Markdown from manifest metadata and CSV.")
    parser.add_argument("--metadata", required=True, help="Structured metadata JSON/YAML")
    parser.add_argument("--csv", required=True, help="Normalized combined CSV")
    parser.add_argument("--output", required=True, help="Markdown output path")
    parser.add_argument("--template", help="Optional custom Markdown template path")
    args = parser.parse_args()

    metadata = load_structured(args.metadata)
    rows = load_rows(args.csv)
    template = load_template(args.template, "soc_handoff.md.tmpl")

    mapping = {
        "run_id": metadata.get("run_id", ""),
        "source_ip": metadata.get("source_ip", ""),
        "timezone": metadata.get("timezone", ""),
        "environment_mode": metadata.get("environment_mode", ""),
        "ssl_visibility": metadata.get("ssl_visibility", ""),
        "callback_state": metadata.get("callback_state", ""),
        "key_findings": build_key_findings(metadata, rows),
        "query_windows": build_query_windows(rows),
        "constraints": build_constraints(metadata),
        "combined_csv": args.csv,
        "row_count": len(rows),
        "manifest_path": metadata.get("manifest_path", args.metadata),
    }
    rendered = render_template(template, mapping)
    Path(args.output).write_text(rendered.rstrip() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
