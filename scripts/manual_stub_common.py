#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


def emit_manual_stub(
    *,
    tc: str,
    title: str,
    output_dir: str,
    reason: str,
    prerequisites: list[str],
    evidence: list[str],
    next_steps: list[str],
) -> None:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "tc": tc,
        "title": title,
        "automation": "manual-only",
        "status": "blocked",
        "reason": reason,
        "prerequisites": prerequisites,
        "minimum_evidence": evidence,
        "next_steps": next_steps,
    }
    (out_dir / "summary.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    lines = [
        f"# {tc} Manual Stub",
        "",
        f"- title: {title}",
        "- automation: manual-only",
        "- status: blocked",
        f"- reason: {reason}",
        "",
        "## Prerequisites",
        *[f"- {item}" for item in prerequisites],
        "",
        "## Minimum Evidence",
        *[f"- {item}" for item in evidence],
        "",
        "## Next Steps",
        *[f"- {item}" for item in next_steps],
        "",
    ]
    (out_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
