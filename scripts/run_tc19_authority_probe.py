#!/usr/bin/env python3
from __future__ import annotations

import argparse

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-19 authority/host/forwarded mismatch probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--host-mismatch", default="evil.invalid")
    parser.add_argument("--forwarded-host", default="admin.internal.example")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    cases = [
        ("baseline_http2", []),
        ("host_mismatch", [f"Host: {args.host_mismatch}"]),
        ("x_forwarded_host", [f"X-Forwarded-Host: {args.forwarded_host}"]),
        ("forwarded_header", [f"Forwarded: host={args.forwarded_host};proto=http"]),
        ("proto_port_mismatch", ["X-Forwarded-Proto: http", "X-Forwarded-Port: 80"]),
    ]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, headers in cases:
        result = curl_request(
            url=args.url,
            out_prefix=out_dir / name,
            headers=headers,
            timeout=args.timeout,
            extra_args=["--http2"],
        )
        metadata = {"case": name, "headers": headers, "result": result}
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "content_type": result["content_type"],
                "body_fingerprint": result["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "http_code", "server_header", "content_type", "body_fingerprint", "header_path", "body_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
