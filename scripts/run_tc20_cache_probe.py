#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from http_probe_common import curl_request, dump_json, ensure_dir, extract_header, write_csv


def with_query(url: str, **pairs: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(pairs)
    return urlunparse(parsed._replace(query=urlencode(query)))


def file_hash(path_str: str) -> str:
    path = Path(path_str)
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-20 cache poisoning / unkeyed input probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--marker-a", default="tc20-a")
    parser.add_argument("--marker-b", default="tc20-b")
    parser.add_argument("--forwarded-host", default="attacker.invalid")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    cases = [
        ("baseline_1", args.url, []),
        ("query_variant_a", with_query(args.url, utm_source=args.marker_a), []),
        ("query_variant_b", with_query(args.url, utm_source=args.marker_b), []),
        ("header_variant", args.url, [f"X-Forwarded-Host: {args.forwarded_host}"]),
        ("baseline_2", args.url, []),
    ]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, url, headers in cases:
        result = curl_request(url=url, out_prefix=out_dir / name, headers=headers, timeout=args.timeout)
        header_text = Path(result["header_path"]).read_text(encoding="utf-8", errors="replace") if Path(result["header_path"]).exists() else ""
        metadata = {
            "case": name,
            "url": url,
            "headers": headers,
            "http_code": result["http_code"],
            "cache_age": extract_header(header_text, "Age"),
            "x_cache": extract_header(header_text, "X-Cache"),
            "cf_cache_status": extract_header(header_text, "CF-Cache-Status"),
            "body_fingerprint": file_hash(result["body_path"]),
            "result": result,
        }
        dump_json(out_dir / f"{name}.meta.json", metadata)
        summary["cases"].append(metadata)
        rows.append(
            {
                "case": name,
                "url": url,
                "http_code": result["http_code"],
                "age": metadata["cache_age"],
                "x_cache": metadata["x_cache"],
                "cf_cache_status": metadata["cf_cache_status"],
                "body_fingerprint": metadata["body_fingerprint"],
                "header_path": result["header_path"],
                "body_path": result["body_path"],
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "url", "http_code", "age", "x_cache", "cf_cache_status", "body_fingerprint", "header_path", "body_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
