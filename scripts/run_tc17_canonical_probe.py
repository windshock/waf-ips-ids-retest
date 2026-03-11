#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from http_probe_common import dump_json, ensure_dir, parse_url, save_raw_http_artifacts, send_raw_http, write_csv


def build_get_request(path: str, lines: list[str]) -> str:
    return "\r\n".join([f"GET {path} HTTP/1.1", *lines, "Connection: close", "", ""])


def build_post_request(path: str, lines: list[str], body: str) -> str:
    return "\r\n".join(
        [
            f"POST {path} HTTP/1.1",
            *lines,
            f"Content-Length: {len(body.encode('utf-8'))}",
            "Connection: close",
            "",
            body,
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-17 duplicate header and canonicalization probes.")
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://target.example/")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--conflict-host", default="admin.internal.example")
    parser.add_argument("--forwarded-host", default="admin.internal.example")
    parser.add_argument("--original-url", default="/admin")
    parser.add_argument("--auth-primary", default="Bearer safe-token")
    parser.add_argument("--auth-secondary", default="Bearer override-token")
    parser.add_argument("--post-body", default='{"probe":"tc17"}')
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    scheme, host, port, path = parse_url(args.url)
    common = [f"Host: {host}", "User-Agent: RETEST-TC17"]

    cases = {
        "baseline_get": build_get_request(path, common),
        "duplicate_host": build_get_request(path, [f"Host: {host}", f"Host: {args.conflict_host}", "User-Agent: RETEST-TC17"]),
        "duplicate_x_forwarded_host": build_get_request(
            path,
            common + [f"X-Forwarded-Host: {host}", f"X-Forwarded-Host: {args.forwarded_host}"],
        ),
        "duplicate_x_original_url": build_get_request(
            path,
            common + [f"X-Original-URL: {path}", f"X-Original-URL: {args.original_url}"],
        ),
        "duplicate_authorization": build_get_request(
            path,
            common + [f"Authorization: {args.auth_primary}", f"Authorization: {args.auth_secondary}"],
        ),
        "te_notation_variant": build_get_request(
            path,
            common + ["Transfer-Encoding: chunked", "Transfer_Encoding: chunked"],
        ),
        "duplicate_content_type_post": build_post_request(
            path,
            common + ["Content-Type: application/json", "Content-Type: text/plain"],
            args.post_body,
        ),
    }

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, request_text in cases.items():
        out_prefix = out_dir / name
        response = send_raw_http(
            scheme=scheme,
            connect_host=host,
            port=port,
            request_bytes=request_text.encode("utf-8"),
            sni=host,
        )
        result = save_raw_http_artifacts(out_prefix, request_text, response)
        result["case"] = name
        summary["cases"].append(result)
        rows.append(
            {
                "case": name,
                "http_code": result["http_code"],
                "server_header": result["server_header"],
                "content_type": result["content_type"],
                "body_fingerprint": result["body_fingerprint"],
                "body_size": str(result["body_size"]),
                "header_path": result["header_path"],
                "body_path": result["body_path"],
                "request_path": str(out_prefix.with_suffix(".request.txt")),
            }
        )

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        ["case", "http_code", "server_header", "content_type", "body_fingerprint", "body_size", "header_path", "body_path", "request_path"],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
