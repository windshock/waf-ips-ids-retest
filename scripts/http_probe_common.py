#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


def ensure_dir(path_str: str | Path) -> Path:
    path = Path(path_str)
    path.mkdir(parents=True, exist_ok=True)
    return path


def dump_json(path: str | Path, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: str | Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return scheme, host, port, path


def parse_status_line(header_text: str) -> str:
    first = header_text.splitlines()[0] if header_text else ""
    parts = first.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return parts[1]
    return "000"


def extract_header(header_text: str, name: str) -> str:
    needle = name.lower() + ":"
    for line in header_text.splitlines():
        if line.lower().startswith(needle):
            return line.split(":", 1)[1].strip()
    return ""


def body_fingerprint(data: bytes) -> str:
    if not data:
        return ""
    return hashlib.sha256(data).hexdigest()[:16]


def curl_request(
    *,
    url: str,
    out_prefix: Path,
    method: str = "GET",
    headers: Iterable[str] | None = None,
    body_path: Path | None = None,
    timeout: int = 15,
    extra_args: Iterable[str] | None = None,
) -> dict:
    hdr_path = out_prefix.with_suffix(".hdr")
    body_out = out_prefix.with_suffix(".body")
    cmd = [
        "curl",
        "-m",
        str(timeout),
        "-sS",
        "-o",
        str(body_out),
        "-D",
        str(hdr_path),
        "-w",
        "%{http_code}",
        "-X",
        method,
        url,
    ]
    for header in headers or []:
        cmd.extend(["-H", header])
    if body_path is not None:
        cmd.extend(["--data-binary", f"@{body_path}"])
    if extra_args:
        cmd.extend(list(extra_args))
    proc = subprocess.run(cmd, text=True, capture_output=True)
    header_text = hdr_path.read_text(encoding="utf-8", errors="replace") if hdr_path.exists() else ""
    body_bytes = body_out.read_bytes() if body_out.exists() else b""
    result = {
        "http_code": proc.stdout.strip() or "000",
        "curl_rc": proc.returncode,
        "stderr": proc.stderr.strip(),
        "header_path": str(hdr_path),
        "body_path": str(body_out),
        "server_header": extract_header(header_text, "Server"),
        "content_type": extract_header(header_text, "Content-Type"),
        "body_fingerprint": body_fingerprint(body_bytes),
        "body_size": len(body_bytes),
    }
    dump_json(out_prefix.with_suffix(".json"), result)
    return result


def send_raw_http(
    *,
    scheme: str,
    connect_host: str,
    port: int,
    request_bytes: bytes,
    timeout: int = 15,
    sni: str | None = None,
) -> bytes:
    raw = socket.create_connection((connect_host, port), timeout=timeout)
    sock = raw
    if scheme == "https":
        context = ssl.create_default_context()
        sock = context.wrap_socket(raw, server_hostname=sni or connect_host)
    try:
        sock.sendall(request_bytes)
        sock.settimeout(timeout)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


def split_http_response(raw_response: bytes) -> tuple[str, bytes]:
    if not raw_response:
        return "", b""
    marker = b"\r\n\r\n"
    if marker not in raw_response:
        return raw_response.decode("latin-1", errors="replace"), b""
    header_bytes, body = raw_response.split(marker, 1)
    return header_bytes.decode("latin-1", errors="replace"), body


def save_raw_http_artifacts(out_prefix: Path, request_text: str, response_bytes: bytes) -> dict:
    req_path = out_prefix.with_suffix(".request.txt")
    raw_resp_path = out_prefix.with_suffix(".raw")
    hdr_path = out_prefix.with_suffix(".hdr")
    body_path = out_prefix.with_suffix(".body")
    req_path.write_text(request_text, encoding="utf-8")
    raw_resp_path.write_bytes(response_bytes)
    header_text, body_bytes = split_http_response(response_bytes)
    hdr_path.write_text(header_text, encoding="utf-8")
    body_path.write_bytes(body_bytes)
    result = {
        "http_code": parse_status_line(header_text),
        "header_path": str(hdr_path),
        "body_path": str(body_path),
        "raw_response_path": str(raw_resp_path),
        "server_header": extract_header(header_text, "Server"),
        "content_type": extract_header(header_text, "Content-Type"),
        "body_fingerprint": body_fingerprint(body_bytes),
        "body_size": len(body_bytes),
    }
    dump_json(out_prefix.with_suffix(".json"), result)
    return result
