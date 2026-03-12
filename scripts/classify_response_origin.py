#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
import zlib
from pathlib import Path


def parse_header_text(text: str) -> tuple[str, dict[str, str]]:
    lines = [line for line in text.splitlines() if line.strip()]
    status = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status, headers


def decode_body_bytes(body_bytes: bytes, headers: dict[str, str]) -> str:
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body_bytes = dechunk_body(body_bytes)
    encoding = headers.get("content-encoding", "").lower()
    decoded = body_bytes
    try:
        if encoding == "gzip":
            decoded = gzip.decompress(body_bytes)
        elif encoding == "deflate":
            decoded = zlib.decompress(body_bytes)
        elif encoding == "br":
            try:
                import brotli  # type: ignore

                decoded = brotli.decompress(body_bytes)
            except Exception:
                proc = subprocess.run(
                    [
                        "node",
                        "-e",
                        (
                            "const fs=require('fs');"
                            "const zlib=require('zlib');"
                            "const input=fs.readFileSync(0);"
                            "process.stdout.write(zlib.brotliDecompressSync(input));"
                        ),
                    ],
                    input=body_bytes,
                    capture_output=True,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout:
                    decoded = proc.stdout
    except Exception:
        decoded = body_bytes
    return decoded.decode("utf-8", errors="replace")


def dechunk_body(body_bytes: bytes) -> bytes:
    pos = 0
    out = bytearray()
    total = len(body_bytes)
    while pos < total:
        line_end = body_bytes.find(b"\r\n", pos)
        if line_end == -1:
            return body_bytes
        size_line = body_bytes[pos:line_end].split(b";", 1)[0].strip()
        if not size_line:
            return body_bytes
        try:
            size = int(size_line, 16)
        except ValueError:
            return body_bytes
        pos = line_end + 2
        if size == 0:
            return bytes(out)
        if pos + size > total:
            return body_bytes
        out.extend(body_bytes[pos:pos + size])
        pos += size
        if body_bytes[pos:pos + 2] != b"\r\n":
            return body_bytes
        pos += 2
    return bytes(out)


def load_record_from_pair(header_path: Path, body_path: Path) -> dict[str, object]:
    header_text = header_path.read_text(encoding="utf-8", errors="replace") if header_path.exists() else ""
    status_line, headers = parse_header_text(header_text)
    body_bytes = body_path.read_bytes() if body_path.exists() else b""
    body_text = decode_body_bytes(body_bytes, headers) if body_bytes else ""
    return {
        "label": header_path.stem,
        "status_line": status_line,
        "headers": headers,
        "body_text": body_text,
        "source": str(header_path),
    }


def load_record_from_meta(meta_path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    preview = str(data.get("response_preview", "") or "")
    if not preview:
        return {
            "label": meta_path.stem.replace("_meta", ""),
            "status_line": "",
            "headers": {},
            "body_text": "",
            "source": str(meta_path),
        }
    if "\r\n\r\n" in preview:
        header_text, body_text = preview.split("\r\n\r\n", 1)
    else:
        header_text, body_text = preview, ""
    return {
        "label": meta_path.stem.replace("_meta", ""),
        "status_line": parse_header_text(header_text)[0],
        "headers": parse_header_text(header_text)[1],
        "body_text": body_text,
        "source": str(meta_path),
    }


def classify(record: dict[str, object], shared_counts: dict[str, int]) -> dict[str, object]:
    headers = dict(record.get("headers") or {})
    body_text = str(record.get("body_text") or "")
    status_line = str(record.get("status_line") or "")
    server = headers.get("server", "")
    content_type = headers.get("content-type", "")
    body_hash = hashlib.sha256(body_text.encode("utf-8", errors="replace")).hexdigest() if body_text else ""
    shared_count = shared_counts.get(body_hash, 0) if body_hash else 0
    indicators: list[str] = []

    if not status_line and not body_text:
        return {
            "label": record["label"],
            "likely_origin": "network-drop-or-hold",
            "confidence": "medium",
            "status_line": "",
            "server": "",
            "body_sha256": "",
            "shared_body_count": 0,
            "indicators": ["no_http_response"],
            "rationale": "No HTTP status line or body was captured.",
            "source": record["source"],
        }

    if server:
        indicators.append(f"server={server}")
    if content_type:
        indicators.append(f"content_type={content_type}")
    if shared_count > 1:
        indicators.append(f"shared_body_count={shared_count}")

    lower_body = body_text.lower()
    server_lower = server.lower()
    likely = "unknown"
    confidence = "low"
    rationale = "The available signals do not uniquely identify the response owner."

    json_like = "json" in content_type.lower()

    if "whitelabel error page" in lower_body or (
        json_like
        and all(token in body_text for token in ['"timestamp"', '"status"', '"error"', '"path"'])
    ):
        likely = "upstream-spring-likely"
        confidence = "high"
        rationale = "The body matches Spring-style default error structure."
    elif "__next_f.push" in body_text or "/_next/static/" in body_text or 'id="__next' in lower_body:
        likely = "upstream-nextjs-likely"
        confidence = "high"
        rationale = "The body matches a Next.js route or shell document."
    elif "apache tomcat" in lower_body or "type status report" in lower_body or "http status 403" in lower_body:
        likely = "upstream-tomcat-likely"
        confidence = "high"
        rationale = "The body matches Tomcat-style error report markup."
    elif json_like and (
        all(token in body_text for token in ['"code"', '"message"'])
        or ("\"ResData\"" in body_text and "\"ResHeader\"" in body_text)
    ):
        likely = "upstream-app-likely"
        confidence = "high" if "\"ResData\"" in body_text and "\"ResHeader\"" in body_text else "medium"
        rationale = "The body is structured application JSON rather than a shared static edge page."
    elif re.search(r"\b30[1278]\b", status_line) and headers.get("location"):
        likely = "front-web-likely"
        confidence = "medium"
        rationale = "The response is a redirect with an explicit Location header, which is commonly emitted by the web tier."
    elif re.search(r"\b400\b", status_line) and (
        "not found(400)" in lower_body or len(body_text.strip()) <= 64
    ):
        likely = "front-web-likely"
        confidence = "medium"
        rationale = "The response is a short 400-style HTML body more consistent with front-side rejection than application JSON."
    elif any(token in server_lower for token in ["cloudflare", "akamai", "imperva", "incapsula", "cloudfront"]):
        likely = "edge-waf-likely"
        confidence = "high"
        rationale = "The visible responder exposes edge or WAF vendor markers."
    elif "nginx" in server_lower and (
        "<title>error page</title>" in lower_body
        or "history.back()" in lower_body
        or "일시적인 시스템장애" in body_text
        or shared_count > 1
    ):
        likely = "front-nginx-likely"
        confidence = "high" if shared_count > 1 else "medium"
        rationale = "The response looks like a shared nginx or front proxy error page."
    elif re.search(r"\b40[034]\b", status_line) and "nginx" in server_lower:
        likely = "front-nginx-likely"
        confidence = "medium"
        rationale = "The visible responder is nginx, but the body is not distinctive enough to prove whether the app contributed."

    return {
        "label": record["label"],
        "likely_origin": likely,
        "confidence": confidence,
        "status_line": status_line,
        "server": server,
        "body_sha256": body_hash,
        "shared_body_count": shared_count,
        "indicators": indicators,
        "rationale": rationale,
        "source": record["source"],
    }


def collect_records(directory: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for header_path in sorted(directory.rglob("*.hdr")):
        body_path = header_path.with_suffix(".body")
        records.append(load_record_from_pair(header_path, body_path))
    for meta_path in sorted(directory.rglob("*_meta.json")):
        record = load_record_from_meta(meta_path)
        if record is not None:
            records.append(record)
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify likely error-response origin conservatively.")
    parser.add_argument("--directory", help="Directory containing .hdr/.body pairs and optional *_meta.json previews")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    if not args.directory:
        raise SystemExit("--directory is required")

    records = collect_records(Path(args.directory))
    body_hashes = [
        hashlib.sha256(str(record.get("body_text") or "").encode("utf-8", errors="replace")).hexdigest()
        for record in records
        if str(record.get("body_text") or "")
    ]
    shared_counts = {body_hash: body_hashes.count(body_hash) for body_hash in set(body_hashes)}
    result = [classify(record, shared_counts) for record in records]
    payload = {"records": result}

    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
