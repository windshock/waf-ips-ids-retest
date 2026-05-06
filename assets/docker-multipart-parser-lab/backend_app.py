from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer


ATTACK_MARKER = os.environ.get("ATTACK_MARKER", "__RETEST_MULTIPART_ATTACK_MARKER__")


def boundary_values(content_type: str) -> list[str]:
    values: list[str] = []
    for item in content_type.split(";")[1:]:
        key, _, value = item.strip().partition("=")
        if key.lower() != "boundary":
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if value:
            values.append(value)
    return values


def extract_header_param(value: str, name: str) -> str:
    pattern = re.compile(r'(?:^|;)\s*' + re.escape(name) + r'=(?:"([^"]*)"|([^;]*))', re.I)
    match = pattern.search(value)
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").strip()


def parse_part_headers(lines: list[bytes], duplicate_policy: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in lines:
        line = raw.decode("latin-1", errors="replace")
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        lowered = key.strip().lower()
        if duplicate_policy == "first" and lowered in headers:
            continue
        headers[lowered] = value.strip()
    return headers


def decode_value(data: bytes, content_type: str, default: str = "utf-8") -> str:
    charset = extract_header_param(content_type, "charset") or default
    normalized = charset.lower().replace("_", "-")
    aliases = {
        "utf16": "utf-16",
        "utf-16": "utf-16",
        "utf16le": "utf-16le",
        "ucs2": "utf-16le",
        "utf16be": "utf-16be",
    }
    codec = aliases.get(normalized, normalized)
    try:
        return data.decode(codec, errors="replace")
    except LookupError:
        return data.decode(default, errors="replace")


def parse_backend_multipart(content_type: str, body: bytes) -> dict[str, object]:
    values = boundary_values(content_type)
    if not values:
        return {"boundary": "", "fields": {}, "notes": ["no-boundary"]}
    boundary = values[0]
    marker = b"--" + boundary.encode("ascii", errors="replace")
    close_marker = marker + b"--"
    lines = body.replace(b"\r\n", b"\n").split(b"\n")

    fields: dict[str, str] = {}
    notes: list[str] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if line == close_marker:
            break
        if line != marker:
            if line.startswith(close_marker):
                notes.append("ignored-malformed-close-marker")
            idx += 1
            continue

        idx += 1
        header_lines: list[bytes] = []
        while idx < len(lines) and lines[idx] != b"":
            header_lines.append(lines[idx])
            idx += 1
        idx += 1

        value_lines: list[bytes] = []
        while idx < len(lines) and not lines[idx].startswith(marker):
            value_lines.append(lines[idx])
            idx += 1
        headers = parse_part_headers(header_lines, duplicate_policy="first")
        disposition = headers.get("content-disposition", "")
        name = extract_header_param(disposition, "name") or f"field_{len(fields)}"
        value_bytes = b"\n".join(value_lines)
        fields[name] = decode_value(value_bytes, headers.get("content-type", ""))

    decoded_values = "\n".join(fields.values())
    return {
        "boundary": boundary,
        "fields": fields,
        "field_count": len(fields),
        "raw_contains_attack": ATTACK_MARKER.encode("utf-8") in body,
        "decoded_contains_attack": ATTACK_MARKER in decoded_values,
        "notes": notes,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "multipart-backend-lab/1.0"

    def log_message(self, format, *args):
        return

    def write_json(self, code: int, payload: dict[str, object]):
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.write_json(200, {"ok": True, "role": "backend"})
            return
        self.write_json(404, {"ok": False, "error": "not-found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type") or ""
        parsed = parse_backend_multipart(content_type, body)
        self.write_json(
            200,
            {
                "role": "backend",
                "path": self.path,
                "content_type": content_type,
                "body_size": len(body),
                "parser": "backend-first-boundary-flex-line-ending-first-part-header",
                "parsed": parsed,
            },
        )


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
