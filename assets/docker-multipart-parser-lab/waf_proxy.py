from __future__ import annotations

import http.client
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer


BACKEND_HOST = os.environ.get("BACKEND_HOST", "lab-backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8080"))
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


def waf_decoded_value(data: bytes, content_type: str) -> str:
    charset = (extract_header_param(content_type, "charset") or "utf-8").lower().replace("_", "-")
    if charset not in {"utf-8", "utf8"}:
        return ""
    return data.decode("utf-8", errors="replace")


def parse_waf_multipart(content_type: str, body: bytes) -> dict[str, object]:
    values = boundary_values(content_type)
    if not values:
        return {"boundary": "", "values": [], "notes": ["no-boundary"]}
    boundary = values[-1]
    marker = b"--" + boundary.encode("ascii", errors="replace")
    close_marker = marker + b"--"
    lines = body.split(b"\r\n")

    decoded_values: list[str] = []
    notes: list[str] = []
    idx = 0
    closed = False
    while idx < len(lines):
        line = lines[idx]
        if line.strip() == close_marker:
            closed = True
            if line != close_marker:
                notes.append("accepted-close-marker-trailing-whitespace")
            break
        if line != marker:
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
        headers = parse_part_headers(header_lines, duplicate_policy="last")
        decoded_values.append(waf_decoded_value(b"\r\n".join(value_lines), headers.get("content-type", "")))

    return {
        "boundary": boundary,
        "value_count": len(decoded_values),
        "values": decoded_values,
        "closed": closed,
        "decoded_contains_attack": any(ATTACK_MARKER in value for value in decoded_values),
        "notes": notes,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "multipart-waf-lab/1.0"

    def log_message(self, format, *args):
        return

    def write_json(self, code: int, payload: dict[str, object]):
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Lab-Waf-Decision", "block" if code == 403 else "pass")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.write_json(200, {"ok": True, "role": "waf"})
            return
        self.write_json(404, {"ok": False, "error": "not-found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type") or ""
        waf_view = parse_waf_multipart(content_type, body)
        if waf_view.get("decoded_contains_attack"):
            self.write_json(
                403,
                {
                    "role": "waf",
                    "decision": "block",
                    "reason": "attack-marker-in-waf-parsed-multipart-value",
                    "waf_view": waf_view,
                },
            )
            return

        forward_headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"connection", "host", "content-length"}
        }
        forward_headers["Content-Length"] = str(len(body))
        forward_headers["Host"] = self.headers.get("Host") or "multipart.example.local"
        connection = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=10)
        try:
            connection.request(self.command, self.path, body=body, headers=forward_headers)
            response = connection.getresponse()
            response_body = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() in {"connection", "transfer-encoding", "content-length"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("X-Lab-Waf-Decision", "pass")
            self.send_header("X-Lab-Waf-Parsed-Values", str(waf_view.get("value_count", "")))
            self.end_headers()
            self.wfile.write(response_body)
        finally:
            connection.close()


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
