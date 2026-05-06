#!/usr/bin/env python3
"""
Simple echo server for TC-27 white-box Coraza WAF lab (:3009).

Echoes back parsed form fields, raw headers, and body so the probe
can verify what actually reached the backend after WAF inspection.
"""
from __future__ import annotations

import cgi
import os
import io
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self._respond({"method": "GET", "path": self.path, "headers": dict(self.headers)})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length else b""

        parsed_fields: dict = {}
        content_type = self.headers.get("Content-Type", "")

        if "multipart/form-data" in content_type:
            try:
                environ = {
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": str(len(raw_body)),
                }
                form = cgi.FieldStorage(
                    fp=io.BytesIO(raw_body),
                    environ=environ,
                    keep_blank_values=True,
                )
                for key in form.keys():
                    item = form[key]
                    if hasattr(item, "value"):
                        try:
                            parsed_fields[key] = item.value
                        except Exception as exc:
                            parsed_fields[key] = f"<decode-error: {exc}>"
            except Exception as exc:
                parsed_fields["_parse_error"] = str(exc)

        self._respond({
            "method": "POST",
            "path": self.path,
            "headers": dict(self.headers),
            "raw_body_hex": raw_body.hex(),
            "raw_body_bytes": len(raw_body),
            "parsed_fields": parsed_fields,
        })

    def _respond(self, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-TC27-Backend", "echo")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    server = HTTPServer(("0.0.0.0", port), EchoHandler)
    print(f"TC-27 echo backend listening on :{port}")
    server.serve_forever()
