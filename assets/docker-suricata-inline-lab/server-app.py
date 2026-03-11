#!/usr/bin/env python3
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-http/1.0"

    def _write(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/ok":
            self._write(200, b"ok\n")
            return
        if self.path == "/blocked":
            self._write(200, b"blocked-ok\n")
            return
        self._write(404, b"not-found\n")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = {
            "path": self.path,
            "length": len(body),
            "content_type": self.headers.get("Content-Type", ""),
            "body_preview": body.decode("utf-8", errors="replace")[:200],
        }
        self._write(200, json.dumps(payload).encode("utf-8"), "application/json")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
