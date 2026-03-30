import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


MODE = os.environ.get("MODE") or os.environ.get("ROLE", "web")


AUTH_DOC = """<!DOCTYPE html><html id="__next_error__"><head><script src="/_next/static/chunks/main-app.js"></script></head><body><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"route-auth"])</script></body></html>"""
REGISTER_DOC = """<!DOCTYPE html><html id="__next_error__"><head><script src="/_next/static/chunks/main-app.js"></script></head><body><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"route-register-password"])</script></body></html>"""
GENERIC_SHELL = """<!DOCTYPE html><html id="__next_error__"><head><script src="/_next/static/chunks/main-app.js"></script></head><body><div>SampleApp</div><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"generic-shell"])</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = {
        "web": "Apache/2.4",
        "next": "next-mock/1.0",
        "appjson": "app-json/1.0",
    }.get(MODE, "mock/1.0")

    def log_message(self, format, *args):
        return

    def _write(self, code: int, body: bytes, content_type: str, extra_headers: dict[str, str] | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _handle_appjson(self):
        if self.headers.get("Host") != "api.example-target.local":
            self._write(404, b"not found", "text/plain")
            return
        content_length = int(self.headers.get("Content-Length") or "0")
        if content_length:
            self.rfile.read(content_length)
        payload = {
            "ResData": {
                "ResHeader": {
                    "command": "5667",
                    "commandVersion": "0001",
                    "rtnCode": "0900" if "text/plain" in (self.headers.get("Content-Type") or "") else "0000",
                    "rtnMessage": "mock",
                },
                "ResBody": {
                    "MemberInfo": {"badgeYn": "Y"},
                    "AgreementInfo": {"walletAccept3Yn": "N"},
                },
            }
        }
        self._write(200, json.dumps(payload).encode("utf-8"), "application/json")

    def do_GET(self):
        if MODE == "web":
            if "${jndi:" in (self.headers.get("X-Test") or ""):
                time.sleep(20)
                return
            if self.headers.get("Host") != "www.example-target.local":
                self._write(404, b"not found", "text/plain")
                return
            self._write(
                302,
                b"",
                "text/html; charset=iso-8859-1",
                {"Location": "https://www.example-target.local/notice.do"},
            )
            return

        if MODE == "next":
            if self.path == "/__lab/upgrade101":
                if self.headers.get("Upgrade", "").lower() == "websocket":
                    self.send_response_only(101, "Switching Protocols")
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.end_headers()
                    self.close_connection = True
                    return
                self._write(400, b"missing upgrade", "text/plain")
                return
            if self.headers.get("Host") != "auth.example-target.local":
                self._write(200, GENERIC_SHELL.encode("utf-8"), "text/html; charset=utf-8")
                return
            if self.path.startswith("/gold-platform/register-password/"):
                self._write(200, REGISTER_DOC.encode("utf-8"), "text/html; charset=utf-8")
                return
            self._write(200, AUTH_DOC.encode("utf-8"), "text/html; charset=utf-8")
            return

        self._handle_appjson()

    def do_POST(self):
        if MODE == "appjson":
            self._handle_appjson()
            return
        self._write(405, b"method not allowed", "text/plain")


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
