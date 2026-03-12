import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


MODE = os.environ.get("MODE", "web")


AUTH_DOC = """<!DOCTYPE html><html id="__next_error__"><head><script src="/_next/static/chunks/main-app.js"></script></head><body><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"route-auth"])</script></body></html>"""
REGISTER_DOC = """<!DOCTYPE html><html id="__next_error__"><head><script src="/_next/static/chunks/main-app.js"></script></head><body><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"route-register-password"])</script></body></html>"""
GENERIC_SHELL = """<!DOCTYPE html><html id="__next_error__"><head><script src="/_next/static/chunks/main-app.js"></script></head><body><div>Syrup</div><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"generic-shell"])</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
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

    def do_GET(self):
        if MODE == "web":
            if "${jndi:" in (self.headers.get("X-Test") or ""):
                time.sleep(20)
                return
            if self.headers.get("Host") != "www.syrup.co.kr":
                self._write(404, b"not found", "text/plain")
                return
            self._write(
                302,
                b"",
                "text/html; charset=iso-8859-1",
                {"Location": "https://www.syrup.co.kr/notice.do"},
            )
            return

        if MODE == "next":
            if self.headers.get("Host") != "nxt.syrup.co.kr":
                self._write(200, GENERIC_SHELL.encode("utf-8"), "text/html; charset=utf-8")
                return
            if self.path.startswith("/gold-platform/register-password/"):
                self._write(200, REGISTER_DOC.encode("utf-8"), "text/html; charset=utf-8")
                return
            self._write(200, AUTH_DOC.encode("utf-8"), "text/html; charset=utf-8")
            return

        if self.headers.get("Host") != "syrup-appif.smartwallet.co.kr":
            self._write(404, b"not found", "text/plain")
            return
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


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
