import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


MODE = os.environ.get("MODE", "appjson")


class Handler(BaseHTTPRequestHandler):
    server_version = {
        "tomcat": "Apache Tomcat/9.0",
        "spring": "spring-mock/1.0",
        "appjson": "app-json/1.0",
        "hold": "hold-mock/1.0",
    }.get(MODE, "mock/1.0")

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if MODE == "hold":
            time.sleep(15)
            return
        if MODE == "spring":
            payload = {
                "timestamp": "2026-03-11T00:00:00.000+00:00",
                "status": 403,
                "error": "Forbidden",
                "path": self.path,
            }
            body = json.dumps(payload).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if MODE == "tomcat":
            body = b"""<html><head><title>Apache Tomcat/9.0 - Error report</title></head>
<body><h1>HTTP Status 403 \xe2\x80\x93 Forbidden</h1><hr><p><b>type</b> Status report</p></body></html>"""
            self.send_response(403)
            self.send_header("Content-Type", "text/html;charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps(
            {"code": "40310", "message": "Blocked by business rule", "detailMessage": ""}
        ).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
