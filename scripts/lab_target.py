#!/usr/bin/env python3
"""Deliberately vulnerable lab target for King Malhare validation.

This server contains no real secrets and must never be exposed to the internet.
It exists so scanner adapters can be validated end-to-end on localhost.
Usage: python3 scripts/lab_target.py [port]
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3000


class LabHandler(BaseHTTPRequestHandler):
    server_version = "KingMalhareLab/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):  # quieter output
        print("[lab] " + fmt % args)

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8"):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Powered-By", "LabFramework/0.1")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, """<!doctype html><html><head><title>King Malhare Lab</title></head>
<body><h1>Authorized test target</h1><p>This server intentionally omits security headers.</p>
<a href="/admin">Admin</a> · <a href="/api">API</a></body></html>""")
        elif path == "/.env":
            self._send(200, "APP_ENV=lab\nDB_PASSWORD=lab-not-real\nJWT_SECRET=lab-not-real\n", "text/plain")
        elif path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n", "text/plain")
        elif path in {"/actuator/env", "/actuator/health"}:
            self._send(200, json.dumps({"activeProfiles": ["lab"], "propertySources": [{"name": "lab"}], "status": "UP"}), "application/json")
        elif path == "/openapi.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "paths": {"/api": {}}}), "application/json")
        elif path == "/admin":
            self._send(200, "<html><body><h1>Admin console</h1></body></html>")
        elif path == "/api":
            self._send(200, json.dumps({"ok": True, "service": "lab"}), "application/json")
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        else:
            self._send(404, "<html><body>Not found</body></html>")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        path = self.path.split("?")[0]
        if path != "/login":
            self._send(404, "<html><body>Not found</body></html>")
            return
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            data = {}
        username = str(data.get("username", ""))
        password = str(data.get("password", ""))
        if username == "lab-tester" and password == "LabPassword-123!":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "labsession=valid-session-value; Path=/")  # intentionally missing HttpOnly/Secure/SameSite
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        elif username == "lab-tester":
            # Deliberately no rate limit or lockout.
            self._send(401, '{"error":"invalid credentials"}', "application/json")
        else:
            self._send(401, '{"error":"invalid credentials"}', "application/json")


if __name__ == "__main__":
    print(f"King Malhare lab target listening on http://127.0.0.1:{PORT}")
    print("WARNING: deliberately insecure. Localhost only. Never expose this server.")
    ThreadingHTTPServer(("127.0.0.1", PORT), LabHandler).serve_forever()
