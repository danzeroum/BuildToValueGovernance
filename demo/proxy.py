#!/usr/bin/env python3
"""
BuildToValue Trust OS Demo — Proxy seguro
Serve os arquivos estaticos do demo na porta 8080
e faz proxy das chamadas /api/* para a API real (porta 8000),
injetando a BTV_API_KEY no header sem expor ao browser.

Uso: python3 demo/proxy.py
"""

import os
import json
import urllib.request
import urllib.error
from http.server import HTTPServer, SimpleHTTPRequestHandler

API_KEY  = os.environ.get("BTV_DEMO_KEY", os.environ.get("BTV_API_KEYS", "2e9854d03357579fa1a48b7cbdfc3296"))
API_BASE = os.environ.get("BTV_API_BASE", "http://localhost:8000")
DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
PORT     = int(os.environ.get("BTV_DEMO_PORT", "8080"))


class DemoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DEMO_DIR, **kwargs)

    def log_message(self, fmt, *args):  # silenciar log verboso
        if self.path.startswith("/api/"):
            print(f"  [proxy] {self.command} {self.path} → {args[1]}")

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._proxy("GET")
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._proxy("POST")
        else:
            self.send_error(405)

    def _proxy(self, method):
        target_path = self.path[4:]  # remove /api
        url = f"{API_BASE}{target_path}"

        body = None
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"

        req = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(exc)}).encode())


if __name__ == "__main__":
    os.chdir(DEMO_DIR)
    print(f"""\n  BuildToValue Trust OS — Demo Proxy
  ────────────────────────────────────
  Frontend : http://0.0.0.0:{PORT}
  API proxy: /api/* → {API_BASE}
  API key  : {'*' * 8}{API_KEY[-6:]}
  Demo dir : {DEMO_DIR}
  ────────────────────────────────────\n""")
    server = HTTPServer(("0.0.0.0", PORT), DemoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Proxy encerrado.")
