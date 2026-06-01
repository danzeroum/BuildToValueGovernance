#!/usr/bin/env python3
"""
BuildToValue Trust OS Demo — Secure Proxy
Serves static demo files and proxies /api/* calls to the BTV API,
injecting the BTV_API_KEY. Uses ThreadingHTTPServer so that long-running
DeepSeek streams do not block simultaneous forensic evidence downloads.

Usage:
  python3 demo/proxy.py
  BTV_DEMO_PORT=9090 DEEPSEEK_API_KEY=sk-xxx python3 demo/proxy.py
"""

import json
import os
import socket
import time
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

API_KEY         = os.environ.get("BTV_DEMO_KEY", os.environ.get("BTV_API_KEYS", "demo-key"))
API_BASE        = os.environ.get("BTV_API_BASE", "http://localhost:8000")
DEMO_USER       = os.environ.get("BTV_DEMO_USER", "admin")
DEMO_PASSWORD   = os.environ.get("BTV_DEMO_PASSWORD", "")  # fail-secure: vazio = somente-leitura
RUST_API_BASE   = os.environ.get("BTV_RUST_BASE", "http://localhost:8080")
DEEPSEEK_KEY    = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE   = os.environ.get("DEEPSEEK_BASE", "https://api.deepseek.com")
DEMO_DIR        = os.path.dirname(os.path.abspath(__file__))
PORT            = int(os.environ.get("BTV_DEMO_PORT", "8080"))

# Routes that go to Rust/Axum (port 8080 / RUST_API_BASE)
RUST_ROUTES = [
    "/v1/validate",
    "/v1/sanitize",
    "/v1/decide",
    "/v1/trust/",
    "/v1/proxy/",
    "/health",
    "/metrics",
]

# Simple in-memory GET cache (TTL 5s)
_cache: dict = {}

def _cache_get(key: str):
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < 5:
        return entry["data"]
    return None

def _cache_set(key: str, data: bytes):
    _cache[key] = {"data": data, "ts": time.time()}


class ReuseAddrThreadingServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with SO_REUSEADDR — each request gets its own thread."""
    allow_reuse_address = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class DemoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DEMO_DIR, **kwargs)

    def log_message(self, fmt, *args):
        if "/api/" in self.path or "/deepseek/" in self.path:
            print(f"  [proxy] {self.command} {self.path} → {args[1] if args else '?'}")

    # ── CORS preflight ────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._proxy("GET")
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/demo-login":
            self._demo_login()
        elif self.path.startswith("/api/"):
            self._proxy("POST")
        elif self.path.startswith("/deepseek/"):
            self._deepseek_proxy()
        else:
            self.send_error(405, "Method Not Allowed")

    # ── BTV API proxy ─────────────────────────────────────
    def _proxy(self, method: str):
        target_path = self.path[4:]  # remove /api prefix

        # Route to Rust or Python
        api_base = RUST_API_BASE if any(target_path.startswith(r) for r in RUST_ROUTES) else API_BASE
        url = f"{api_base}{target_path}"

        # Read body
        body = None
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"

        # GET cache
        cache_key = f"{method}:{url}"
        if method == "GET":
            cached = _cache_get(cache_key)
            if cached:
                self._write_json(200, cached)
                return

        req = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers=self._build_headers(self.headers.get("Authorization")),
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                if method == "GET" and resp.status == 200:
                    _cache_set(cache_key, data)
                self._write_json(resp.status, data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self._write_json(e.code, data)
        except Exception as exc:
            err = json.dumps({"error": str(exc), "action": "BLOCK", "rationale": "Proxy error — fail-secure"})
            self._write_json(502, err.encode())

    # ── DeepSeek proxy ────────────────────────────────────
    def _deepseek_proxy(self):
        if not DEEPSEEK_KEY:
            err = json.dumps({"error": "DEEPSEEK_API_KEY not configured"})
            self._write_json(503, err.encode())
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"

        url = f"{DEEPSEEK_BASE}/v1/chat/completions"
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {DEEPSEEK_KEY}",
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            self._write_json(e.code, e.read())
        except Exception as exc:
            err = json.dumps({"error": str(exc)})
            self._write_json(503, err.encode())

    # ── Demo login ────────────────────────────────────────
    def _demo_login(self) -> None:
        """POST /demo-login — obtém JWT do backend com credenciais de ambiente.

        Fail-secure: BTV_DEMO_PASSWORD ausente ou vazio → 403 imediato.
        A senha nunca é logada — apenas o estado da decisão.
        Não aplica cache (POST, sem efeito colateral idempotente).
        """
        if not DEMO_PASSWORD:
            print("[DEMO-AUTH] Decision: BLOCK. Reason: Password not provisioned.")
            payload = json.dumps({
                "action": "BLOCK",
                "verdict": "DENY",
                "reason": "Missing BTV_DEMO_PASSWORD environment variable. Fail-Secure enforced.",
            }).encode()
            self._write_json(403, payload)
            return

        url = f"{API_BASE}/v1/auth/login"
        body = json.dumps({"username": DEMO_USER, "password": DEMO_PASSWORD}).encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                print(f"[DEMO-AUTH] Decision: ALLOW. User: {DEMO_USER}")
                self._write_json(resp.status, data)
        except urllib.error.HTTPError as e:
            print(f"[DEMO-AUTH] Decision: BLOCK. Reason: Backend returned {e.code}.")
            self._write_json(e.code, e.read())
        except Exception as exc:
            print(f"[DEMO-AUTH] Decision: BLOCK. Reason: {exc}")
            err = json.dumps({"action": "BLOCK", "verdict": "DENY", "reason": str(exc)}).encode()
            self._write_json(502, err)

    def _build_headers(self, auth_header: Optional[str]) -> Dict[str, str]:
        """Monta headers de saída: injeta API key; repassa Bearer do browser se presente."""
        headers_out: Dict[str, str] = {
            "X-API-Key": API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if auth_header:
            headers_out["Authorization"] = auth_header
        return headers_out

    # ── Helpers ───────────────────────────────────────────
    def _write_json(self, status: int, data: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")


if __name__ == "__main__":
    os.chdir(DEMO_DIR)
    has_deepseek = bool(DEEPSEEK_KEY)
    print(f"""
  BuildToValue Trust OS — Demo Proxy (ThreadingHTTPServer)
  ────────────────────────────────────────────────────────────
  Frontend  : http://0.0.0.0:{PORT}
  API proxy : /api/* → Rust ({RUST_API_BASE}) | Python ({API_BASE})
  DeepSeek  : {'✓ Configured' if has_deepseek else '✗ Not configured (set DEEPSEEK_API_KEY)'}
  API key   : {'*' * 8}{API_KEY[-6:] if len(API_KEY) > 6 else '***'}
  Demo dir  : {DEMO_DIR}
  ────────────────────────────────────────────────────────────
  Pages:
    http://localhost:{PORT}/              Home
    http://localhost:{PORT}/dashboard.html
    http://localhost:{PORT}/lab.html
    http://localhost:{PORT}/proxy-demo.html
    http://localhost:{PORT}/sanitizer-demo.html
    http://localhost:{PORT}/ledger-explorer.html
  ────────────────────────────────────────────────────────────
""")
    server = ReuseAddrThreadingServer(("0.0.0.0", PORT), DemoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Proxy encerrado.")
