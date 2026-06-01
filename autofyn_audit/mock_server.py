#!/usr/bin/env python3
"""
mock_server.py — Stdlib-only HTTP collector + fake internal target.

No pip installs required. Python 3.6+.

Endpoints:
  GET /ssrf-target          — Returns HTML with SSRF canary token in <title> and og:description.
  GET /latest/meta-data/    — Fake AWS metadata endpoint (same canary HTML).
  GET /__hits?since=<ts>    — Returns JSON array of hits recorded since Unix timestamp.
  ALL other paths           — Logged and returns 200 OK.

Writes:
  .audit_state/mock_hits.log  — Line-delimited JSON of every inbound request.
  .audit_state/canary.txt     — The canary UUID generated at startup.
  .audit_state/mock.pid       — PID of this process.
"""

import http.server
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9099

# The .audit_state directory lives next to this script.
SCRIPT_DIR = Path(__file__).parent
AUDIT_STATE_DIR = SCRIPT_DIR / ".audit_state"

# ---------------------------------------------------------------------------
# In-memory hit log (also flushed to disk)
# ---------------------------------------------------------------------------
HITS: List[Dict[str, Any]] = []

# Canary token — generated once at startup, written to disk so exploit scripts
# can read the same value.
CANARY_TOKEN: str = f"SSRF-CANARY-{uuid.uuid4()}"


def canary_html() -> bytes:
    """Return an HTML page embedding the canary token in multiple positions."""
    html = (
        "<!DOCTYPE html><html><head>"
        f"<title>{CANARY_TOKEN}</title>"
        f'<meta property="og:title" content="{CANARY_TOKEN}-og-title">'
        f'<meta property="og:description" content="{CANARY_TOKEN}-og-desc">'
        f'<meta name="description" content="{CANARY_TOKEN}-meta-desc">'
        "</head><body>"
        f"<h1>{CANARY_TOKEN}</h1>"
        "</body></html>"
    )
    return html.encode("utf-8")


def setup_state_dir() -> None:
    AUDIT_STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Write canary
    (AUDIT_STATE_DIR / "canary.txt").write_text(CANARY_TOKEN)

    # Write PID
    (AUDIT_STATE_DIR / "mock.pid").write_text(str(os.getpid()))

    print(f"[mock_server] Canary token: {CANARY_TOKEN}", flush=True)
    print(f"[mock_server] State dir: {AUDIT_STATE_DIR}", flush=True)
    print(f"[mock_server] PID: {os.getpid()}", flush=True)


def record_hit(method: str, path: str, headers: dict, query: dict) -> None:
    entry = {
        "ts": time.time(),
        "method": method,
        "path": path,
        "headers": headers,
        "query": query,
    }
    HITS.append(entry)

    log_path = AUDIT_STATE_DIR / "mock_hits.log"
    with log_path.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")

    print(
        f"[mock_server] HIT  {method} {path}  (total hits: {len(HITS)})",
        flush=True,
    )


class MockHandler(http.server.BaseHTTPRequestHandler):
    """Handle all incoming requests to the mock server."""

    def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
        # Suppress default request logging — we do our own.
        pass

    def _parse_request(self) -> tuple[str, dict]:
        """Return (clean_path, query_dict)."""
        parsed = urlparse(self.path)
        query = {k: v for k, v in parse_qs(parsed.query).items()}
        return parsed.path, query

    def _collect_headers(self) -> dict:
        return dict(self.headers.items())

    def do_GET(self) -> None:
        path, query = self._parse_request()
        headers = self._collect_headers()
        record_hit("GET", path, headers, query)

        if path in ("/ssrf-target", "/ssrf-target/"):
            self._respond_canary()
        elif path.startswith("/latest/meta-data"):
            self._respond_canary()
        elif path == "/__hits":
            self._respond_hits(query)
        else:
            self._respond_ok(f"Mock server — hit recorded for {path}".encode())

    def do_POST(self) -> None:
        path, query = self._parse_request()
        headers = self._collect_headers()
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        record_hit("POST", path, headers, {**query, "_body": body.decode(errors="replace")})
        self._respond_ok(b"POST recorded")

    def do_HEAD(self) -> None:
        path, query = self._parse_request()
        headers = self._collect_headers()
        record_hit("HEAD", path, headers, query)
        self.send_response(200)
        self.end_headers()

    # -----------------------------------------------------------------
    # Response helpers
    # -----------------------------------------------------------------

    def _respond_canary(self) -> None:
        body = canary_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_hits(self, query: dict) -> None:
        since_list = query.get("since", ["0"])
        try:
            since = float(since_list[0]) if isinstance(since_list, list) else float(since_list)
        except (ValueError, IndexError, TypeError):
            since = 0.0

        filtered = [h for h in HITS if h["ts"] >= since]
        body = json.dumps(filtered).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_ok(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    setup_state_dir()

    server = http.server.HTTPServer((LISTEN_HOST, LISTEN_PORT), MockHandler)
    print(
        f"[mock_server] Listening on {LISTEN_HOST}:{LISTEN_PORT}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[mock_server] Shutting down.", flush=True)
        server.server_close()


if __name__ == "__main__":
    main()
