"""HTTP plumbing every page shares: the host and access-token gate, origin and CSRF checks,
reading bodies, writing responses and routing. Pages are plain functions ``view(req, *groups)``
listed in routes.py; ``req`` is the Handler for the current request."""
from __future__ import annotations

import json
import os
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote

from . import routes
from .app import App

LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")
TOKEN_COOKIE = "vulnscope_access"
SECURITY_HEADERS = {
    # The pages carry their own inline scripts and styles; nothing loads from other origins.
    "Content-Security-Policy": ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
                                "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"),
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",       # no-referrer would make browsers send Origin: null
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
TYPES = {".html": "text/html; charset=utf-8", ".md": "text/markdown; charset=utf-8",
         ".csv": "text/csv; charset=utf-8", ".json": "application/json",
         ".jsonl": "application/x-ndjson; charset=utf-8"}


class Handler(BaseHTTPRequestHandler):
    app: App                       # set on the subclass make_handler builds for one server
    timeout = 120                  # drop clients that stop sending mid-request

    # -- gate ---------------------------------------------------------------------------------
    def host_ok(self) -> bool:
        """Reject requests for any other host name (DNS rebinding) unless remote access is on."""
        if self.app.access_token:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.server.server_address[1]
        names = {f"{n}:{port}" for n in LOOPBACK_NAMES} | self.app.allowed_hosts
        if port == 80:
            names |= set(LOOPBACK_NAMES)
        return host in names

    def cookie(self, name: str) -> str | None:
        try:
            got = SimpleCookie(self.headers.get("Cookie") or "").get(name)
        except Exception:
            return None
        return got.value if got else None

    def token_ok(self) -> bool:
        token = self.app.access_token
        if not token:
            return True
        got = self.cookie(TOKEN_COOKIE)
        return bool(got) and secrets.compare_digest(got, token)

    def gate(self) -> bool:
        """Host and access-token checks shared by every request. Sends the refusal itself."""
        if not self.host_ok():
            self.send_text(421, "Unknown host name. Open the upload page at the address the server printed.")
            return False
        token = self.app.access_token
        if token and not self.token_ok():
            given = self.query.get("token", [""])[0]
            if self.command == "GET" and given and secrets.compare_digest(given, token):
                self.redirect(self.path.split("?", 1)[0], {
                    "Set-Cookie": f"{TOKEN_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"})
                return False
            self.send_text(401, "Open the link with the access token that the server printed at start-up.")
            return False
        return True

    def same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or origin == f"http://{self.headers.get('Host', '')}"

    # -- reading ------------------------------------------------------------------------------
    @property
    def query(self) -> dict[str, list[str]]:
        return parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}

    def length(self) -> int:
        """Content-Length as a non-negative int; -1 when missing or malformed."""
        try:
            n = int(self.headers.get("Content-Length") or "")
        except ValueError:
            return -1
        return n if n >= 0 else -1

    def read_body(self, cap: int) -> bytes | None:
        n = self.length()
        if n < 0 or n > cap:
            self.close_connection = True
            return None
        return self.rfile.read(n)

    def read_form(self, cap: int = 20000) -> dict | None:
        """A url-encoded form as {name: first value}; None when missing or larger than ``cap``."""
        raw = self.read_body(cap)
        if raw is None:
            return None
        return {k: v[0] for k, v in parse_qs(raw.decode(errors="replace")).items()}

    def read_json(self) -> dict | None:
        """A small JSON object carrying this server's CSRF token; None otherwise."""
        raw = self.read_body(20000)
        if raw is None:
            return None
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return None
        return body if isinstance(body, dict) and self.app.csrf_ok(body.get("csrf")) else None

    # -- writing ------------------------------------------------------------------------------
    def send(self, code: int, body, ctype: str = "text/html; charset=utf-8", headers: dict | None = None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, code: int, text: str):
        self.send(code, text, "text/plain")

    def send_json(self, code: int, obj, headers: dict | None = None):
        self.send(code, json.dumps(obj), "application/json", headers)

    def redirect(self, location: str, headers: dict | None = None):
        self.send(303, "", headers={"Location": location, **(headers or {})})

    def send_file(self, path: str, headers: dict | None = None):
        with open(path, "rb") as fh:
            self.send(200, fh.read(), TYPES.get(os.path.splitext(path)[1], "application/octet-stream"), headers)

    # -- routing ------------------------------------------------------------------------------
    def do_GET(self):
        if self.gate():
            self._dispatch(routes.GET, unquote(self.path.split("?", 1)[0]))

    def do_POST(self):
        if not self.gate():
            return
        if not self.same_origin():
            return self.send_text(403, "Cross-origin request refused")
        self._dispatch(routes.POST, self.path)

    def _dispatch(self, table, path: str):
        for pattern, view in table:
            m = pattern.fullmatch(path)
            if m:
                return view(self, *m.groups())
        self.send_text(404, "Not found")
