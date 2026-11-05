"""Regression tests for the security review findings (web server, settings, parsers, exports)."""
import csv
import gzip
import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from vulnflow.correlate import Config
from vulnflow.llm import LLMConfig, LLMError
from vulnflow.parsers import _util, nessus
from vulnflow.report import _cell
from vulnflow.schema import ParseStats
from vulnflow.web import make_handler, serve


class _Server:
    def __init__(self, tmp, llm_cfg=None, access_token=None):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            os.path.join(tmp, "runs"), Config(), llm_cfg, access_token=access_token))
        self.port = self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read().decode(errors="replace")
        conn.close()
        return resp.status, data, resp

    def token(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.request("GET", "/")[1])[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class WebSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def server(self, **kw):
        s = _Server(self.tmp, **kw)
        self.addCleanup(s.close)
        return s

    def test_foreign_host_header_is_refused(self):
        s = self.server()
        self.assertEqual(s.request("GET", "/")[0], 200)
        self.assertEqual(s.request("GET", "/", host=f"localhost:{s.port}")[0], 200)
        status, _, _ = s.request("GET", "/", host=f"evil.example:{s.port}")
        self.assertEqual(status, 421)
        token = s.token()
        body = json.dumps({"csrf": token, "path": "/"})
        status, data, _ = s.request("POST", "/browse", body, {
            "Content-Type": "application/json", "Origin": f"http://evil.example:{s.port}"},
            host=f"evil.example:{s.port}")
        self.assertEqual(status, 421)
        self.assertNotIn("dirs", data)

    def test_security_headers(self):
        _, _, resp = self.server().request("GET", "/")
        self.assertIn("frame-ancestors 'none'", resp.headers["Content-Security-Policy"])
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")

    def test_upload_requires_csrf_token(self):
        s = self.server()
        b = "xyz"
        body = (f"--{b}\r\nContent-Disposition: form-data; name=\"telemetry\"; filename=\"a.log\"\r\n\r\n"
                f"hello\r\n--{b}--\r\n")
        status, _, _ = s.request("POST", "/analyze", body, {"Content-Type": f"multipart/form-data; boundary={b}"})
        self.assertEqual(status, 403)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "runs")) if os.path.isdir(os.path.join(self.tmp, "runs")) else [], [])

    def test_bad_content_length_is_rejected_without_blocking(self):
        s = self.server()
        token = s.token()
        status, _, _ = s.request("POST", "/analyze-folder", f"csrf={token}", {
            "Content-Type": "application/x-www-form-urlencoded", "Content-Length": "-1"})
        self.assertEqual(status, 400)

    def _save(self, s, **form):
        form.setdefault("action", "save")
        form["csrf"] = s.token()
        return s.request("POST", "/settings", urllib.parse.urlencode(form),
                         {"Content-Type": "application/x-www-form-urlencoded"})

    def test_changing_endpoint_drops_the_stored_key(self):
        cfg = LLMConfig(provider="openai", model="m", api_key="sk-typed-1234").resolved()
        s = self.server(llm_cfg=cfg)
        status, body, _ = self._save(s, provider="openai", model="m", base_url="https://attacker.example/v1")
        self.assertEqual(status, 400)
        self.assertIn("needs an API key", body)
        # same endpoint, blank key: the stored key is kept
        status, _, _ = self._save(s, provider="openai", model="m2", base_url="")
        self.assertEqual(status, 303)

    def test_environment_key_never_goes_to_a_browser_chosen_endpoint(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-5678"}):
            s = self.server(llm_cfg=LLMConfig())
            status, body, _ = self._save(s, provider="openai", model="m", base_url="https://attacker.example/v1")
            self.assertEqual(status, 400)
            self.assertIn("needs an API key", body)
            status, _, _ = self._save(s, provider="openai", model="m")      # default endpoint may use it
            self.assertEqual(status, 303)

    def test_key_is_never_sent_over_plain_http_to_another_machine(self):
        with self.assertRaises(LLMError):
            LLMConfig(provider="openai", model="m", api_key="k", base_url="http://203.0.113.5/v1").resolved()
        LLMConfig(provider="local", model="m", api_key="k", base_url="http://127.0.0.1:11434/v1").resolved()

    def test_remote_mode_requires_access_token(self):
        s = self.server(access_token="secret-token")
        self.assertEqual(s.request("GET", "/", host="192.0.2.10:8080")[0], 401)
        status, _, resp = s.request("GET", "/?token=secret-token", host="192.0.2.10:8080")
        self.assertEqual(status, 303)
        cookie = resp.headers["Set-Cookie"].split(";", 1)[0]
        self.assertIn("HttpOnly", resp.headers["Set-Cookie"])
        self.assertEqual(s.request("GET", "/", headers={"Cookie": cookie}, host="192.0.2.10:8080")[0], 200)
        self.assertEqual(s.request("GET", "/", headers={"Cookie": "vulnscope_access=wrong"})[0], 401)

    def test_serve_refuses_non_loopback_without_flag(self):
        with self.assertRaises(SystemExit):
            serve("0.0.0.0", 0, os.path.join(self.tmp, "r"), Config())


class ParserSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_gzip_bomb_is_capped(self):
        p = os.path.join(self.tmp, "conn.log.gz")
        with gzip.open(p, "wb") as fh:
            fh.write(b"A" * (4 * 1024 * 1024))
        with mock.patch.dict(os.environ, {"VULNSCOPE_MAX_GZ_BYTES": str(1024 * 1024)}):
            with self.assertRaises(_util.DecompressionLimit):
                with _util.open_text(p) as fh:
                    while fh.read(65536):
                        pass

    def test_nessus_doctype_is_refused(self):
        p = os.path.join(self.tmp, "scan.nessus")
        with open(p, "w") as fh:
            fh.write('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
                     '<NessusClientData_v2><Report name="t"></Report></NessusClientData_v2>')
        with self.assertRaises(ValueError):
            nessus.parse_xml(p, ParseStats(file="scan.nessus", fmt="nessus"))

    def test_csv_formula_cells_are_neutralised(self):
        self.assertEqual(_cell("=HYPERLINK(\"http://x\")"), "'=HYPERLINK(\"http://x\")")
        self.assertEqual(_cell("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(_cell("-"), "-")
        self.assertEqual(_cell(-5), -5)
        self.assertEqual(_cell("web01"), "web01")


if __name__ == "__main__":
    unittest.main()
