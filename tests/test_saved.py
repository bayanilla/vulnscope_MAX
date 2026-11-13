"""Reopening a saved results.json (and explorer.html) from the upload page."""
import http.client
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import unittest.mock
import urllib.parse
from http.server import ThreadingHTTPServer

from vulnflow import saved
from vulnflow.correlate import RESULTS_SCHEMA_VERSION, Config
from vulnflow.pipeline import run
from vulnflow.samples import generate
from vulnflow.web import SAVED_SANDBOX, make_handler


class SavedRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "first_run")
        run(generate(os.path.join(cls.tmp, "in")), cls.out)
        with open(os.path.join(cls.out, "results.json"), "rb") as fh:
            cls.results = fh.read()
        with open(os.path.join(cls.out, "explorer.html"), "rb") as fh:
            cls.explorer = fh.read()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(cls.tmp, "runs"), Config()))
        cls.port = cls.srv.server_port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, True)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.port}", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read().decode(errors="replace")
        conn.close()
        return resp.status, data, resp

    def post_folder(self, folder, action="/analyze-folder"):
        token = re.search(r'name="csrf" value="([^"]+)"', self.request("GET", "/")[1])[1]
        body = urllib.parse.urlencode({"csrf": token, "path": folder})
        return self.request("POST", action, body, {"Content-Type": "application/x-www-form-urlencoded"})

    def opened(self, folder, action="/analyze-folder"):
        status, page, resp = self.post_folder(folder, action)
        self.assertEqual(status, 303, page)
        return resp.getheader("Location")

    def copy(self, name, edit=None):
        """A copy of the first run's output folder, optionally edited."""
        folder = os.path.join(self.tmp, name)
        shutil.copytree(self.out, folder)
        if edit:
            edit(folder)
        return folder

    def test_report_folder_reopens_without_reanalyzing(self):
        before = os.listdir(self.out)
        here = self.opened(self.out)
        self.assertEqual(sorted(os.listdir(self.out)), sorted(before))       # folder left as it was
        status, index, _ = self.request("GET", here)
        self.assertEqual(status, 200)
        self.assertIn("Saved report reopened from", index)
        for name in ("explorer.html", "normalized/flows.csv", "normalized/findings.csv", "correlated_findings.csv"):
            self.assertIn(name, index)
        for name in ("executive_summary.html", "technical_report.html", "explorer.html", "correlated_findings.csv",
                     "normalized/flows.csv"):
            status, _, resp = self.request("GET", here + name)
            self.assertEqual(status, 200, name)
            self.assertIn(SAVED_SANDBOX, resp.getheader("Content-Security-Policy"), name)
        with open(os.path.join(self.out, "normalized", "flows.csv"), encoding="utf-8", newline="") as fh:
            self.assertEqual(self.request("GET", here + "normalized/flows.csv")[1], fh.read())
        page = self.request("GET", here + "explorer.html")[1]
        old = json.loads(re.search(r'id="vf-data" type="application/json">(.*?)</script>', self.explorer.decode(), re.S)[1])
        new = json.loads(re.search(r'id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
        self.assertEqual(old["nodes"], new["nodes"])
        self.assertEqual(old["links"], new["links"])
        self.assertEqual(json.loads(self.request("GET", here + "results.json")[1]), json.loads(self.results))

    def test_page_can_tell_a_report_folder_from_a_data_folder(self):
        token = re.search(r'name="csrf" value="([^"]+)"', self.request("GET", "/")[1])[1]

        def kind(path, csrf=token):
            status, body, _ = self.request("POST", "/folder-kind", json.dumps({"csrf": csrf, "path": path}),
                                           {"Content-Type": "application/json"})
            return status, json.loads(body)
        self.assertEqual(kind(self.out), (200, {"report": True}))
        self.assertEqual(kind(os.path.join(self.tmp, "in")), (200, {"report": False}))
        self.assertEqual(kind(os.path.join(self.tmp, "missing")), (200, {"report": False}))
        self.assertEqual(kind(""), (200, {"report": False}))
        self.assertEqual(kind(self.out, "wrong")[0], 403)

    def test_only_listed_files_are_served_from_the_folder(self):
        folder = self.copy("extra", lambda f: open(os.path.join(f, "secret.txt"), "w").write("x"))
        here = self.opened(folder)
        for name in ("secret.txt", "../secret.txt", "normalized/../secret.txt", "%2e%2e/%2e%2e/etc/passwd"):
            self.assertEqual(self.request("GET", here + name)[0], 404, name)

    def test_folder_without_explorer_opens_reports_and_says_why(self):
        here = self.opened(self.copy("no_explorer", lambda f: os.remove(os.path.join(f, "explorer.html"))))
        index = self.request("GET", here)[1]
        self.assertIn("no <code>explorer.html</code>", index)
        self.assertEqual(self.request("GET", here + "explorer.html")[0], 404)
        self.assertEqual(self.request("GET", here + "technical_report.html")[0], 200)

    def test_fresh_runs_are_not_sandboxed(self):
        self.assertEqual(json.loads(self.results)["schema_version"], RESULTS_SCHEMA_VERSION)
        os.makedirs(os.path.join(self.tmp, "runs", "a" * 16, "out"), exist_ok=True)
        shutil.copy(os.path.join(self.out, "technical_report.html"), os.path.join(self.tmp, "runs", "a" * 16, "out"))
        _, _, resp = self.request("GET", f"/runs/{'a' * 16}/technical_report.html")
        self.assertNotIn("sandbox", resp.getheader("Content-Security-Policy"))

    def assertRefused(self, folder, message):
        runs = os.path.join(self.tmp, "runs")
        before = set(os.listdir(runs)) if os.path.isdir(runs) else set()
        status, page, _ = self.post_folder(folder)
        self.assertEqual(status, 200)
        self.assertIn(message, page)
        self.assertEqual(set(os.listdir(runs)) - before if os.path.isdir(runs) else set(), set())   # nothing left behind

    def test_bad_folders_are_refused_with_a_reason(self):
        res = json.loads(self.results)

        def results(obj):
            def edit(f):
                with open(os.path.join(f, "results.json"), "wb") as fh:
                    fh.write(obj if isinstance(obj, bytes) else json.dumps(obj).encode())
            return edit

        def explorer(text):
            return lambda f: open(os.path.join(f, "explorer.html"), "wb").write(text)

        self.assertRefused(self.copy("b1", results(b"{not json")), "not valid JSON")
        self.assertRefused(self.copy("b2", results(b'{"a":' * 100000 + b"1" + b"}" * 100000)), "nested too deeply")
        self.assertRefused(self.copy("b3", results({**res, "schema_version": RESULTS_SCHEMA_VERSION + 1})), "newer VulnScope")
        self.assertRefused(self.copy("b4", results({**res, "hosts": "x"})), "&quot;hosts&quot; is missing")
        self.assertRefused(self.copy("b5", results({**res, "findings": [{"host": "10.0.0.1"}]})), "can&#x27;t be drawn")
        other = self.explorer.replace(res["generated"].encode(), b"2001-01-01T00:00:00Z")
        self.assertRefused(self.copy("b6", explorer(other)), "different analysis")
        self.assertRefused(self.copy("b7", explorer(b"<!doctype html><p>hi")), "not a VulnScope Explorer page")

    def test_results_without_schema_version_still_open(self):
        res = json.loads(self.results)
        del res["schema_version"]
        self.opened(self.copy("legacy", lambda f: open(os.path.join(f, "results.json"), "w").write(json.dumps(res))))

    def test_oversized_results_are_refused(self):
        with unittest.mock.patch.object(saved, "MAX_SAVED_FILE", 1000):
            self.assertRefused(self.out, "too large to reopen")


if __name__ == "__main__":
    unittest.main()
