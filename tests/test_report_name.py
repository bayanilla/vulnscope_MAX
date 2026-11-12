import json
import os
import re
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from http.server import ThreadingHTTPServer

from vulnflow import runname
from vulnflow.correlate import Config
from vulnflow.samples import generate


class RunNameTests(unittest.TestCase):
    def test_clean_trims_and_limits(self):
        r = runname.clean("  Plant 3\n review  ", "line one  \r\n\r\n\r\n\r\nline   two" + "x" * 3000)
        self.assertEqual(r["name"], "Plant 3 review")
        self.assertTrue(r["description"].startswith("line one\n\nline two"))
        self.assertEqual(len(r["description"]), runname.DESCRIPTION_MAX)
        self.assertEqual(runname.clean(None, None), {"name": "", "description": ""})

    def test_slug_is_folder_and_url_safe(self):
        self.assertEqual(runname.slug("Múcaro / Q4: review ../etc"), "Mucaro-Q4-review-etc")
        self.assertEqual(runname.slug("..."), "")
        self.assertRegex(runname.slug("a" * 300), r"^a{60}$")

    def test_new_run_names_and_timestamps(self):
        data = tempfile.mkdtemp()
        now = datetime(2026, 11, 12, 10, 19, 14)
        self.assertEqual(runname.new_run(data, "Plant 3 review", now), "Plant-3-review_2026-11-12_10-19-14")
        self.assertEqual(runname.new_run(data, "Plant 3 review", now), "Plant-3-review_2026-11-12_10-19-14-2")
        unnamed = runname.new_run(data, "", now)
        self.assertRegex(unnamed, r"^[0-9a-f]{16}_2026-11-12_10-19-14$")
        self.assertRegex(runname.new_run(data, "日本", now), r"^[0-9a-f]{16}_2026-11-12_10-19-14$")
        for name in os.listdir(data):
            self.assertRegex(name, rf"^{runname.RUN_ID}$")
        self.assertRegex("0123456789abcdef", rf"^{runname.RUN_ID}$")      # older runs still open
        self.assertNotRegex("..", rf"^{runname.RUN_ID}$")


class WebReportNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.samples = generate(os.path.join(cls.tmp, "in"))

    def serve(self, sub):
        from vulnflow.web import make_handler
        data = os.path.join(self.tmp, sub)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(data, Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        with urllib.request.urlopen(base + "/") as resp:
            page = resp.read().decode()
        self.assertIn('id="report_name"', page)
        self.assertIn('id="report_description"', page)
        return base, data, re.search(r'name="csrf" value="([^"]+)"', page)[1]

    def test_named_upload_saved_with_name_and_timestamp(self):
        base, data, csrf = self.serve("named")
        boundary = uuid.uuid4().hex
        part = lambda name, value: (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                                    f"{value}\r\n").encode()
        body = part("csrf", csrf) + part("report_name", "Plant 3 <review>") + \
            part("report_description", "Case 42.\r\n\r\nAsked by the <b>plant</b> manager.")
        for p in self.samples:
            with open(p, "rb") as fh:
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"folder\"; "
                         f"filename=\"bundle/{os.path.basename(p)}\"\r\n"
                         "Content-Type: application/octet-stream\r\n\r\n").encode() + fh.read() + b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(base + "/analyze", data=body,
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req) as resp:
            index, run_url = resp.read().decode(), resp.url
        self.assertRegex(run_url, r"/runs/Plant-3-review_\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d/$")
        self.assertEqual(os.listdir(data), [run_url.rstrip("/").rsplit("/", 1)[1]])  # temp folder renamed
        self.assertIn("<h1>Plant 3 &lt;review&gt;</h1>", index)
        self.assertIn("Asked by the &lt;b&gt;plant&lt;/b&gt; manager.", index)
        with urllib.request.urlopen(run_url + "results.json") as resp:
            self.assertEqual(json.load(resp)["report"], {"name": "Plant 3 <review>",
                                                         "description": "Case 42.\n\nAsked by the <b>plant</b> manager."})
        for page in ("executive_summary.html", "technical_report.html"):
            with urllib.request.urlopen(run_url + page) as resp:
                text = resp.read().decode()
            self.assertIn("<strong>Report:</strong> Plant 3 &lt;review&gt;", text)
            self.assertIn("<title>Plant 3 &lt;review&gt; · ", text)
            self.assertNotIn("<b>plant</b>", text)
        with urllib.request.urlopen(run_url + "explorer.html") as resp:
            text = resp.read().decode()
        self.assertIn('<span id="report-name" title="Case 42.', text)
        self.assertIn(">Plant 3 &lt;review&gt;</span>", text)
        with urllib.request.urlopen(base + "/") as resp:       # the next analysis starts empty
            self.assertIn('id="report_name" type="text" name="report_name" value=""', resp.read().decode())

    def test_unnamed_folder_run_keeps_id_plus_timestamp(self):
        base, data, csrf = self.serve("unnamed")
        form = {"path": os.path.dirname(self.samples[0]), "csrf": csrf}
        with urllib.request.urlopen(urllib.request.Request(base + "/analyze-folder",
                                                           data=urllib.parse.urlencode(form).encode())) as resp:
            index, run_url = resp.read().decode(), resp.url
        self.assertRegex(run_url, r"/runs/[0-9a-f]{16}_\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d/$")
        self.assertIn("<h1>Results</h1>", index)
        with urllib.request.urlopen(run_url + "results.json") as resp:
            self.assertEqual(json.load(resp)["report"], {"name": "", "description": ""})
        with urllib.request.urlopen(run_url + "executive_summary.html") as resp:
            self.assertNotIn("Report:", resp.read().decode())
        with urllib.request.urlopen(run_url + "ai-status") as resp:     # run routes accept the new ids
            self.assertEqual(resp.status, 200)

    def test_failed_folder_run_keeps_typed_details(self):
        base, data, csrf = self.serve("failed")
        form = {"path": "/no/such/folder", "csrf": csrf, "report_name": "Kept", "report_description": "Still here"}
        with urllib.request.urlopen(urllib.request.Request(base + "/analyze-folder",
                                                           data=urllib.parse.urlencode(form).encode())) as resp:
            page = resp.read().decode()
        self.assertIn("Folder not found", page)
        self.assertIn('name="report_name" value="Kept"', page)
        self.assertIn(">Still here</textarea>", page)
        self.assertFalse(os.path.exists(data) and os.listdir(data))


if __name__ == "__main__":
    unittest.main()
