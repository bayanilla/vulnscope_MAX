"""Which analysis errors the upload page shows: a problem the person can fix (UserError) is shown
and its run folder dropped; anything else is a bug, so the page says only that it failed and the
details go to the server console."""
import contextlib
import io
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from vulnflow.correlate import Config
from vulnflow.errors import UserError
from vulnflow.pipeline import check_internal_nets
from vulnflow.samples import generate
from vulnflow.web import make_handler


class AnalysisErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.folder = os.path.dirname(generate(os.path.join(cls.tmp, "in"))[0])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def analyze(self, sub, **form):
        data = os.path.join(self.tmp, sub)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(data, Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_port}"
        with urllib.request.urlopen(base + "/") as resp:
            csrf = re.search(r'name="csrf" value="([^"]+)"', resp.read().decode())[1]
        body = urllib.parse.urlencode({"csrf": csrf, "path": self.folder, **form}).encode()
        with urllib.request.urlopen(urllib.request.Request(base + "/analyze-folder", data=body)) as resp:
            return resp.read().decode(), data

    def runs(self, data):
        return sorted(os.listdir(data)) if os.path.isdir(data) else []

    def test_problem_the_person_can_fix_is_shown(self):
        with mock.patch("vulnflow.web.upload.run", side_effect=UserError("No network telemetry <here>.")):
            page, data = self.analyze("user-error")
        self.assertIn("No network telemetry &lt;here&gt;.", page)
        self.assertEqual(self.runs(data), [])                       # nothing left half-made

    def test_bug_is_not_shown(self):
        console = io.StringIO()
        with mock.patch("vulnflow.web.upload.run", side_effect=ValueError("secret detail /srv/x")), \
                contextlib.redirect_stderr(console):
            page, data = self.analyze("bug")
        self.assertIn("The analysis failed; see the server console for details.", page)
        self.assertNotIn("secret detail", page)
        self.assertIn("secret detail /srv/x", console.getvalue())  # the traceback is on the console
        self.assertEqual(len(self.runs(data)), 1)                   # kept for a look at what went wrong

    def test_internal_network_typo_is_explained(self):
        with contextlib.redirect_stderr(io.StringIO()):
            page, data = self.analyze("nets", internal_nets="10.0.0.0/8, 10.1.0.0/33")
        self.assertIn("Internal networks: &#x27;10.1.0.0/33&#x27; is not an address range.", page)
        self.assertEqual(self.runs(data), [])
        check_internal_nets(["10.0.0.0/8", "192.168.1.7/24", "fd00::/8"])
        with self.assertRaises(UserError):
            check_internal_nets(["corp-lan"])


if __name__ == "__main__":
    unittest.main()
