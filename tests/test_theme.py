"""Graphite is the default theme: every page starts in it, and the browser's saved choice (key
vulnflow-theme) replaces it. SOC Dark stays in the list."""
import os
import re
import shutil
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from vulnflow import compare, explore, report
from vulnflow.correlate import Config
from vulnflow.web import make_handler
from vulnflow.web.pages import page

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vulnflow", "static")


class DefaultThemeTests(unittest.TestCase):
    def test_graphite_is_the_default_and_listed_first(self):
        self.assertEqual(report.DEFAULT_THEME, "graphite")
        self.assertEqual(report.THEMES[0], ("graphite", "Graphite"))
        self.assertIn(("dark", "SOC Dark"), report.THEMES)           # still in the picker
        self.assertIn('data-theme="graphite" data-calm>', report.HTML_OPEN)
        init = report.THEME_INIT
        self.assertIn('let savedTheme = "graphite";', init)
        self.assertIn("localStorage.getItem('vulnflow-theme') || \"graphite\"", init)
        self.assertIn('supportedThemes.has(name) ? name : "graphite"', init)
        self.assertNotIn("'dark'", init)
        self.assertIn('root.dataset.theme:"graphite"', report.theme_control())

    def test_explorer_uses_the_same_default(self):
        with open(os.path.join(STATIC, "explorer.js"), encoding="utf-8") as fh:
            js = fh.read()
        self.assertEqual(re.search(r"const DEFAULT_THEME = '([^']+)';", js)[1], report.DEFAULT_THEME)
        self.assertNotIn("themeName = 'dark'", js)

    def test_generated_pages_open_in_the_default_theme(self):
        pages = {
            "report": report.md_to_html("# Findings\n\nNone.", "Technical report"),
            "server page": page("Settings", "<p>x</p>"),
            "comparison": compare.page({"iocs": [], "vulns": []}),
            "explorer": explore.html({"nodes": [], "edges": [], "focus": {}, "ioc_matches": []}),
        }
        for name, html in pages.items():
            with self.subTest(name):
                self.assertTrue(html.startswith(report.HTML_OPEN), html[:120])

    def test_upload_page_opens_in_the_default_theme(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(tmp, "data"), Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_port}/") as resp:
            html = resp.read().decode()
        self.assertTrue(html.startswith(report.HTML_OPEN), html[:120])
        self.assertIn('<option value="graphite">Graphite</option><option value="dark">SOC Dark</option>', html)


if __name__ == "__main__":
    unittest.main()
