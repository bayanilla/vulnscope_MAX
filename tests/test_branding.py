"""Analyst branding: the name before "VulnScope" and a small logo, set from the upload page."""
import base64
import os
import shutil
import struct
import tempfile
import unittest
import uuid
import zlib
from unittest import mock

from vulnflow import branding, explore, report
try:
    from tests.test_security import _Server
except ImportError:                       # run from inside tests/
    from test_security import _Server


def png(w=32, h=16):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    raw = b"".join(b"\x00" + b"\x00\x00\x00\x00" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def multipart_body(fields, files=()):
    boundary = uuid.uuid4().hex
    out = b""
    for k, v in fields.items():
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    for name, filename, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


class BrandingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.dict(os.environ, {"VULNSCOPE_HOME": os.path.join(self.tmp, "home")})
        patch.start()
        self.addCleanup(patch.stop)

    def test_default_is_mucaro(self):
        self.assertEqual(branding.product_name(), "Múcaro VulnScope")
        self.assertTrue(branding.icon_data_uri().startswith("data:image/svg+xml"))
        self.assertEqual(branding.logo_img(), "")

    def test_prefix_cleaning(self):
        self.assertEqual(branding.clean_prefix("  Ford   Motor "), "Ford Motor")
        self.assertEqual(branding.clean_prefix("Ford VulnScope"), "Ford")
        self.assertEqual(branding.clean_prefix(""), "")
        with self.assertRaises(branding.BrandingError):
            branding.clean_prefix("x" * 41)
        with self.assertRaises(branding.BrandingError):
            branding.clean_prefix("Ford‮")          # right-to-left override
        with self.assertRaises(branding.BrandingError):
            branding.clean_prefix("Ford\x00")

    def test_logo_checks_content_not_name(self):
        self.assertEqual(branding.sniff_logo(png()), "image/png")
        for bad in (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
                    b"<html><script>alert(1)</script></html>", b"", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20):
            with self.assertRaises(branding.BrandingError):
                branding.sniff_logo(bad)
        with self.assertRaises(branding.BrandingError):
            branding.sniff_logo(png(4000, 10))
        with self.assertRaises(branding.BrandingError):
            branding.sniff_logo(png() + b"\x00" * branding.MAX_LOGO_BYTES)

    def test_saved_branding_reaches_reports_and_explorer(self):
        branding.update("Ford", png())
        self.assertEqual(branding.product_name(), "Ford VulnScope")
        self.assertTrue(branding.icon_data_uri().startswith("data:image/png;base64,"))
        bar = report.theme_control()
        self.assertIn('class="brand-logo" src="data:image/png;base64,', bar)
        self.assertIn("Ford VulnScope", bar)
        page = explore.html({"nodes": [], "edges": [], "focus": {}, "ioc_matches": []})
        self.assertIn('<meta name="application-name" content="Ford VulnScope">', page)
        self.assertIn('<img class="brand-logo" src="data:image/png;base64,', page)
        self.assertIn("Ford <b>VULNSCOPE</b>", page)
        self.assertNotIn("<!--BRAND-->", page)

    def test_prefix_is_escaped_everywhere(self):
        branding.update('<img src=x onerror=alert(1)>"')
        self.assertNotIn("<img src=x", report.theme_control())
        page = explore.html({"nodes": [], "edges": [], "focus": {}, "ioc_matches": []})
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img src=x", page)

    def test_keep_and_remove_logo(self):
        branding.update("Ford", png())
        branding.update("Acme")
        self.assertIsNotNone(branding.load().logo)
        branding.update("Acme", remove_logo=True)
        self.assertIsNone(branding.load().logo)

    def test_corrupt_file_falls_back_to_default(self):
        branding.update("Ford")
        branding.config_path().write_text('{"prefix": "Ford", "logo": "' +
                                          base64.b64encode(b"<svg/>").decode() + '"}')
        self.assertEqual(branding.load(), branding.Branding())

    def _server(self):
        s = _Server(self.tmp)
        self.addCleanup(s.close)
        return s

    def test_branding_page_saves_name_and_logo(self):
        s = self._server()
        self.assertIn('href="/branding"', s.request("GET", "/")[1])
        body, headers = multipart_body({"csrf": s.token(), "prefix": "Ford"}, [("logo", "ford.png", png())])
        status, _, resp = s.request("POST", "/branding", body, headers)
        self.assertEqual(status, 303)
        self.assertEqual(branding.product_name(), "Ford VulnScope")
        page = s.request("GET", "/")[1]
        self.assertIn("<title>Ford VulnScope</title>", page)
        self.assertIn('class="brand-logo" src="data:image/png;base64,', page)

    def test_branding_page_refuses_svg_and_missing_csrf(self):
        s = self._server()
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
        body, headers = multipart_body({"csrf": s.token(), "prefix": "Ford"}, [("logo", "logo.png", svg)])
        status, data, _ = s.request("POST", "/branding", body, headers)
        self.assertEqual(status, 400)
        self.assertIn("SVG", data)
        self.assertEqual(branding.product_name(), "Múcaro VulnScope")
        body, headers = multipart_body({"csrf": "wrong", "prefix": "Evil"})
        self.assertEqual(s.request("POST", "/branding", body, headers)[0], 403)
        self.assertEqual(branding.product_name(), "Múcaro VulnScope")

    def test_branding_reset(self):
        s = self._server()
        branding.update("Ford", png())
        body, headers = multipart_body({"csrf": s.token(), "action": "reset"})
        self.assertEqual(s.request("POST", "/branding", body, headers)[0], 303)
        self.assertEqual(branding.load(), branding.Branding())


if __name__ == "__main__":
    unittest.main()
