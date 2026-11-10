"""Analyst branding: the name before "VulnScope" and a small logo, set from the upload page."""
import base64
import os
import urllib.parse
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


TEST_PASSWORD = "Correct Horse Battery Staple"
TEST_HASH = branding.hash_password(TEST_PASSWORD, n=2 ** 14)


class BrandingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.dict(os.environ, {"VULNSCOPE_HOME": os.path.join(self.tmp, "home"),
                                             branding.PASSWORD_ENV: TEST_HASH})
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

    def test_logo_size_choice(self):
        branding.update("Ford", png())
        self.assertEqual(branding.load().logo_size, "medium")
        self.assertIn('class="brand-logo" src=', report.theme_control())
        branding.update("Ford", logo_size="small")
        self.assertIsNotNone(branding.load().logo)
        self.assertIn('class="brand-logo logo-small" src=', report.theme_control())
        page = explore.html({"nodes": [], "edges": [], "focus": {}, "ioc_matches": []})
        self.assertIn('<img class="brand-logo logo-small" src="data:image/png', page)
        branding.update("Ford")                             # no size given keeps the saved one
        self.assertEqual(branding.load().logo_size, "small")
        with self.assertRaises(branding.BrandingError):
            branding.update("Ford", logo_size="huge")

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

    def _unlock(self, s, password=TEST_PASSWORD):
        body = urllib.parse.urlencode({"csrf": s.token(), "password": password})
        status, data, resp = s.request("POST", "/branding/unlock", body,
                                       {"Content-Type": "application/x-www-form-urlencoded"})
        cookie = (resp.headers.get("Set-Cookie") or "").split(";")[0]
        return status, data, {"Cookie": cookie} if status == 303 else {}

    def _post(self, s, fields, files=(), cookie=None):
        body, headers = multipart_body(fields, files)
        headers.update(cookie or {})
        return s.request("POST", "/branding", body, headers)

    def test_password_hash_checks(self):
        self.assertTrue(branding.check_password("  correct horse   BATTERY staple "))
        self.assertFalse(branding.check_password("Correct Horse Battery"))
        self.assertFalse(branding.check_password(""))
        self.assertNotIn(TEST_PASSWORD.encode(), TEST_HASH.encode())
        with mock.patch.dict(os.environ, {branding.PASSWORD_ENV: "scrypt$garbage"}):
            self.assertFalse(branding.check_password(TEST_PASSWORD))

    def test_default_password_hash_is_well_formed(self):
        scheme, n, r, p, salt, digest = branding.DEFAULT_PASSWORD_HASH.split("$")
        self.assertEqual((scheme, int(n), int(r), int(p)), ("scrypt", 2 ** 15, 8, 1))
        self.assertEqual(len(base64.b64decode(salt)), 16)
        self.assertEqual(len(base64.b64decode(digest)), 32)
        with mock.patch.dict(os.environ, {branding.PASSWORD_ENV: ""}):
            self.assertFalse(branding.check_password("VulnScope"))

    def test_branding_page_is_locked_until_password(self):
        s = self._server()
        status, page, _ = s.request("GET", "/branding")
        self.assertEqual(status, 200)
        self.assertIn('name="password"', page)
        self.assertNotIn('name="prefix"', page)
        status, _, _ = self._post(s, {"csrf": s.token(), "prefix": "Evil"})
        self.assertEqual(status, 403)
        self.assertEqual(branding.product_name(), "Múcaro VulnScope")
        status, _, cookie = self._unlock(s, "wrong password")
        self.assertEqual(status, 403)
        self.assertEqual(cookie, {})
        status, _, cookie = self._unlock(s)
        self.assertEqual(status, 303)
        self.assertIn('name="prefix"', s.request("GET", "/branding", headers=cookie)[1])
        self.assertEqual(s.request("POST", "/branding/lock", urllib.parse.urlencode({"csrf": s.token()}),
                                   {"Content-Type": "application/x-www-form-urlencoded", **cookie})[0], 303)
        self.assertEqual(self._post(s, {"csrf": s.token(), "prefix": "Evil"}, cookie=cookie)[0], 403)

    def test_repeated_wrong_passwords_lock_out(self):
        s = self._server()
        for _ in range(5):
            self.assertEqual(self._unlock(s, "nope")[0], 403)
        status, data, cookie = self._unlock(s)            # even the right password waits out the lockout
        self.assertEqual(status, 429)
        self.assertIn("Too many", data)
        self.assertEqual(cookie, {})

    def test_unlock_requires_csrf(self):
        s = self._server()
        body = urllib.parse.urlencode({"csrf": "wrong", "password": TEST_PASSWORD})
        status, _, resp = s.request("POST", "/branding/unlock", body,
                                    {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403)
        self.assertIsNone(resp.headers.get("Set-Cookie"))

    def test_branding_page_saves_name_and_logo(self):
        s = self._server()
        self.assertIn('href="/branding"', s.request("GET", "/")[1])
        cookie = self._unlock(s)[2]
        status, _, _ = self._post(s, {"csrf": s.token(), "prefix": "Ford", "logo_size": "small"},
                                  [("logo", "ford.png", png())], cookie)
        self.assertEqual(status, 303)
        self.assertEqual(branding.product_name(), "Ford VulnScope")
        self.assertEqual(branding.load().logo_size, "small")
        page = s.request("GET", "/")[1]
        self.assertIn("<title>Ford VulnScope</title>", page)
        self.assertIn('class="brand-logo logo-small" src="data:image/png;base64,', page)

    def test_branding_page_refuses_svg_and_missing_csrf(self):
        s = self._server()
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
        cookie = self._unlock(s)[2]
        status, data, _ = self._post(s, {"csrf": s.token(), "prefix": "Ford"}, [("logo", "logo.png", svg)], cookie)
        self.assertEqual(status, 400)
        self.assertIn("SVG", data)
        self.assertEqual(branding.product_name(), "Múcaro VulnScope")
        self.assertEqual(self._post(s, {"csrf": "wrong", "prefix": "Evil"}, cookie=cookie)[0], 403)
        self.assertEqual(branding.product_name(), "Múcaro VulnScope")

    def test_branding_reset(self):
        s = self._server()
        branding.update("Ford", png())
        cookie = self._unlock(s)[2]
        self.assertEqual(self._post(s, {"csrf": s.token(), "action": "reset"}, cookie=cookie)[0], 303)
        self.assertEqual(branding.load(), branding.Branding())


if __name__ == "__main__":
    unittest.main()
