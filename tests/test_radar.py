"""On-demand Radar context and the local server boundary."""
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from vulnflow.correlate import Config
from vulnflow.radar import RadarError, lookup
from vulnflow.web import make_handler


class RadarLookupTests(unittest.TestCase):
    def test_public_ip_returns_selected_metadata(self):
        payload = {"success": True, "result": {"ip": {
            "ip": "8.8.8.8", "asn": "15169", "asnOrgName": "Google LLC",
            "locationName": "United States", "unused": "not returned"}}}
        with mock.patch("vulnflow.radar.urllib.request.urlopen",
                        return_value=io.BytesIO(json.dumps(payload).encode())) as call:
            result = lookup("ip", "8.8.8.8", "test-token")
        self.assertEqual(result["asnOrgName"], "Google LLC")
        self.assertNotIn("unused", result)
        self.assertNotIn("test-token", json.dumps(result))
        self.assertEqual(call.call_args.args[0].get_header("Authorization"), "Bearer test-token")

    def test_domain_rank_and_categories(self):
        payload = {"success": True, "result": {"details_0": {
            "rank": 12, "categories": [{"name": "Technology"}]}}}
        with mock.patch("vulnflow.radar.urllib.request.urlopen",
                        return_value=io.BytesIO(json.dumps(payload).encode())):
            result = lookup("domain", "EXAMPLE.COM", "test-token")
        self.assertEqual((result["value"], result["rank"], result["categories"]),
                         ("example.com", 12, ["Technology"]))

    def test_invalid_and_rejected_requests(self):
        with mock.patch("vulnflow.radar.urllib.request.urlopen") as call:
            with self.assertRaisesRegex(ValueError, "public IPv4"):
                lookup("ip", "10.0.0.1", "test-token")
            with self.assertRaisesRegex(ValueError, "Invalid domain"):
                lookup("domain", "not/a/domain", "test-token")
            call.assert_not_called()
        with self.assertRaisesRegex(RadarError, "not configured"):
            lookup("ip", "8.8.8.8", "")
        error = urllib.error.HTTPError("https://api.cloudflare.com", 403, "Forbidden", {}, None)
        with mock.patch("vulnflow.radar.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(RadarError, "token or its permissions"):
                lookup("ip", "8.8.8.8", "test-token")


class RadarServerTests(unittest.TestCase):
    def test_only_matched_indicators_can_be_looked_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "a" * 16
            out = os.path.join(tmp, run_id, "out")
            os.makedirs(out)
            with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as fh:
                json.dump({"ioc_matches": [{"type": "ip", "value": "8.8.8.8"}]}, fh)
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(tmp, Config()))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{server.server_port}/runs/{run_id}/"
            try:
                with mock.patch.dict(os.environ, {"CLOUDFLARE_RADAR_API_TOKEN": "test-token"}):
                    with urllib.request.urlopen(base + "radar-status") as response:
                        status = json.load(response)
                    self.assertTrue(status["enabled"])

                    def post(value, csrf):
                        body = json.dumps({"csrf": csrf, "type": "ip", "value": value}).encode()
                        return urllib.request.Request(base + "radar", data=body,
                            headers={"Content-Type": "application/json"})

                    with mock.patch("vulnflow.web.radar_lookup",
                                    return_value={"type": "ip", "value": "8.8.8.8"}) as call:
                        with self.assertRaises(urllib.error.HTTPError) as denied:
                            urllib.request.urlopen(post("8.8.8.8", "wrong"))
                        self.assertEqual(denied.exception.code, 403)
                        denied.exception.close()
                        with self.assertRaises(urllib.error.HTTPError) as unmatched:
                            urllib.request.urlopen(post("8.8.4.4", status["csrf"]))
                        self.assertEqual(unmatched.exception.code, 404)
                        unmatched.exception.close()
                        call.assert_not_called()
                        with urllib.request.urlopen(post("8.8.8.8", status["csrf"])) as response:
                            self.assertEqual(json.load(response)["value"], "8.8.8.8")
                        call.assert_called_once_with("ip", "8.8.8.8", "test-token")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
