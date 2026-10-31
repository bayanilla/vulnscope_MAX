import json
import os
import re
import tempfile
import unittest

from vulnflow import explore
from vulnflow.correlate import Config, correlate
from vulnflow.normalize import load
from vulnflow.report import write_all
from vulnflow.samples import generate


class ExploreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ds = load(generate(os.path.join(cls.tmp, "in")))
        cls.res = correlate(cls.ds, Config())
        cls.data = explore.build(cls.res, cls.ds)

    def test_attackers_of_the_web_server(self):
        f = self.data["focus"]["10.10.1.10"]
        kinds = {a["ip"]: a["kind"] for a in f["attackers"]}
        self.assertEqual(kinds.get("203.0.113.45"), "alert")
        self.assertEqual(f["attackers"][0]["ip"], "203.0.113.45")   # IPS alerts sort first
        self.assertGreaterEqual(f["attackers_total"], len(f["attackers"]))
        self.assertTrue(all(not a["ip"].startswith("10.") for a in f["attackers"]))

    def test_blast_radius_has_likelihood_bands(self):
        f = self.data["focus"]["10.10.1.10"]
        self.assertTrue(f["peers"])
        for p in f["peers"]:
            self.assertGreaterEqual(p["p"], 0)
            self.assertLessEqual(p["p"], 1)
            if p["out"] or p["in"]:
                band = "High" if p["p"] >= 0.6 else "Medium" if p["p"] >= 0.35 else "Low"
            else:                                       # attempts only: shown, but no likelihood
                band = "None"
                self.assertEqual(p["p"], 0)
            self.assertEqual(p["band"], band)
            self.assertTrue(p["why"])
        self.assertEqual({p["ip"]: p["band"] for p in f["peers"]}.get("10.10.2.25"), "High")
        for p in f["hop2"]:
            self.assertIn(p["via"], {q["ip"] for q in f["peers"]})

    def test_all_traffic_both_directions(self):
        # every outside and internal address that exchanged flows with a host appears, whatever the direction
        net_ext = lambda ip: not ip.startswith("10.")
        for host, f in self.data["focus"].items():
            seen = {x for fl in self.ds.flows if host in (fl.src_ip, fl.dst_ip)
                    for x in (fl.src_ip, fl.dst_ip) if x != host}
            self.assertEqual({a["ip"] for a in f["attackers"] if a["sessions"] or a["out_sessions"]},
                             {x for x in seen if net_ext(x)}, host)
            self.assertEqual({p["ip"] for p in f["peers"]}, {x for x in seen if not net_ext(x)}, host)

    def test_html_embeds_data_safely(self):
        page = explore.html(self.data)
        m = re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn("</", m.group(1))
        self.assertIn("10.10.1.10", json.loads(m.group(1))["focus"])
        self.assertIn("not confirmed compromise", page)

    def test_ioc_host_hints_count_distinct_matches(self):
        res = dict(self.res)
        res["ioc_matches"] = [
            {"id": "ip:203.0.113.45", "hosts": ["10.10.1.10", "10.10.2.25"]},
            {"id": "ip:203.0.113.45", "hosts": ["10.10.1.10"]},
            {"id": "domain:example.test", "hosts": ["10.10.1.10", "203.0.113.45"]},
        ]
        data = explore.build(res, self.ds)
        self.assertEqual(data["ioc_counts"], {"10.10.1.10": 2, "10.10.2.25": 1})
        page = explore.html(data)
        self.assertIn('id="ioc-filter"', page)
        self.assertIn('"ioc_counts":{"10.10.1.10":2,"10.10.2.25":1}', page)

    def test_write_all_includes_explorer(self):
        out = os.path.join(self.tmp, "out")
        write_all(self.res, self.ds, out)
        self.assertTrue(os.path.exists(os.path.join(out, "explorer.html")))


if __name__ == "__main__":
    unittest.main()
