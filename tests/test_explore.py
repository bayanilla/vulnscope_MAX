import json
import ipaddress
import os
import re
import tempfile
import unittest
from datetime import datetime, timezone

from vulnflow import explore
from vulnflow.correlate import Config, correlate
from vulnflow.normalize import Dataset, load
from vulnflow.schema import Flow, OTEvent, ThreatEvent
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

    def test_connection_details_keep_recorded_direction_and_ot_operations(self):
        ts = datetime(2026, 11, 4, 10, 0, tzinfo=timezone.utc)
        ds = Dataset(flows=[
            Flow(ts, "10.70.10.10", "10.70.20.11", 502, "tcp", src_port=53001,
                 app="Modbus TCP", source="ot_flows.csv"),
            Flow(ts, "10.70.20.11", "10.70.10.10", 53001, "tcp", src_port=502,
                 app="Modbus TCP", source="ot_flows.csv"),
            Flow(ts, "10.70.10.10", "10.70.20.11", None, "udp",
                 source="partial-flow.csv"),
        ], ot_events=[OTEvent(ts, "modbus", "M1", "10.70.10.10", "10.70.20.11",
                             {"id.orig_h": "10.70.10.10", "id.resp_h": "10.70.20.11"},
                             source="modbus.log", protocol="Modbus",
                             operation="READ_HOLDING_REGISTERS", direction="originator"),
                      OTEvent(ts, "dnp3", "D1", None, None,
                              {"id.orig_h": "10.70.10.10", "id.resp_h": "10.70.20.11"},
                              source="dnp3.log", protocol="DNP3", operation="READ",
                              direction="unknown")])
        data = explore.build(correlate(ds), ds)
        self.assertFalse(data["vulnerability_data_available"])
        peer = next(p for p in data["focus"]["10.70.10.10"]["peers"] if p["ip"] == "10.70.20.11")
        self.assertEqual([(e["src_ip"], e["src_port"], e["dst_ip"], e["dst_port"], e["proto"], e["app"])
                          for e in peer["connection_examples"]], [
            ("10.70.10.10", 53001, "10.70.20.11", 502, "tcp", "Modbus TCP"),
            ("10.70.10.10", None, "10.70.20.11", None, "udp", ""),
            ("10.70.20.11", 502, "10.70.10.10", 53001, "tcp", "Modbus TCP")])
        event = data["focus"]["10.70.10.10"]["ot_events"][0]
        self.assertEqual((event["protocol"], event["operation"], event["message_side"]),
                         ("Modbus", "READ_HOLDING_REGISTERS", "originator"))
        self.assertEqual(data["focus"]["10.70.10.10"]["ot_events_total"], 2)
        self.assertEqual(data["focus"]["10.70.10.10"]["ot_events"][1]["message_side"], "unknown")
        self.assertEqual(data["focus"]["10.70.10.10"]["findings"], [])

    def test_scan_mode_also_exposes_recorded_connection_details(self):
        attacker = next(a for a in self.data["focus"]["10.10.1.10"]["attackers"]
                        if a["ip"] == "203.0.113.45")
        self.assertTrue(attacker["connection_examples"])
        self.assertTrue(all(e["src_ip"] in ("203.0.113.45", "10.10.1.10")
                            and e["proto"] in ("tcp", "udp") for e in attacker["connection_examples"]))

    def test_panel_data_reaches_past_graph_limit_without_double_counting_alerts(self):
        host = "10.70.1.10"
        outside = [str(ipaddress.IPv4Address("198.18.0.1") + i) for i in range(405)]
        peers = [str(ipaddress.IPv4Address("10.71.0.1") + i) for i in range(405)]
        flows = ([Flow(None, src, host, 443, "tcp") for src in outside[:-1]] +
                 [Flow(None, host, outside[-1], 443, "tcp")] +
                 [Flow(None, host, dst, 445, "tcp") for dst in peers])
        # An alert on an address that only has outbound flows must not add a duplicate IP row.
        ds = Dataset(flows=flows, threats=[ThreatEvent(None, outside[-1], host, 443, "IPS signature")])
        data = explore.build(correlate(ds), ds)
        focus = data["focus"][host]
        self.assertEqual(focus["attackers_total"], 405)
        self.assertEqual(focus["peers_total"], 405)
        self.assertEqual(len({a["ip"] for a in focus["attackers"]}), 405)
        self.assertEqual(len({p["ip"] for p in focus["peers"]}), 405)
        self.assertEqual({a["ip"] for a in focus["attackers"]}, set(outside))
        self.assertEqual({p["ip"] for p in focus["peers"]}, set(peers))
        self.assertIn(outside[-1], explore.html(data))


if __name__ == "__main__":
    unittest.main()
