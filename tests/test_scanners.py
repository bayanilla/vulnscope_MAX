"""Scanner detection from traffic, the expected-scanner list, and counting only hosts that exist."""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from vulnflow import explore, report, scanners
from vulnflow.correlate import Config, correlate
from vulnflow.errors import UserError
from vulnflow.normalize import Dataset
from vulnflow.schema import Flow, ThreatEvent

T0 = datetime(2026, 3, 1, 12, tzinfo=timezone.utc)
SCANNER, ADMIN, WEB, DB = "10.9.0.66", "10.9.0.5", "10.9.1.10", "10.9.1.20"


def _flows():
    out = []
    # the scanner sweeps 10.9.2.1-150 on two ports; only two addresses exist (one refuses, one answers)
    for i in range(1, 151):
        for port in (22, 445):
            dst = f"10.9.2.{i}"
            if i == 7:
                f = Flow(T0, SCANNER, dst, port, "tcp", action="reject", established=False)
            elif i == 9:
                f = Flow(T0, SCANNER, dst, port, "tcp", established=True, bytes_out=10, bytes_in=10)
            else:
                f = Flow(T0, SCANNER, dst, port, "tcp", established=False)
            out.append(f)
    # ordinary use: many completed sessions to a few servers is not scanning
    for i in range(300):
        out.append(Flow(T0 + timedelta(seconds=i), ADMIN, WEB if i % 2 else DB, 443, "tcp",
                        established=True, bytes_out=100, bytes_in=900))
    return out


class ScannerTests(unittest.TestCase):
    def _run(self, known=(), threats=()):
        ds = Dataset(flows=_flows(), threats=list(threats))
        cfg = Config(known_scanner_list=list(known))
        res = correlate(ds, cfg)
        return ds, res

    def test_sweep_is_flagged_and_normal_use_is_not(self):
        _, res = self._run()
        found = res["summary"]["traffic_scanners"]
        self.assertEqual([e["ip"] for e in found], [SCANNER])
        e = found[0]
        self.assertEqual((e["sessions"], e["hosts"], e["ports"], e["targets"]), (300, 150, 2, 300))
        self.assertEqual((e["failed_pct"], e["kind"], e["expected"], e["internal"]),
                         (99, "address sweep", False, True))

    def test_known_scanner_is_labelled_expected_but_still_listed(self):
        _, res = self._run(known=[{"cidr": "10.9.0.64/28", "name": "Nessus"}])
        e = res["summary"]["traffic_scanners"][0]
        self.assertEqual((e["ip"], e["expected"], e["name"]), (SCANNER, True, "Nessus"))
        text = report.executive_summary(res)
        self.assertIn("Expected: Nessus", text)
        self.assertIn("0 are not on your list", text)

    def test_zeek_scan_notice_names_a_scanner(self):
        _, res = self._run(threats=[ThreatEvent(T0, "198.51.100.9", WEB, 22, "Scan::Port_Scan - 198.51.100.9 scanned")])
        by_ip = {e["ip"]: e for e in res["summary"]["traffic_scanners"]}
        self.assertEqual(by_ip["198.51.100.9"]["evidence"], ["notice"])
        self.assertFalse(by_ip["198.51.100.9"]["internal"])

    def test_only_addresses_that_sent_or_answered_are_hosts(self):
        ds, res = self._run()
        hosts = {h["host"] for h in res["hosts"]}
        # scanner, admin, two servers, the address that refused and the one that answered
        self.assertEqual(hosts, {SCANNER, ADMIN, WEB, DB, "10.9.2.7", "10.9.2.9"})
        self.assertEqual(res["coverage"]["telemetry_internal_hosts"], 6)
        self.assertEqual(res["coverage"]["probed_only_addresses"], 148)
        text = report.executive_summary(res)
        self.assertIn("6 internal hosts sent or answered traffic.", text)
        self.assertIn("148 more internal addresses were only probed", text)
        data = explore.build(res, ds)
        self.assertEqual({n["id"] for n in data["nodes"]}, hosts)
        f = data["focus"][SCANNER]
        self.assertEqual((f["probed_only"], f["peers_total"]), (148, 2))
        self.assertEqual(next(n for n in data["nodes"] if n["id"] == SCANNER)["name"], "Scanner (review)")
        self.assertEqual(data["start"], SCANNER)

    def test_known_scanners_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known_scanners.csv")
            with open(path, "w") as fh:
                fh.write("address,name\n# ours\n10.9.0.66,Nessus\n10.20.0.0/28\n")
            self.assertTrue(scanners.is_list_file(path))
            entries = scanners.read(path)
            self.assertEqual(entries, [{"cidr": "10.9.0.66/32", "name": "Nessus"}, {"cidr": "10.20.0.0/28", "name": ""}])
            known = scanners.Known(entries, nessus=("10.1.1.1",))
            self.assertEqual((known.label("10.9.0.66"), known.label("10.20.0.3"), known.label("10.20.0.99"),
                              known.label("10.1.1.1")), ("Nessus", "", None, "Vulnerability scanner"))
            with open(path, "w") as fh:
                fh.write("10.9.0.66\nnot-an-address,x\n")
            with self.assertRaisesRegex(UserError, "line 2"):
                scanners.read(path)


if __name__ == "__main__":
    unittest.main()
