"""Ground-truth checks for Zeek + Nessus correlation (report, coverage and explorer agree)."""
import os
import shutil
import tempfile
import unittest

from vulnflow import explore
from vulnflow.correlate import correlate
from vulnflow.normalize import load

SCAN = 1793620800            # 2026-11-02 12:00 UTC
DAY = 86400


def conn(ts, src, sport, dst, dport, proto="tcp", state="SF"):
    ob, rb = (0, 0) if state in ("REJ", "S0") else (500, 4000)
    return ('{"ts":%s,"uid":"C%d","id.orig_h":"%s","id.orig_p":%d,"id.resp_h":"%s","id.resp_p":%d,'
            '"proto":"%s","conn_state":"%s","orig_bytes":%d,"resp_bytes":%d}\n'
            % (ts, sport, src, sport, dst, dport, proto, state, ob, rb))


def report_host(ip, port, proto="tcp"):
    return (f'<ReportHost name="{ip}"><HostProperties><tag name="host-ip">{ip}</tag>'
            f'<tag name="HOST_START_TIMESTAMP">{SCAN}</tag><tag name="HOST_END_TIMESTAMP">{SCAN + 600}</tag>'
            f'</HostProperties><ReportItem port="{port}" svc_name="x" protocol="{proto}" severity="3" '
            f'pluginID="9{port}" pluginName="flaw {port}"><cvss3_base_score>7.5</cvss3_base_score>'
            f'</ReportItem></ReportHost>')


class CorrelationAccuracyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.tmp, "tap_a"))
        os.makedirs(os.path.join(cls.tmp, "tap_b"))
        t = SCAN - 3600
        a = (conn(t, "203.0.113.30", 46300, "198.51.100.10", 443)            # public-address DMZ host
             + conn(t + 1, "10.60.1.20", 53000, "10.60.0.12", 3389)          # also seen by tap B
             + conn(t + 2, "10.60.1.21", 53001, "10.60.0.12", 3389)
             + "".join(conn(t + 3 + k, "198.51.100.66", 41000 + k, "10.60.0.13", 22, state="REJ") for k in range(3))
             + conn(t - 31 * DAY, "203.0.113.9", 46000, "10.60.0.20", 443)  # long before the scan
             + conn(t + 10, "10.60.1.42", 45200, "10.60.0.19", 161, proto="udp")
             + conn(t + 11, "203.0.113.40", 45202, "10.60.0.19", 161))       # TCP, finding is UDP
        b = conn(t + 1.4, "10.60.1.20", 53000, "10.60.0.12", 3389)
        nessus = ('<?xml version="1.0" ?><NessusClientData_v2><Report name="t">'
                  + report_host("198.51.100.10", 443) + report_host("10.60.0.12", 3389)
                  + report_host("10.60.0.13", 22) + report_host("10.60.0.20", 443)
                  + report_host("10.60.0.19", 161, "udp") + "</Report></NessusClientData_v2>")
        paths = []
        for name, text in (("tap_a/conn.log", a), ("tap_b/conn.log", b), ("scan.nessus", nessus)):
            paths.append(os.path.join(cls.tmp, name))
            with open(paths[-1], "w") as fh:
                fh.write(text)
        cls.ds = load(paths)
        cls.res = correlate(cls.ds)
        cls.find = {(r["host"], r["port"]): r for r in cls.res["findings"]}
        cls.explorer = explore.build(cls.res, cls.ds)

    @classmethod
    def tearDownClass(cls):
        cls.ds.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def outside(self, host, ip):
        return next(a for a in self.explorer["focus"][host]["attackers"] if a["ip"] == ip)

    def test_public_address_scanned_host_counts_as_seen(self):
        cov = self.res["coverage"]
        self.assertNotIn("198.51.100.10", cov["scanned_not_seen"])
        self.assertEqual(cov["scanned_and_seen"], 5)
        self.assertEqual(self.find[("198.51.100.10", 443)]["exposure"]["external_sources"], 1)

    def test_two_zeek_taps_count_one_session_once(self):
        exp = self.find[("10.60.0.12", 3389)]["exposure"]
        self.assertEqual((exp["established"], exp["internal_sources"]), (2, 2))
        self.assertEqual(self.ds.cross_sensor_duplicates, 1)

    def test_zeek_rej_is_refused_by_host_not_firewall(self):
        exp = self.find[("10.60.0.13", 22)]["exposure"]
        self.assertEqual((exp["denied"], exp["refused"], exp["attempts"]), (0, 3, 0))
        self.assertEqual(exp["label"], "Connections to service refused by the host")

    def test_explorer_respects_scan_window(self):
        self.assertEqual(self.find[("10.60.0.20", 443)]["exposure"]["label"], "Service not observed in use")
        a = self.outside("10.60.0.20", "203.0.113.9")
        self.assertEqual((a["kind"], a["vuln_ports"]), ("reached", []))

    def test_explorer_respects_protocol(self):
        self.assertEqual(self.find[("10.60.0.19", 161)]["exposure"]["external_sources"], 0)
        a = self.outside("10.60.0.19", "203.0.113.40")
        self.assertEqual((a["kind"], a["vuln_ports"]), ("reached", []))

    def test_timeline_vulnerable_flag_matches_report(self):
        tl = self.explorer["timeline"]
        flagged = [f for f in tl["flows"] if f[4] & 4]
        # attempts count too (the refused SSH tries); the out-of-window 443 and the TCP/161 session do not
        self.assertEqual(sorted(f[3] for f in flagged), [22, 22, 22, 161, 443, 3389, 3389])


if __name__ == "__main__":
    unittest.main()
