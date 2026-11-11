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


def report_host(ip, port, proto="tcp", start=SCAN):
    return (f'<ReportHost name="{ip}"><HostProperties><tag name="host-ip">{ip}</tag>'
            f'<tag name="HOST_START_TIMESTAMP">{start}</tag><tag name="HOST_END_TIMESTAMP">{start + 600}</tag>'
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


class CorrelationAccuracyRound2Tests(unittest.TestCase):
    """Scanner probes, rescans, self-traffic, asymmetric taps, mixed scan formats, telemetry-only."""

    def run_folder(self, files):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        paths = []
        for name, text in files.items():
            paths.append(os.path.join(tmp, name))
            os.makedirs(os.path.dirname(paths[-1]), exist_ok=True)
            with open(paths[-1], "w") as fh:
                fh.write(text)
        ds = load(paths)
        self.addCleanup(ds.close)
        res = correlate(ds)
        return ds, res, {(r["host"], r["port"]): r for r in res["findings"]}

    def nessus(self, *hosts):
        return '<?xml version="1.0" ?><NessusClientData_v2><Report name="t">' + "".join(hosts) + "</Report></NessusClientData_v2>"

    def test_scanner_probes_are_not_service_use(self):
        info = ('<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" '
                'pluginName="Nessus Scan Information"><plugin_output>Nessus version : 10.8.3\nScanner IP : 10.70.9.9\n'
                '</plugin_output></ReportItem>')
        host = report_host("10.70.0.10", 8443).replace("</ReportHost>", info + "</ReportHost>")
        ds, res, find = self.run_folder({
            "conn.log": conn(SCAN + 60, "10.70.9.9", 60001, "10.70.0.10", 8443),
            "scan.nessus": self.nessus(host)})
        exp = find[("10.70.0.10", 8443)]["exposure"]
        self.assertEqual((exp["label"], exp["established"]), ("Service not observed in use", 0))
        self.assertTrue(exp["telemetry_seen"])
        self.assertEqual((res["summary"]["scanner_ips"], res["summary"]["scanner_sessions_excluded"]), (["10.70.9.9"], 1))
        x = explore.build(res, ds)
        self.assertEqual({n["id"]: n["name"] for n in x["nodes"]}["10.70.9.9"], "Vulnerability scanner")

    def test_rescanned_host_uses_every_scan_time(self):
        old = report_host("10.70.0.12", 443, start=SCAN - 20 * DAY)
        ds, res, find = self.run_folder({
            "conn.log": conn(SCAN + 3600, "203.0.113.110", 1110, "10.70.0.12", 443),
            "scan.nessus": self.nessus(old, report_host("10.70.0.12", 443))})
        self.assertEqual(find[("10.70.0.12", 443)]["exposure"]["external_sources"], 1)
        self.assertEqual(res["summary"]["duplicate_findings_merged"], 1)

    def test_host_talking_to_itself_is_not_exposure(self):
        ds, res, find = self.run_folder({
            "conn.log": conn(SCAN, "10.70.0.15", 2200, "10.70.0.15", 8080),
            "scan.nessus": self.nessus(report_host("10.70.0.15", 8080))})
        self.assertEqual(find[("10.70.0.15", 8080)]["exposure"]["internal_sources"], 0)

    def test_tap_that_saw_the_whole_session_wins(self):
        ds, res, find = self.run_folder({
            "a/conn.log": conn(SCAN, "10.70.1.50", 3200, "10.70.0.27", 5432, state="S0"),
            "b/conn.log": conn(SCAN + 0.2, "10.70.1.50", 3200, "10.70.0.27", 5432),
            "scan.nessus": self.nessus(report_host("10.70.0.27", 5432))})
        exp = find[("10.70.0.27", 5432)]["exposure"]
        self.assertEqual((exp["established"], exp["attempts"]), (1, 0))

    def test_nessus_csv_and_xml_together_with_callback(self):
        # Used to crash DuckDB's binder (correlated NOT EXISTS with mixed timed/untimed findings).
        csv = ("Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name\n"
               "910014,CVE-2026-2001,8.8,High,10.70.0.21,tcp,3389,RDP flaw\n")
        ds, res, find = self.run_folder({
            "conn.log": conn(SCAN, "203.0.113.131", 2402, "10.70.0.18", 443)
                        + conn(SCAN + 300, "10.70.0.18", 2403, "203.0.113.131", 8443)
                        + conn(SCAN - 60 * DAY, "203.0.113.150", 2701, "10.70.0.21", 3389),
            "scan.nessus": self.nessus(report_host("10.70.0.18", 443)), "scan.csv": csv})
        self.assertEqual([i["type"] for i in find[("10.70.0.18", 443)]["indicators"]], ["return_connection"])
        self.assertEqual(find[("10.70.0.21", 3389)]["exposure"]["external_sources"], 1)   # no scan time: all telemetry

    def test_explorer_callback_needs_inbound_first(self):
        ds, res, find = self.run_folder({
            "conn.log": conn(SCAN, "10.70.0.17", 2400, "203.0.113.130", 443)
                        + conn(SCAN + 300, "203.0.113.130", 2401, "10.70.0.17", 443),
            "scan.nessus": self.nessus(report_host("10.70.0.17", 443))})
        self.assertEqual(find[("10.70.0.17", 443)]["indicators"], [])
        a = explore.build(res, ds)["focus"]["10.70.0.17"]["attackers"][0]
        self.assertFalse(a["returned"])

    def test_telemetry_only_outbound_alert_names_the_internal_host(self):
        notice = ('{"ts":%d,"note":"Sig","msg":"Beacon","src":"10.80.0.16","dst":"203.0.113.240","p":8080,'
                  '"actions":["Notice::ACTION_LOG"]}\n' % SCAN)
        ds, res, _ = self.run_folder({"conn.log": conn(SCAN, "10.80.1.1", 4200, "10.80.0.13", 445),
                                      "notice.log": notice})
        self.assertFalse(res["summary"]["vulnerability_data_available"])
        self.assertEqual([(l["host"], l["role"]) for l in res["telemetry_leads"]], [("10.80.0.16", ["source"])])
        a = explore.build(res, ds)["focus"]["10.80.0.16"]["attackers"]
        self.assertEqual([(x["ip"], x["kind"], x["dir"]) for x in a], [("203.0.113.240", "alert", "out")])


class ReviewFollowUpTests(unittest.TestCase):
    """Same-instant tap duplicates and rescans far apart (PR #34 review)."""

    def run_folder(self, files):
        return CorrelationAccuracyRound2Tests.run_folder(self, files)

    def test_same_instant_taps_keep_the_completed_session(self):
        for first, second in (("S0", "SF"), ("SF", "S0")):        # whichever file is read first
            with self.subTest(first=first):
                ds, res, find = self.run_folder({
                    "a/conn.log": conn(SCAN, "10.70.1.50", 3200, "10.70.0.27", 5432, state=first),
                    "b/conn.log": conn(SCAN, "10.70.1.50", 3200, "10.70.0.27", 5432, state=second),
                    "scan.nessus": CorrelationAccuracyRound2Tests.nessus(self, report_host("10.70.0.27", 5432))})
                exp = find[("10.70.0.27", 5432)]["exposure"]
                self.assertEqual((exp["label"], exp["established"], exp["attempts"]),
                                 ("Vulnerable service reached internally", 1, 0))
                self.assertEqual(len(ds.flows), 1)

    def test_rescans_use_a_window_per_scan_not_the_gap(self):
        old = report_host("10.70.0.12", 443, start=SCAN - 60 * DAY)
        flows = (conn(SCAN - 30 * DAY, "203.0.113.111", 1111, "10.70.0.12", 443)      # halfway: outside both
                 + conn(SCAN - 60 * DAY + 3600, "203.0.113.112", 1112, "10.70.0.12", 443)   # near the old scan
                 + conn(SCAN + 3600, "203.0.113.113", 1113, "10.70.0.12", 443))           # near the new scan
        ds, res, find = self.run_folder({"conn.log": flows,
                                         "scan.nessus": CorrelationAccuracyRound2Tests.nessus(self, old, report_host("10.70.0.12", 443))})
        r = find[("10.70.0.12", 443)]
        self.assertEqual(r["exposure"]["external_sources"], 2)
        self.assertEqual(sorted(ip for ip, _, _ in r["exposure"]["top_sources"]), ["203.0.113.112", "203.0.113.113"])
        self.assertEqual(len(r["exposure"]["windows"]), 2)
        atk = {a["ip"]: a for a in explore.build(res, ds)["focus"]["10.70.0.12"]["attackers"]}
        self.assertEqual(atk["203.0.113.111"]["kind"], "reached")          # Explorer agrees with the report
        self.assertEqual(atk["203.0.113.113"]["kind"], "vuln")

    def test_untimed_flow_counts_once_with_several_windows(self):
        old = report_host("10.70.0.12", 443, start=SCAN - 60 * DAY)
        untimed = conn(SCAN, "10.70.1.9", 1200, "10.70.0.12", 443).replace('"ts":%s' % SCAN, '"ts":"-"')
        ds, res, find = self.run_folder({"conn.log": untimed,
                                         "scan.nessus": CorrelationAccuracyRound2Tests.nessus(self, old, report_host("10.70.0.12", 443))})
        self.assertEqual(find[("10.70.0.12", 443)]["exposure"]["established"], 1)
