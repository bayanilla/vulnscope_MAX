import csv
import os
import re
import gzip
import json
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import urllib.parse
import urllib.request
import uuid
from email.message import Message
from http.server import ThreadingHTTPServer

from vulnflow.correlate import Config, correlate
from vulnflow.normalize import load
from vulnflow.parsers import detect
from vulnflow.pipeline import run
from vulnflow.samples import generate, generate_bundles


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.samples = generate(os.path.join(cls.tmp, "in"))

    def write(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p


class ParserTests(Base):
    def test_detects_sample_formats(self):
        got = {os.path.basename(p): detect(p) for p in self.samples}
        self.assertEqual(got, {"zeek_conn.log": "zeek", "paloalto_traffic.csv": "paloalto",
                               "netflow_segment6.csv": "generic", "quarterly_scan.nessus": "nessus",
                               "modbus.log": "zeek"})

    def test_ioc_csv_links_survive_standalone_reports(self):
        archive = self.write("mucaro-archive.csv",
            "indicatorType,indicator,articleUrls,sources,disposition,firstSeenAt,lastSeenAt\n"
            "cve,CVE-2024-21887,https://research.example/report,Research,Actionable,2026-10-01,2026-10-20\n"
            "ip,8.8.8.8,https://research.example/indicator,Research,Actionable,2026-10-01,2026-10-20\n"
            "ip,9.9.9.9,javascript:alert(1),Unknown,Actionable,2026-10-01,2026-10-20\n")
        output = os.path.join(self.tmp, "archive-output")
        with patch("vulnflow.article_preview.fetch_preview",
                   return_value={"title": "Source report", "overview": "A short source-backed overview."}):
            res, paths = run(self.samples + [archive], output)
        self.assertEqual(res["ioc_archive"]["indicators"], 3)
        self.assertIn("CVE-2024-21887", [m["value"] for m in res["ioc_matches"]])
        self.assertIn("8.8.8.8", [m["value"] for m in res["ioc_matches"]])
        for name in ("executive_summary.html", "technical_report.html", "explorer.html"):
            with open(paths[name], encoding="utf-8") as fh:
                page = fh.read()
            self.assertIn('id="ioc-drawer"', page)
            self.assertIn("https://research.example/report", page)
            self.assertIn("A short source-backed overview.", page)
            self.assertNotIn("javascript:alert(1)", page)

    def test_ioc_csv_without_source_links_matches_scan(self):
        indicators = self.write("plain-indicators.csv", "type,indicator\ncve,CVE-2024-21887\n")
        res, _ = run(self.samples + [indicators], os.path.join(self.tmp, "plain-ioc-output"))
        match = next(item for item in res["ioc_matches"] if item["value"] == "CVE-2024-21887")
        self.assertEqual(match["articles"], [])
        self.assertEqual(res["ioc_archive"]["indicators"], 1)

    def test_article_preview_reads_short_source_description(self):
        from vulnflow.article_preview import fetch_preview, _public_address
        self.assertIsNone(_public_address("http://127.0.0.1/private"))

        class Response:
            status = 200
            headers = Message()
            headers["Content-Type"] = "text/html; charset=utf-8"

            def read(self, _limit):
                return (b'<html><head><title>Research note</title>'
                        b'<meta name="description" content="A concise source overview."></head>'
                        b'<body><p>Longer article content stays on the source page.</p></body></html>')

        class Connection:
            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with patch("vulnflow.article_preview._public_address",
                   return_value=("research.example", 443, "93.184.215.14", "/report")), \
             patch("vulnflow.article_preview.http.client.HTTPSConnection", return_value=Connection()):
            preview = fetch_preview("https://research.example/report")
        self.assertEqual(preview, {"title": "Research note", "overview": "A concise source overview."})

    def test_paloalto_syslog_without_header(self):
        line = ("<14>Oct 16 03:12:00 fw01 1,2026/10/16 03:12:00,0164,TRAFFIC,end,2560,2026/10/16 03:12:00,"
                "203.0.113.9,10.1.1.5,0.0.0.0,0.0.0.0,allow-web,,,ssl,vsys1,untrust,dmz,eth1,eth2,fwd,,1234,1,"
                "51000,443,0,0,0x0,tcp,allow,5000,1000,4000,10,2026/10/16 03:11:58,2,any\n")
        p = self.write("pan.log", line + line.replace("TRAFFIC", "SYSTEM"))
        ds = load([p])
        self.assertEqual(detect(p), "paloalto")
        self.assertEqual(len(ds.flows), 1)
        f = ds.flows[0]
        self.assertEqual((f.src_ip, f.dst_ip, f.dst_port, f.action, f.src_zone), ("203.0.113.9", "10.1.1.5", 443, "allow", "untrust"))
        self.assertEqual(ds.stats[0].dropped["SYSTEM log type not used"], 1)

    def test_paloalto_csv_threat_rows_take_receive_time(self):
        # web UI exports leave Start Time empty on THREAT rows; Receive Time is the alert's time
        csv_text = ("Receive Time,Type,Source address,Destination address,Destination Port,Action,Start Time,Threat/Content Name\n"
                    "2026/10/12 05:36:45,THREAT,192.0.2.216,10.10.3.31,3389,reset-both,,RDP exploit\n"
                    "2026/10/13 20:23:51,TRAFFIC,192.0.2.216,10.10.3.31,3389,deny,2026/10/13 20:23:50,\n")
        ds = load([self.write("pa.csv", csv_text)])
        self.assertEqual(len(ds.threats), 1)
        self.assertEqual(ds.threats[0].ts, datetime(2026, 10, 12, 5, 36, 45, tzinfo=timezone.utc))
        self.assertEqual(ds.flows[0].ts, datetime(2026, 10, 13, 20, 23, 50, tzinfo=timezone.utc))   # Start Time still wins

    def test_sample_firewall_log_has_only_valid_addresses(self):
        import ipaddress
        p = next(x for x in self.samples if x.endswith("paloalto_traffic.csv"))
        with open(p, newline="") as fh:
            for row in csv.DictReader(fh):
                ipaddress.ip_address(row["Source address"])
                ipaddress.ip_address(row["Destination address"])

    def test_threat_sources(self):
        pan = ("<14>Oct 16 03:12:00 fw01 1,2026/10/16 03:12:00,0164,THREAT,vulnerability,2560,2026/10/16 03:12:00,"
               "203.0.113.9,10.1.1.5,0.0.0.0,0.0.0.0,allow-web,,,web-browsing,vsys1,untrust,dmz,eth1,eth2,fwd,,1234,1,"
               "51000,443,0,0,0x0,tcp,alert,/cgi-bin/.%2e/,Apache Path Traversal CVE-2021-41773(91694),any,critical,client-to-server\n")
        eve = ('{"timestamp":"2026-10-16T03:12:00Z","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.1.1.5",'
               '"dest_port":443,"proto":"TCP","alert":{"action":"allowed","signature":"ET EXPLOIT Apache CVE-2021-41773","severity":1}}\n'
               '{"timestamp":"2026-10-16T03:12:01Z","event_type":"flow","src_ip":"10.1.1.5","src_port":50000,"dest_ip":"203.0.113.9",'
               '"dest_port":4444,"proto":"TCP","flow":{"bytes_toserver":900,"bytes_toclient":1200,"state":"closed"}}\n')
        notice = ('{"ts":1760584320.0,"note":"Scan::Port_Scan","msg":"203.0.113.9 scanned 30 ports","src":"203.0.113.9",'
                  '"dst":"10.1.1.5","p":22,"actions":["Notice::ACTION_LOG"]}\n')
        ds = load([self.write("pan_threat.log", pan), self.write("eve.json", eve), self.write("notice.log", notice)])
        self.assertEqual(detect(os.path.join(self.tmp, "eve.json")), "suricata")
        names = sorted(t.name for t in ds.threats)
        self.assertEqual(len(names), 3)
        self.assertIn("Apache Path Traversal CVE-2021-41773(91694)", names)
        self.assertEqual(len(ds.flows), 1)
        self.assertEqual(ds.flows[0].dst_port, 4444)

    def test_zeek_json(self):
        p = self.write("conn.json", '{"ts":1760000000.1,"id.orig_h":"10.0.0.1","id.orig_p":5000,'
                       '"id.resp_h":"10.0.0.2","id.resp_p":445,"proto":"tcp","conn_state":"REJ"}\n')
        f = load([p]).flows[0]
        self.assertEqual((f.action, f.established, f.dst_port), ("reject", False, 445))   # host refused, not a firewall

    def test_zeek_streams_do_not_become_connections(self):
        dns = self.write("00_dns.log", '{"ts":1760000001,"uid":"D1","id.orig_h":"10.0.0.1",'
                         '"id.resp_h":"10.0.0.2","query":"plant.example"}\n')
        smtp = self.write("01_smtp.log", '{"ts":1760000002,"uid":"S1","id.orig_h":"10.0.0.1",'
                          '"id.resp_h":"10.0.0.3","mailfrom":"operator@example.com"}\n')
        custom = self.write("custom.log", "#separator \\x09\n#path\tdns\n#empty_field\tEMPTY\n"
                            "#unset_field\tNONE\n#fields\tts\tuid\tquery\tanswers\n"
                            "1760000003\tD2\tEMPTY\tNONE\n")
        ds = load([dns, smtp, custom])
        self.assertEqual(len(ds.flows), 0)
        self.assertEqual(len(ds.threats), 0)
        self.assertEqual([e.stream for e in ds.zeek_events], ["dns", "smtp", "dns"])
        self.assertEqual(ds.zeek_events[2].fields["query"], "")
        self.assertIsNone(ds.zeek_events[2].fields["answers"])
        mislabeled = self.write("conn.log", '{"ts":1760000004,"id.orig_h":"10.0.0.1",'
                                '"id.resp_h":"10.0.0.2","query":"plant.example"}\n')
        wrong = load([mislabeled])
        self.assertEqual(wrong.flows, [])
        self.assertEqual(wrong.stats[0].dropped["conn record missing connection fields"], 1)

    def test_zeek_ot_logs_preserve_operations_and_direction(self):
        modbus = self.write("modbus.log", '{"ts":1760000001,"uid":"M1","id.orig_h":"10.0.0.1",'
                            '"id.resp_h":"10.0.0.2","is_orig":false,"func":"WRITE_MULTIPLE_REGISTERS"}\n')
        bacnet = self.write("bacnet_device_control.log", '{"ts":1760000002,"uid":"B1",'
                            '"source_h":"10.0.0.3","destination_h":"10.0.0.4","service":"ReinitializeDevice"}\n')
        dnp3 = os.path.join(self.tmp, "dnp3.log.gz")
        with gzip.open(dnp3, "wt") as fh:
            fh.write("#separator \\x09\n#path\tdnp3\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tfc_request\n"
                     "1760000003\tN1\t10.0.0.5\t10.0.0.6\tOPERATE\n")
        ds = load([modbus, bacnet, dnp3])
        self.assertEqual(len(ds.flows), 0)
        self.assertEqual([e.protocol for e in ds.ot_events], ["Modbus", "BACnet", "DNP3"])
        self.assertEqual((ds.ot_events[0].src_ip, ds.ot_events[0].dst_ip, ds.ot_events[0].direction),
                         ("10.0.0.2", "10.0.0.1", "responder"))
        self.assertEqual(ds.ot_events[1].operation, "ReinitializeDevice")
        self.assertEqual(ds.ot_events[2].operation, "OPERATE")

    def test_nessus_csv_merges_cve_rows(self):
        p = self.write("scan.csv", "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Solution\n"
                       "97833,CVE-2017-0143,8.1,Critical,10.0.0.2,tcp,445,MS17-010,s,patch\n"
                       "97833,CVE-2017-0144,8.1,Critical,10.0.0.2,tcp,445,MS17-010,s,patch\n")
        ds = load([p])
        self.assertEqual(detect(p), "nessus_csv")
        self.assertEqual(len(ds.findings), 1)
        self.assertEqual(ds.findings[0].cves, ["CVE-2017-0143", "CVE-2017-0144"])
        self.assertEqual(ds.findings[0].severity, 4)

    def test_generic_vpc_flow_space_delimited(self):
        p = self.write("vpc.log", "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
                       "2 123 eni-1 198.51.100.7 10.0.0.2 40000 22 6 10 840 1760000000 1760000060 REJECT OK\n")
        f = load([p]).flows[0]
        self.assertEqual((f.src_ip, f.dst_port, f.proto, f.action), ("198.51.100.7", 22, "tcp", "deny"))


class CorrelationTests(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ds = load(cls.samples)
        cls.res = correlate(cls.ds, Config())
        cls.by = {(r["host"], r["plugin_id"]): r for r in cls.res["findings"]}

    def test_cleaning(self):
        zeek = next(s for s in self.ds.stats if s.fmt == "zeek")
        self.assertEqual(zeek.dropped["missing or invalid IP"], 1)
        self.assertEqual(self.res["summary"]["duplicate_flows_removed"], 1)

    def test_exploited_web_server_is_corroborated(self):
        r = self.by[("10.10.1.10", "153884")]
        self.assertEqual(r["priority"], "P1")
        self.assertEqual(r["exposure"]["label"], "Vulnerable service reached from the internet")
        types = {i["type"] for i in r["indicators"]}
        self.assertTrue({"return_connection", "new_lateral", "exfil", "threat_alert", "corroborated"} <= types)
        self.assertEqual(self.res["summary"]["hosts_corroborated"], ["10.10.1.10"])
        self.assertEqual(self.res["summary"]["hosts_to_investigate"], [])
        # every network pattern on its own stays a lead
        self.assertEqual({i["confidence"] for i in r["indicators"] if i["type"] != "corroborated"}, {"lead"})
        # BlueKeep probes the IPS reset count as mitigation, not as evidence
        bk = self.by[("10.10.3.31", "125313")]
        self.assertEqual(bk["exposure"]["threat_blocked"], 3)
        self.assertNotIn("threat_alert", {i["type"] for i in bk["indicators"]})

    def test_return_connection_without_threat_logs_is_only_a_lead(self):
        import csv as _csv
        src = next(p for p in self.samples if p.endswith("paloalto_traffic.csv"))
        dst = os.path.join(self.tmp, "pan_no_threat.csv")
        with open(src, newline="") as fi, open(dst, "w", newline="") as fo:
            w = _csv.writer(fo)
            for row in _csv.reader(fi):
                if len(row) > 2 and row[2] == "THREAT":
                    continue
                w.writerow(row)
        files = [dst if p.endswith("paloalto_traffic.csv") else p for p in self.samples]
        ds = load(files)
        res = correlate(ds, Config())
        self.assertEqual(res["summary"]["hosts_corroborated"], [])
        self.assertEqual(res["summary"]["hosts_to_investigate"], ["10.10.1.10"])
        from vulnflow.report import executive_summary
        ex = executive_summary(res)
        self.assertIn("Investigate", ex)
        self.assertNotIn("Likely exploitation", ex)
        self.assertNotIn("compromise on", ex.lower())

    def test_lateral_spread_only_for_new_targets(self):
        self.assertEqual(self.res["summary"]["hosts_possible_spread"], ["10.10.2.25", "10.10.3.31"])

    def test_exposure_classes(self):
        self.assertEqual(self.by[("10.10.1.10", "187201")]["exposure"]["label"], "Connections to service blocked by firewall")
        self.assertEqual(self.by[("10.10.4.50", "42263")]["exposure"]["label"], "Service not observed in use")
        self.assertEqual(self.by[("10.10.5.60", "41028")]["exposure"]["label"], "No telemetry for this host (unknown)")
        self.assertEqual(self.by[("10.10.4.50", "42263")]["priority"], "P4")

    def test_blast_radius_and_coverage(self):
        app = next(h for h in self.res["hosts"] if h["host"] == "10.10.1.20")
        self.assertIn("10.10.2.20", [r["ip"] for r in app["blast"]["reachable"]])
        gaps = [g["ip"] for g in self.res["coverage"]["active_servers_not_scanned"]]
        self.assertTrue({"10.10.0.10", "10.10.6.70", "10.10.6.71"} <= set(gaps))
        self.assertEqual(self.res["coverage"]["scanned_not_seen"], ["10.10.5.60"])

    def test_custom_internal_nets_changes_exposure(self):
        # treat the workstation subnet as outside: SMB on fs01 becomes "reached from the internet"
        self.assertEqual(self.by[("10.10.2.25", "97833")]["exposure"]["external_sources"], 0)
        res = correlate(self.ds, Config(internal_nets=["10.10.0.0/24", "10.10.1.0/24", "10.10.2.0/24"]))
        r = next(r for r in res["findings"] if r["plugin_id"] == "97833")
        self.assertGreater(r["exposure"]["external_sources"], 0)


class EndToEndTests(Base):
    def test_pipeline_writes_reports(self):
        out = os.path.join(self.tmp, "out")
        _, paths = run(self.samples, out)
        for name in ("executive_summary.html", "technical_report.html", "correlated_findings.csv", "results.json"):
            self.assertTrue(os.path.getsize(paths[name]) > 0, name)
        with open(paths["executive_summary.md"]) as fh:
            self.assertIn("Likely exploitation", fh.read())

    def test_network_telemetry_without_scan(self):
        inputs = [p for p in self.samples if not p.endswith(".nessus")]
        ioc = self.write("network-ioc.csv", "type,indicator\nip,203.0.113.45\n")
        res, paths = run(inputs + [ioc], os.path.join(self.tmp, "telemetry-only"))
        self.assertFalse(res["summary"]["vulnerability_data_available"])
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["summary"]["priority_counts"], {p: None for p in ("P1", "P2", "P3", "P4")})
        self.assertTrue(res["hosts"])
        self.assertTrue(res["telemetry_leads"])
        self.assertTrue(res["ioc_matches"])
        self.assertIn("10.10.1.10", res["ioc_matches"][0]["hosts"])
        for name in ("executive_summary.md", "technical_report.md", "explorer.html"):
            with open(paths[name], encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("No vulnerability data", text)
            self.assertNotIn("No vulnerability reached Priority 1", text)
        with open(paths["explorer.html"], encoding="utf-8") as fh:
            page = fh.read()
        data = json.loads(re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
        self.assertIn("10.10.1.10", data["focus"])
        self.assertEqual(data["focus"]["10.10.1.10"]["findings"], [])
        self.assertEqual(data["focus"]["10.10.1.10"]["peers"][0]["band"], "Unknown")
        from vulnflow.report import save_article_briefs
        save_article_briefs(res, os.path.join(self.tmp, "telemetry-only"))
        with open(paths["technical_report.html"], encoding="utf-8") as fh:
            self.assertIn("Vulnerability status: unknown", fh.read())
        from vulnflow.llm import Analyst, LLMConfig
        self.assertIn("without vulnerability scan data", Analyst(res, LLMConfig.from_env(provider="local")).system)
        self.assertIn("vulnerability status is unknown", Analyst(res, LLMConfig.offline()).brief())

    def test_empty_scan_and_missing_telemetry(self):
        empty_scan = self.write("empty.nessus", "")
        telemetry = next(p for p in self.samples if p.endswith("zeek_conn.log"))
        res, _ = run([telemetry, empty_scan], os.path.join(self.tmp, "empty-scan-output"))
        self.assertFalse(res["summary"]["vulnerability_data_available"])
        with self.assertRaisesRegex(ValueError, "No network telemetry"):
            run([empty_scan], os.path.join(self.tmp, "missing-telemetry-output"))
        with self.assertRaisesRegex(ValueError, "No network telemetry"):
            run([], os.path.join(self.tmp, "empty-input-output"))

    def test_alert_only_telemetry(self):
        notice = os.path.join(os.path.dirname(__file__), "..", "samples", "scan_and_telemetry", "notice.log")
        res, paths = run([notice], os.path.join(self.tmp, "alert-only-output"))
        self.assertFalse(res["summary"]["vulnerability_data_available"])
        self.assertEqual(res["summary"]["flows"], 0)
        self.assertEqual(res["summary"]["threat_alerts"], 1)
        self.assertTrue(res["hosts"])
        self.assertTrue(res["telemetry_leads"])
        self.assertTrue(os.path.exists(paths["explorer.html"]))

    def test_cli_network_only_and_scan_regression(self):
        from vulnflow.cli import main
        from contextlib import redirect_stdout
        from io import StringIO
        telemetry = next(p for p in self.samples if p.endswith("zeek_conn.log"))
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["explore", telemetry, "--no-open", "-o", os.path.join(self.tmp, "explore-only")]), 0)
        self.assertIn("No vulnerability data available", output.getvalue())
        with redirect_stdout(StringIO()):
            res, _ = run(self.samples, os.path.join(self.tmp, "scan-regression"))
        self.assertTrue(res["summary"]["vulnerability_data_available"])
        self.assertGreater(res["summary"]["findings_scored"], 0)

    def test_recursive_folder_combines_zeek_ot_and_scan(self):
        from vulnflow.cli import main
        root = os.path.join(self.tmp, "bundle")
        os.makedirs(os.path.join(root, "zeek"))
        os.makedirs(os.path.join(root, "scans"))
        for p in self.samples:
            sub = "scans" if p.endswith(".nessus") else "zeek"
            shutil.copy2(p, os.path.join(root, sub, os.path.basename(p)))
        self.write("modbus_extra.log", '{"ts":1760000001,"uid":"M1","id.orig_h":"10.0.0.1",'
                   '"id.resp_h":"10.0.0.2","is_orig":true,"func":"READ_COILS"}\n')
        shutil.copy2(os.path.join(self.tmp, "modbus_extra.log"), os.path.join(root, "zeek", "modbus_extra.log"))
        for name, field in (("dns", '"query":"plant.example"'),
                            ("smtp", '"mailfrom":"operator@example.com"')):
            source = self.write(name + ".log", '{"ts":1760000002,"uid":"X1",'
                                '"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2",' + field + '}\n')
            shutil.copy2(source, os.path.join(root, "zeek", name + ".log"))
        out = os.path.join(root, "out")
        self.assertEqual(main(["analyze", root, "-o", out]), 0)
        with open(os.path.join(out, "results.json")) as fh:
            result = json.load(fh)
        self.assertEqual(result["summary"]["ot_protocol_counts"], {"Modbus": 5})
        self.assertEqual(result["summary"]["zeek_event_counts"],
                         {"dns": 1, "modbus": 4, "modbus_extra": 1, "smtp": 1})
        self.assertEqual(result["summary"]["flows"], len(load(self.samples).flows))
        self.assertEqual(len(result["inputs"]), len(self.samples) + 3)
        with open(os.path.join(out, "normalized", "ot_events.jsonl")) as fh:
            event = next(e for e in map(json.loads, fh) if e["operation"] == "READ_COILS")
        self.assertEqual(event["operation"], "READ_COILS")
        self.assertEqual(event["direction"], "originator")

    def test_web_upload(self):
        from vulnflow.web import make_handler
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(self.tmp, "runs"), Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            boundary = uuid.uuid4().hex
            with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_port}/") as resp:
                token = re.search(r'name="csrf" value="([^"]+)"', resp.read().decode())[1]
            body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{token}\r\n").encode()
            for p in self.samples:
                field = "folder"
                with open(p, "rb") as fh:
                    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; "
                             f"filename=\"bundle/{os.path.basename(p)}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
                    body += fh.read() + b"\r\n"
            body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"internal_nets\"\r\n\r\n\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/analyze", data=body,
                                         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            with urllib.request.urlopen(req) as resp:
                index = resp.read().decode()
                run_url = resp.url
            self.assertIn("Executive summary", index)
            with urllib.request.urlopen(run_url + "executive_summary.html") as resp:
                self.assertIn("web01", resp.read().decode())
            with urllib.request.urlopen(run_url + "normalized/zeek_events.jsonl") as resp:
                self.assertEqual(resp.status, 200)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(run_url + "..%2f..%2fin%2f00_x")
        finally:
            srv.shutdown()

    def test_web_telemetry_only_upload(self):
        from vulnflow.web import make_handler
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(self.tmp, "telemetry-runs"), Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            boundary = uuid.uuid4().hex
            telemetry = next(p for p in self.samples if p.endswith("zeek_conn.log"))
            with open(telemetry, "rb") as fh:
                payload = fh.read()
            with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_port}/") as resp:
                token = re.search(r'name="csrf" value="([^"]+)"', resp.read().decode())[1]
            body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{token}\r\n"
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"telemetry\"; "
                    f"filename=\"zeek_conn.log\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
            body += payload + f"\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/analyze", data=body,
                                         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            with urllib.request.urlopen(req) as resp:
                index, run_url = resp.read().decode(), resp.url
            self.assertIn("No vulnerability data available", index)
            with urllib.request.urlopen(run_url + "results.json") as resp:
                self.assertFalse(json.load(resp)["summary"]["vulnerability_data_available"])
        finally:
            srv.shutdown()

    def test_web_analyze_folder_in_place(self):
        from vulnflow.web import make_handler
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(self.tmp, "runs3"), Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_port}"
            with urllib.request.urlopen(base + "/") as resp:
                page = resp.read().decode()
            csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
            folder = os.path.dirname(self.samples[0])
            post = lambda form: urllib.request.Request(base + "/analyze-folder",
                                                       data=urllib.parse.urlencode(form).encode())
            with self.assertRaises(urllib.error.HTTPError):          # no token, no read
                urllib.request.urlopen(post({"path": folder}))
            with urllib.request.urlopen(post({"path": folder, "csrf": csrf})) as resp:
                page = resp.read().decode()
                self.assertIn("Executive summary", page)
                self.assertIn("explorer.html", page)
                self.assertIn('explorer.html" target="_blank"', page)
                run_url = resp.url
            with urllib.request.urlopen(run_url + "executive_summary.html") as resp:
                self.assertIn("web01", resp.read().decode())
            with urllib.request.urlopen(post({"path": folder + "/nope", "csrf": csrf})) as resp:
                self.assertIn("Folder not found", resp.read().decode())
        finally:
            srv.shutdown()

    def test_web_folder_browser(self):
        from vulnflow import web
        os.makedirs(os.path.join(self.tmp, "pick", "case-a"), exist_ok=True)
        os.makedirs(os.path.join(self.tmp, "pick", ".hidden"), exist_ok=True)
        open(os.path.join(self.tmp, "pick", "notes.txt"), "w").close()
        srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(os.path.join(self.tmp, "runs4"), Config()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_port}"
            with urllib.request.urlopen(base + "/") as resp:
                page = resp.read().decode()
            self.assertIn('id="browse"', page)
            csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
            call = lambda url, body: urllib.request.Request(base + url, data=json.dumps(body).encode(),
                                                            headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError):          # no token, no listing
                urllib.request.urlopen(call("/browse", {"path": self.tmp}))
            with urllib.request.urlopen(call("/browse", {"path": os.path.join(self.tmp, "pick"), "csrf": csrf})) as resp:
                d = json.loads(resp.read())
            self.assertEqual(d["dirs"], ["case-a"])
            self.assertEqual(d["files"], 1)
            self.assertEqual(d["parent"], os.path.realpath(self.tmp))
            gone = os.path.join(self.tmp, "pick", "missing", "deeper")   # falls back to the nearest folder
            with urllib.request.urlopen(call("/browse", {"path": gone, "csrf": csrf})) as resp:
                self.assertEqual(json.loads(resp.read())["path"], os.path.realpath(os.path.join(self.tmp, "pick")))
            if not web.folders.NATIVE_PICKER:
                with urllib.request.urlopen(call("/pick-folder", {"csrf": csrf})) as resp:
                    self.assertTrue(json.loads(resp.read())["unsupported"])
        finally:
            srv.shutdown()

    def test_web_upload_size_limit(self):
        from vulnflow.web import make_handler
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(self.tmp, "runs2"), Config(),
                                                                   max_upload=1024))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            body = b"--b\r\nContent-Disposition: form-data; name=\"telemetry\"; filename=\"x.log\"\r\n\r\n" + b"x" * 4096 + b"\r\n--b--\r\n"
            req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/analyze", data=body,
                                         headers={"Content-Type": "multipart/form-data; boundary=b"})
            try:
                with urllib.request.urlopen(req) as resp:
                    page = resp.read().decode()
            except urllib.error.HTTPError as e:
                page = e.read().decode()
            self.assertIn("Upload must be between", page)
            self.assertFalse(os.path.exists(os.path.join(self.tmp, "runs2")) and
                             any(f.endswith("x.log") for _, _, fs in os.walk(os.path.join(self.tmp, "runs2")) for f in fs))
        finally:
            srv.shutdown()


class BundledSamplesTests(unittest.TestCase):
    def test_generator_writes_the_sample_folders(self):
        with tempfile.TemporaryDirectory() as root:
            paths = generate_bundles(root)
            self.assertEqual(sorted(os.listdir(root)),
                             ["compare_two_companies", "gootloader_seo_poisoning", "hosts_onprem_and_aws",
                              "scan_and_telemetry", "telemetry_only"])
            self.assertEqual(len(paths), 67)
            self.assertEqual(len(os.listdir(os.path.join(root, "compare_two_companies"))), 6)   # six sites
            self.assertTrue(os.path.isfile(os.path.join(root, "scan_and_telemetry", "quarterly_scan.nessus")))
            self.assertFalse(any(name.endswith((".nessus", "scan.csv"))
                                 for name in os.listdir(os.path.join(root, "telemetry_only"))))
            self.assertTrue(os.path.isfile(os.path.join(root, "telemetry_only", "modbus.log")))

    def test_checked_in_folders_keep_scan_and_network_only_contracts(self):
        from vulnflow.pipeline import input_files as _input_files
        root = os.path.join(os.path.dirname(__file__), "..", "samples")
        self.assertEqual(sorted(name for name in os.listdir(root) if os.path.isdir(os.path.join(root, name))),
                         ["compare_two_companies", "gootloader_seo_poisoning", "hosts_onprem_and_aws",
                          "scan_and_telemetry", "telemetry_only"])
        with tempfile.TemporaryDirectory() as output:
            full_files = _input_files([os.path.join(root, "scan_and_telemetry")], output)
            network_files = _input_files([os.path.join(root, "telemetry_only")], output)
            self.assertFalse(any(name.endswith((".nessus", "scan.csv")) for name in network_files))
            for path in network_files:
                matching_path = os.path.join(root, "scan_and_telemetry", os.path.basename(path))
                with open(path, "rb") as network_file, open(matching_path, "rb") as full_file:
                    self.assertEqual(network_file.read(), full_file.read(), os.path.basename(path))
            full, _ = run(full_files, os.path.join(output, "full"), article_previews=False)
            network, paths = run(network_files, os.path.join(output, "network"), article_previews=False)
            self.assertEqual(full["coverage"]["scanned_hosts"], 250)
            self.assertTrue({f"10.10.6.{i}" for i in range(10, 15)} <= set(load(full_files).scanned_hosts))
            self.assertTrue(full["summary"]["vulnerability_data_available"])
            self.assertTrue(full["findings"])
            self.assertFalse(network["summary"]["vulnerability_data_available"])
            self.assertEqual(network["findings"], [])
            self.assertEqual(full["summary"]["flows"], network["summary"]["flows"])
            self.assertEqual(full["summary"]["ot_protocol_counts"], {"Modbus": 4})
            self.assertEqual(network["summary"]["ot_protocol_counts"], {"Modbus": 4})
            ds = load(network_files)
            self.assertEqual(sum(f.src_ip == "10.10.6.11" and f.dst_ip == "198.51.100.77"
                                 for f in ds.flows), 3)
            self.assertEqual(sum(f.src_ip == "10.10.7.46" and f.dst_ip == "198.51.100.77"
                                 for f in ds.flows), 2)
            self.assertEqual(sum(f.src_ip == "10.10.7.46" and f.dst_ip == "10.10.6.11"
                                 and f.dst_port == 3389 for f in ds.flows), 2)
            firewall_path = os.path.join(root, "telemetry_only", "paloalto_traffic.csv")
            with open(firewall_path, newline="") as firewall_file:
                vpn_access = [row for row in csv.DictReader(firewall_file)
                              if row["Rule"] == "GlobalProtect-Engineer-VPN"]
            self.assertEqual(len(vpn_access), 2)
            self.assertTrue(all(row["Source address"] == "10.10.7.46"
                                and row["Destination address"] == "10.10.6.11"
                                and row["Source Zone"] == "vpn" and row["Destination Zone"] == "ot"
                                and row["Application"] == "ms-rdp" and row["Action"] == "allow"
                                for row in vpn_access))
            self.assertEqual({event.operation for event in ds.ot_events},
                             {"READ_HOLDING_REGISTERS", "READ_INPUT_REGISTERS"})
            self.assertTrue(all(event.src_ip == "10.10.6.10" and event.dst_ip in
                                {"10.10.6.13", "10.10.6.14"} for event in ds.ot_events))
            with open(paths["explorer.html"], encoding="utf-8") as fh:
                page = fh.read()
            data = json.loads(re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
            self.assertEqual(data["focus"]["10.10.6.10"]["ot_events_total"], 4)
            self.assertIn("No vulnerability data", page)

    def test_host_sample_has_4324_hosts_on_prem_and_in_aws(self):
        from vulnflow import sample_hosts
        from vulnflow.pipeline import input_files as _input_files
        root = os.path.join(os.path.dirname(__file__), "..", "samples", sample_hosts.FOLDER)
        with tempfile.TemporaryDirectory() as tmp:
            fresh = os.path.join(tmp, "fresh")
            for path in sample_hosts.generate(fresh):          # checked-in folder matches the generator
                with open(path, "rb") as a, open(os.path.join(root, os.path.basename(path)), "rb") as b:
                    self.assertEqual(a.read(), b.read(), os.path.basename(path))
            files = _input_files([root], tmp)
            fmts = {os.path.basename(p): detect(p) for p in files}
            self.assertEqual(fmts["aws_vpcflow_prod_us-east-2.log"], "generic")
            self.assertEqual(fmts["estate_scan.nessus"], "nessus")
            res, paths = run(files, os.path.join(tmp, "out"), article_previews=False)
            with open(paths["explorer.html"], encoding="utf-8") as fh:
                page = fh.read()
        data = json.loads(re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
        drawn = {n["id"] for n in data["nodes"]}
        self.assertEqual(len(drawn), 2000)                     # capped, riskiest first
        self.assertLessEqual(set(data["focus"]), drawn)          # the host list only offers drawn hosts
        self.assertIn("10.60.1.16", drawn)
        self.assertEqual(data["counts"]["hosts"], 4324)
        cov = res["coverage"]
        self.assertEqual((cov["scanned_hosts"], cov["telemetry_internal_hosts"], cov["scanned_and_seen"]),
                         (4324, 4324, 4324))
        self.assertEqual(sum(place.startswith("aws") for *_, place in sample_hosts.HOSTS.values()), 413)
        self.assertTrue(any(h["host"].startswith(("10.60.", "10.61.")) for h in res["hosts"]))
        self.assertTrue(all(sum(st["dropped"].values()) == 0 for st in res["inputs"]))
        self.assertEqual(res["summary"]["hosts_to_investigate"], ["10.60.1.16"])       # web-prod-07
        self.assertEqual(res["summary"]["threat_alerts"], 4)
        self.assertEqual([(n["name"], n["scanned"]) for n in res["networks"]],
                         [("HQ on-prem", 3911), ("AWS prod (us-east-2)", 280), ("AWS dev (us-west-2)", 133)])
        self.assertNotIn("network_map.csv", [i["file"] for i in res["inputs"]])   # not read as telemetry
        self.assertEqual(next(h for h in res["hosts"] if h["host"] == "10.60.1.16")["network"], "AWS prod (us-east-2)")
        self.assertEqual(data["networks"][1]["type"], "aws")
        self.assertEqual(next(n for n in data["nodes"] if n["id"] == "10.60.1.16")["net"], 1)

    def test_gootloader_sample_replays_the_intrusion_with_timed_alerts(self):
        import ipaddress
        from datetime import datetime, timezone
        from vulnflow import sample_gootloader as g
        from vulnflow.pipeline import input_files as _input_files
        root = os.path.join(os.path.dirname(__file__), "..", "samples", g.FOLDER)
        with tempfile.TemporaryDirectory() as tmp:
            fresh = os.path.join(tmp, "fresh")
            for path in g.generate(fresh):                     # checked-in folder matches the generator
                with open(path, "rb") as a, open(os.path.join(root, os.path.basename(path)), "rb") as b:
                    self.assertEqual(a.read(), b.read(), os.path.basename(path))
            files = _input_files([root], tmp)
            fmts = {os.path.basename(p): detect(p) for p in files}
            self.assertEqual((fmts["conn.log"], fmts["dns.log"], fmts["files.log"], fmts["suricata_eve.json"],
                              fmts["paloalto_traffic.csv"], fmts["domain_scan.nessus"]),
                             ("zeek", "zeek", "zeek", "suricata", "paloalto", "nessus"))
            ds = load([p for p in files if not p.endswith(("ioc_indicators.csv", "article_previews.json"))])
            res, paths = run(files, os.path.join(tmp, "out"), article_previews=False)
            with open(paths["explorer.html"], encoding="utf-8") as fh:
                page = fh.read()
        # every address is valid (no 2-octet prefixes), and every alert keeps its own time
        for f in ds.flows:
            ipaddress.ip_address(f.src_ip), ipaddress.ip_address(f.dst_ip)
        self.assertEqual(res["summary"]["threat_alerts"], len(ds.threats))
        self.assertTrue(all(t.ts is not None for t in ds.threats))
        first = {t.name: t.ts for t in sorted(ds.threats, key=lambda t: t.ts, reverse=True)}
        self.assertEqual(first["Gootloader JavaScript Downloader Payload Retrieval"],
                         datetime(2026, 10, 26, 23, 2, 12, tzinfo=timezone.utc))      # T0 + 9 h, the firewall row
        self.assertLess(first["Gootloader JavaScript Downloader Payload Retrieval"],
                        first["ET RPC DCERPC SVCCTL - Remote Service Control Manager Access"])
        self.assertLess(first["ET RPC DCERPC SVCCTL - Remote Service Control Manager Access"],
                        first["ET MALWARE SystemBC Powershell bot registration"])
        self.assertEqual(res["coverage"]["scanned_hosts"], 115)
        self.assertIn(g.PATIENT0, {h for m in res["ioc_matches"] for h in m["hosts"]})
        matched = {(m["type"], m["value"]) for m in res["ioc_matches"]}
        self.assertTrue({("ip", g.CS_C2), ("ip", g.SYSTEMBC_C2), ("ip", g.GOOT_SERVER),
                         ("domain", "blog.lilianpraskova.cz")} <= matched)
        self.assertEqual(sum(t == "hash" for t, _ in matched), 12)                    # 4 beacons x md5/sha1/sha256
        self.assertIn(g.DC1, res["summary"]["hosts_to_investigate"])
        data = json.loads(re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
        tl = data["timeline"]
        self.assertEqual(len(tl["alerts"]), len(ds.threats))                       # none dropped for lack of time
        t0 = datetime.fromisoformat(tl["t0"].replace("Z", "+00:00"))
        payload = next(a for a in tl["alerts"] if a[3].startswith("Gootloader"))
        self.assertAlmostEqual(payload[0], (first[payload[3]] - t0).total_seconds() / 3600, places=3)
        self.assertTrue(tl["ioc_lookups"])

    def test_network_map_is_optional(self):
        """Without a network map, results, reports and the Explorer carry no network fields."""
        from vulnflow import sample_hosts
        src = os.path.join(os.path.dirname(__file__), "..", "samples", sample_hosts.FOLDER)
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, "in")
            shutil.copytree(src, folder, ignore=shutil.ignore_patterns("network_map.csv"))
            from vulnflow.pipeline import input_files as _input_files
            res, paths = run(_input_files([folder], tmp), os.path.join(tmp, "out"), article_previews=False)
            with open(paths["explorer.html"], encoding="utf-8") as fh:
                page = fh.read()
            with open(paths["executive_summary.md"], encoding="utf-8") as fh:
                summary = fh.read()
        self.assertNotIn("networks", res)
        self.assertFalse(any("network" in h for h in res["hosts"]))
        self.assertNotIn("## Networks", summary)
        data = json.loads(re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
        self.assertEqual(data["networks"], [])
        self.assertFalse(any("net" in n for n in data["nodes"]) or any("net" in s for s in data["subnets"]))

    def test_bad_network_map_names_the_line(self):
        from vulnflow import netmap
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "network_map.csv")
            with open(path, "w") as fh:
                fh.write("cidr,name,type\n10.0.0.0/8,Office,on-prem\nnot-a-range,AWS,aws\n")
            with self.assertRaisesRegex(ValueError, "line 3"):
                netmap.read(path)
            with open(path, "w") as fh:
                fh.write("10.0.0.0/8,Office\n")
            with self.assertRaisesRegex(ValueError, "cidr"):
                netmap.read(path)
            nm = netmap.NetMap([{"cidr": "10.0.0.0/8", "name": "Office", "type": "on-prem", "cloud": False},
                                {"cidr": "10.60.0.0/16", "name": "AWS", "type": "aws", "cloud": True}])
            self.assertEqual((nm.name("10.60.1.1"), nm.name("10.1.1.1"), nm.name("8.8.8.8")), ("AWS", "Office", ""))


class DockerEntrypointTests(unittest.TestCase):
    """docker/entrypoint.py hands vulnflow's commands to ``python -m vulnflow`` and anything else to the shell."""

    def entrypoint(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "vulnscope_entrypoint", os.path.join(os.path.dirname(__file__), "..", "docker", "entrypoint.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def run_entrypoint(self, argv):
        import sys
        ep = self.entrypoint()
        with patch.object(ep, "drop_privileges"), patch("os.umask"), patch("os.execv") as execv, \
                patch("os.execvp") as execvp, patch.object(sys, "argv", ["entrypoint.py"] + argv), \
                patch.dict(os.environ, {"VULNSCOPE_WORKDIR": "", "VULNSCOPE_HOME": ""}):
            ep.main()
        return execv.call_args[0][1][3:] if execv.called else ("shell", execvp.call_args[0][1])

    def test_every_vulnflow_command_runs_in_the_container(self):
        import contextlib
        import io
        from vulnflow.cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            main(["--help"])
        commands = set(re.search(r"\{([a-z,-]+)\}", out.getvalue())[1].split(","))
        self.assertIn("compare-sample", commands)
        self.assertLessEqual(commands, self.entrypoint().VULNFLOW_COMMANDS)

    def test_compare_sample_loads_into_the_upload_pages_folder(self):
        self.assertEqual(self.run_entrypoint(["compare-sample"]), ["compare-sample", "--data-dir=/runs/web"])
        self.assertEqual(self.run_entrypoint(["compare-sample", "--data-dir", "/runs/x"]),
                         ["compare-sample", "--data-dir", "/runs/x"])
        self.assertEqual(self.run_entrypoint(["compare-sample", "--data-dir=/runs/x", "--again"]),
                         ["compare-sample", "--data-dir=/runs/x", "--again"])
        self.assertEqual(self.run_entrypoint(["ls", "/runs"]), ("shell", ["ls", "/runs"]))


if __name__ == "__main__":
    unittest.main()
