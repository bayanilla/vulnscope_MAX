"""Zeek logs shipped by Filebeat and exported again (Kibana CSV report, elasticdump NDJSON)."""
import csv
import json
import os
import shutil
import tempfile
import unittest

from vulnflow.parsers import detect, filebeat, zeek
from vulnflow.schema import Flow, ParseStats, ThreatEvent, ZeekEvent

DNS_RAW = json.dumps({"ts": 1762850002.5, "uid": "Cdns1", "id.orig_h": "10.0.1.5", "id.orig_p": 53311,
                      "id.resp_h": "10.0.0.53", "id.resp_p": 53, "proto": "udp", "query": "evil.example",
                      "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["203.0.113.9"]})

# What Filebeat's Zeek module stores, as a Kibana Discover CSV report writes it: dates in the
# default "MMM D, YYYY @ HH:mm:ss.SSS" format, bytes through the bytes formatter, numbers with
# thousands separators, lists joined with ", ", missing values as "-".
ROWS = [
    {"@timestamp": "Nov 11, 2025 @ 08:33:20.250", "event.dataset": "zeek.connection", "fileset.name": "connection",
     "source.ip": "10.0.1.5", "source.address": "10.0.1.5", "source.port": "50,123",
     "destination.ip": "203.0.113.9", "destination.port": "443", "network.transport": "tcp",
     "network.protocol": "ssl", "zeek.session_id": "Cconn1", "event.id": "Cconn1",
     "zeek.connection.state": "SF", "zeek.connection.history": "ShADadFf",
     "zeek.connection.state_message": "Normal establishment and termination.",
     "source.bytes": "1.5KB", "destination.bytes": "48,000", "source.packets": "12", "destination.packets": "40",
     "event.duration": "2,500,000,000", "zeek.connection.local_orig": "true", "tags": "zeek.connection, local_orig",
     "related.ip": "10.0.1.5, 203.0.113.9", "agent.type": "filebeat", "event.original": "-"},
    {"@timestamp": "Nov 11, 2025 @ 08:33:21.000", "event.dataset": "zeek.connection", "fileset.name": "connection",
     "source.ip": "10.0.1.6", "destination.ip": "10.0.2.10", "network.transport": "icmp",
     "zeek.connection.icmp.type": "8", "zeek.connection.icmp.code": "0", "zeek.session_id": "Cicmp1",
     "zeek.connection.state": "OTH", "source.bytes": "84B", "destination.bytes": "84B"},
    {"@timestamp": "Nov 11, 2025 @ 08:33:22.500", "event.dataset": "zeek.dns", "fileset.name": "dns",
     "source.ip": "10.0.1.5", "dns.question.name": "evil.example", "event.original": DNS_RAW},
    {"@timestamp": "Nov 11, 2025 @ 08:33:23.000", "event.dataset": "zeek.http", "source.ip": "10.0.1.5",
     "source.port": "50124", "destination.ip": "203.0.113.9", "destination.port": "80", "url.port": "80",
     "zeek.session_id": "Chttp1", "http.request.method": "GET", "event.action": "GET", "url.domain": "evil.example",
     "url.original": "/'=cmd", "http.response.status_code": "200", "user_agent.original": "curl/8.0",
     "zeek.http.resp_mime_types": "text/html, application/x-dosexec"},
    {"@timestamp": "Nov 11, 2025 @ 08:33:24.000", "event.dataset": "zeek.notice", "source.ip": "10.0.1.5",
     "destination.ip": "203.0.113.9", "destination.port": "443", "rule.name": "SSL::Invalid_Server_Cert",
     "rule.description": "self signed", "zeek.notice.note": "SSL::Invalid_Server_Cert"},
    {"@timestamp": "Nov 11, 2025 @ 08:33:25.000", "event.dataset": "system.auth", "source.ip": "10.0.1.5"},
]


def write_csv(path, rows, delimiter=","):
    cols = ["@timestamp"] + sorted({k for r in rows for k in r} - {"@timestamp"})
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter=delimiter, quoting=csv.QUOTE_ALL)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c, "-") for c in cols])


class FilebeatZeekTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.csv = os.path.join(self.tmp, "discover_export.csv")
        write_csv(self.csv, ROWS)

    def records(self, path):
        stats = ParseStats(file=os.path.basename(path), fmt="filebeat_zeek")
        return dict(((s, r.get("uid")), r) for s, r in filebeat.records(path, stats)), stats

    def test_detects_kibana_csv_and_ndjson_but_not_plain_zeek_or_flows(self):
        self.assertEqual(detect(self.csv), "filebeat_zeek")
        nd = os.path.join(self.tmp, "dump.ndjson")
        with open(nd, "w") as fh:
            fh.write(json.dumps({"_index": "filebeat-8", "_source": {
                "@timestamp": "2025-11-11T08:33:20.250Z", "event": {"dataset": "zeek.connection"},
                "source": {"ip": "10.0.1.5", "port": 1}, "destination": {"ip": "10.0.2.1", "port": 22},
                "zeek": {"session_id": "C1", "connection": {"state": "SF"}}}}) + "\n")
        self.assertEqual(detect(nd), "filebeat_zeek")
        plain = os.path.join(self.tmp, "conn.log")
        with open(plain, "w") as fh:
            fh.write('{"ts":1762850000.0,"uid":"C1","id.orig_h":"10.0.1.5","id.orig_p":1,'
                     '"id.resp_h":"10.0.2.1","id.resp_p":22,"proto":"tcp","conn_state":"SF"}\n')
        self.assertEqual(detect(plain), "zeek")
        flows = os.path.join(self.tmp, "flows.csv")
        with open(flows, "w") as fh:
            fh.write("src_ip,dst_ip,dst_port\n10.0.1.5,10.0.2.1,22\n")
        self.assertEqual(detect(flows), "generic")

    def test_ecs_columns_go_back_to_zeek_field_names(self):
        recs, stats = self.records(self.csv)
        conn = recs[("conn", "Cconn1")]
        self.assertEqual(conn["id.orig_h"], "10.0.1.5")
        self.assertEqual(conn["id.orig_p"], 50123)
        self.assertEqual(conn["id.resp_p"], 443)
        self.assertEqual((conn["proto"], conn["service"], conn["conn_state"]), ("tcp", "ssl", "SF"))
        self.assertEqual((conn["orig_ip_bytes"], conn["resp_ip_bytes"]), (1536, 48000))
        self.assertEqual(conn["duration"], 2.5)
        self.assertIs(conn["local_orig"], True)
        self.assertAlmostEqual(conn["ts"], 1762850000.25, places=3)
        self.assertNotIn("state_message", conn)          # added by Filebeat, not Zeek
        self.assertNotIn("orig_bytes", conn)             # Filebeat drops it; not invented
        self.assertEqual(list(conn)[:6], list(filebeat.FIRST_KEYS))
        icmp = recs[("conn", "Cicmp1")]
        self.assertEqual((icmp["id.orig_p"], icmp["id.resp_p"]), (8, 0))
        http = recs[("http", "Chttp1")]
        self.assertEqual((http["method"], http["host"], http["status_code"]), ("GET", "evil.example", 200))
        self.assertEqual(http["uri"], "/'=cmd")
        self.assertEqual(http["resp_mime_types"], ["text/html", "application/x-dosexec"])
        self.assertEqual(stats.dropped["not a Zeek record (no zeek.* event.dataset)"], 1)
        self.assertTrue(any("orig_ip_bytes" in n for n in stats.notes))

    def test_original_zeek_line_is_used_when_present(self):
        recs, stats = self.records(self.csv)
        self.assertEqual(recs[("dns", "Cdns1")], json.loads(DNS_RAW))
        self.assertTrue(any("whole Zeek record" in n for n in stats.notes))

    def test_semicolon_separator_and_gzip(self):
        import gzip
        path = os.path.join(self.tmp, "export.csv.gz")
        plain = os.path.join(self.tmp, "semi.csv")
        write_csv(plain, ROWS, delimiter=";")
        with open(plain, "rb") as src, gzip.open(path, "wb") as dst:
            dst.write(src.read())
        recs, _ = self.records(path)
        self.assertEqual(recs[("conn", "Cconn1")]["id.resp_h"], "203.0.113.9")
        self.assertEqual(recs[("dns", "Cdns1")]["query"], "evil.example")

    def test_parse_feeds_flows_alerts_and_events(self):
        stats = ParseStats(file="x", fmt="filebeat_zeek")
        items = list(filebeat.parse(self.csv, stats))
        flows = [i for i in items if isinstance(i, Flow)]
        self.assertEqual(len(flows), 2)
        f = next(x for x in flows if x.dst_port == 443)
        self.assertEqual((f.src_ip, f.dst_ip, f.bytes_out, f.bytes_in, f.app), ("10.0.1.5", "203.0.113.9", 1536, 48000, "ssl"))
        self.assertTrue(f.established)
        alert = next(i for i in items if isinstance(i, ThreatEvent))
        self.assertEqual((alert.src_ip, alert.dst_ip, alert.dst_port), ("10.0.1.5", "203.0.113.9", 443))
        self.assertIn("SSL::Invalid_Server_Cert", alert.name)
        streams = sorted(i.stream for i in items if isinstance(i, ZeekEvent))
        self.assertEqual(streams, ["dns", "http"])

    def test_export_writes_zeek_json_logs_the_zeek_parser_reads(self):
        out = os.path.join(self.tmp, "zeek")
        counts = filebeat.export([self.csv], out)
        self.assertEqual(counts, {"conn": 2, "dns": 1, "http": 1, "notice": 1})
        conn = os.path.join(out, "conn.log")
        self.assertEqual(detect(conn), "zeek")
        flows = list(zeek.parse(conn, ParseStats(file="conn.log", fmt="zeek")))
        self.assertEqual(sorted(f.dst_port for f in flows), [0, 443])

    def test_ndjson_elasticdump_with_nested_source(self):
        nd = os.path.join(self.tmp, "dump.ndjson")
        doc = {"@timestamp": "2025-11-11T08:33:20.250Z", "event": {"dataset": "zeek.ssl", "duration": 5e8},
               "source": {"ip": "10.0.1.5", "port": 50000}, "destination": {"ip": "203.0.113.9", "port": 443},
               "zeek": {"session_id": "Cssl1", "ssl": {"server": {"name": "evil.example"}, "version": "TLSv13",
                                                       "established": True}},
               "tls": {"client": {"ja3": "abc"}}}
        with open(nd, "w") as fh:
            fh.write(json.dumps({"_index": "filebeat", "_source": doc}) + "\n")
        recs, _ = self.records(nd)
        ssl = recs[("ssl", "Cssl1")]
        self.assertEqual((ssl["server_name"], ssl["version"], ssl["ja3"]), ("evil.example", "TLSv13", "abc"))
        self.assertIs(ssl["established"], True)

    def test_whole_zeek_json_in_message_column(self):
        conn = {"ts": 1762850000.25, "uid": "Cm1", "id.orig_h": "10.0.1.5", "id.orig_p": 50000,
                "id.resp_h": "203.0.113.9", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                "duration": 1.5, "orig_bytes": 900, "resp_bytes": 40000, "conn_state": "SF"}
        dns = json.loads(DNS_RAW)
        http = {"ts": 1762850003.0, "uid": "Ch1", "id.orig_h": "10.0.1.5", "id.orig_p": 50001,
                "id.resp_h": "203.0.113.9", "id.resp_p": 80, "method": "GET", "host": "evil.example",
                "uri": "/a,b", "status_code": 200}
        # Plain Filebeat log/filestream input: one long JSON string per row, no zeek.* fields.
        with_path = os.path.join(self.tmp, "with_path.csv")
        write_csv(with_path, [
            {"@timestamp": "Nov 11, 2025 @ 08:33:20.250", "log.file.path": "/opt/zeek/logs/current/conn.log",
             "input.type": "filestream", "message": json.dumps(conn)},
            {"@timestamp": "Nov 11, 2025 @ 08:33:22.500", "log.file.path": "/opt/zeek/logs/current/dns.log",
             "input.type": "filestream", "message": DNS_RAW}])
        bare = os.path.join(self.tmp, "bare.csv")       # only a timestamp and the JSON string
        write_csv(bare, [{"@timestamp": "x", "message": json.dumps(r)} for r in (conn, dns, http)])
        for path in (with_path, bare):
            self.assertEqual(detect(path), "filebeat_zeek")
            recs, stats = self.records(path)
            self.assertEqual(recs[("conn", "Cm1")], conn)     # untouched, orig_bytes included
            self.assertEqual(recs[("dns", "Cdns1")], dns)
        self.assertEqual(recs[("http", "Ch1")], http)
        flows = [i for i in filebeat.parse(bare, ParseStats(file="b", fmt="f")) if isinstance(i, Flow)]
        self.assertEqual((flows[0].bytes_out, flows[0].bytes_in), (900, 40000))
        syslog = os.path.join(self.tmp, "syslog.csv")    # a message column that is not Zeek
        write_csv(syslog, [{"@timestamp": "x", "message": "sshd[1]: Accepted password for root"}])
        self.assertNotEqual(detect(syslog), "filebeat_zeek")

    def test_native_zeek_bytes_unchanged_when_orig_bytes_present(self):
        stats = ParseStats(file="conn.log", fmt="zeek")
        f = zeek._to_flow({"id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "conn_state": "S0",
                           "orig_bytes": None, "orig_ip_bytes": 60}, stats)
        self.assertEqual(f.bytes_out, 0)


if __name__ == "__main__":
    unittest.main()
