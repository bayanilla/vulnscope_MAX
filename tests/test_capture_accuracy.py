"""Regression checks from the Brim sample-capture accuracy run: mid-stream captures, answered pings,
subnet broadcasts, Zeek bookkeeping logs, capture loss, Zui/Brim JSON exports and Suricata flows
picked up mid-stream. Every expected number was worked out by hand from the records below."""
import gzip
import json
import os
import shutil
import tempfile
import unittest

from vulnflow import explore, report
from vulnflow.correlate import correlate
from vulnflow.normalize import load
from vulnflow.parsers import detect

T = 1425567000.0


def zconn(ts, src, sport, dst, dport, proto="tcp", state="SF", history="ShADadFf",
          ob=500, rb=4000, op=5, rp=5):
    rec = {"ts": ts, "uid": f"C{sport}{dport}", "id.orig_h": src, "id.orig_p": sport,
           "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "conn_state": state,
           "history": history, "orig_bytes": ob, "resp_bytes": rb, "orig_pkts": op, "resp_pkts": rp}
    return json.dumps(rec) + "\n"


class ZeekCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        conn = (
            # mid-stream: client data, server only ACKs (no SYN seen, no bytes back)
            zconn(T, "192.168.0.51", 50858, "192.168.0.1", 80, state="OTH", history="ADa", ob=338, rb=0)
            # mid-stream: only the server's data back to an outside client is in the capture
            + zconn(T + 1, "192.168.0.2", 34446, "130.236.100.79", 80, state="OTH", history="Ad", ob=0, rb=2776)
            # an answered ping: ICMP request and reply, no payload bytes
            + zconn(T + 2, "10.47.0.9", 8, "10.47.10.1", 0, proto="icmp", state="OTH", history="",
                    ob=0, rb=0, op=1, rp=1)
            # an unanswered ping and an unanswered SYN: probed only
            + zconn(T + 3, "10.47.0.9", 8, "10.47.10.2", 0, proto="icmp", state="OTH", history="",
                    ob=0, rb=0, op=1, rp=0)
            + zconn(T + 4, "10.47.0.9", 40001, "10.47.10.3", 22, state="S0", history="S", ob=0, rb=0, rp=0)
            # subnet broadcast (UDP only): not an address that failed to answer
            + zconn(T + 5, "192.168.1.179", 15600, "192.168.1.255", 15600, proto="udp", state="S0",
                    history="D", ob=60, rb=0, op=1, rp=0)
            # an address ending in .255 that received TCP is an ordinary address
            + zconn(T + 6, "10.47.0.9", 40002, "10.47.1.255", 445, state="S0", history="S", ob=0, rb=0, rp=0)
        )
        notice = (json.dumps({"ts": T + 7, "note": "CaptureLoss::Too_Much_Loss",
                              "msg": "The capture loss script detected an estimated loss rate above 13.636%"})
                  + "\n")
        bookkeeping = "".join(json.dumps({"ts": T, "name": f"s{i}.zeek"}) + "\n" for i in range(5))
        files = {"conn.log": conn, "notice.log": notice, "loaded_scripts.log": bookkeeping,
                 "dns.log": json.dumps({"ts": T, "uid": "Cx", "id.orig_h": "10.47.0.9", "query": "a"}) + "\n"}
        paths = []
        for name, text in files.items():
            paths.append(os.path.join(cls.tmp, name))
            with open(paths[-1], "w") as fh:
                fh.write(text)
        cls.ds = load(paths)
        cls.res = correlate(cls.ds)
        cls.hosts = {h["host"]: h for h in cls.res["hosts"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_midstream_and_ping_responders_are_hosts(self):
        cov = self.res["coverage"]
        self.assertIn("192.168.0.1", self.hosts)        # only ACKed, mid-stream
        self.assertIn("10.47.10.1", self.hosts)         # answered a ping
        self.assertNotIn("10.47.10.2", self.hosts)
        self.assertEqual(cov["telemetry_internal_hosts"], 6)
        # 10.47.10.2, 10.47.10.3 and 10.47.1.255; the UDP-only broadcast is not counted
        self.assertEqual(cov["probed_only_addresses"], 3)

    def test_midstream_reply_counts_as_reached_destination(self):
        self.assertEqual(self.hosts["192.168.0.2"]["blast"]["external_destinations"], 1)

    def test_answered_share_counts_two_way_sessions(self):
        # answered: the two mid-stream sessions and the ping; 3 of 7
        self.assertEqual(self.res["coverage"]["sessions_answered_pct"], round(100 * 3 / 7, 1))

    def test_bookkeeping_logs_are_not_activity_and_loss_is_reported(self):
        self.assertEqual(self.res["summary"]["zeek_event_counts"], {"dns": 1})
        self.assertEqual(self.res["summary"]["threat_alerts"], 0)
        self.assertEqual(self.res["coverage"]["capture_loss_pct"], 13.64)
        self.assertIn("missed up to 13.64% of packets", report.executive_summary(self.res))

    def test_probed_addresses_csv_leaves_out_broadcast(self):
        rows = self.ds.flow_store().probed_rows()
        self.assertEqual(sorted(r[0] for r in rows), ["10.47.1.255", "10.47.10.2", "10.47.10.3"])

    def test_explorer_does_not_count_broadcast_as_probed(self):
        data = explore.build(self.res, self.ds)
        self.assertEqual(data["focus"]["192.168.1.179"]["probed_only"], 0)
        self.assertEqual(data["focus"]["10.47.0.9"]["probed_only"], 3)
        self.assertNotIn("192.168.1.255", {n["id"] for n in data["nodes"]})


class ZuiExportTests(unittest.TestCase):
    """A Zui/Brim export: one JSON array, records tagged by _path, nested connection IDs, ISO times
    and Zed duration strings; Suricata alerts from brimcap use _path "alert"."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        recs = [
            {"_path": "capture_loss", "ts": "2018-03-24T17:30:20.600852Z", "percent_lost": 0.5},
            {"_path": "conn", "ts": "2018-03-24T17:15:21.255387Z", "uid": "C1",
             "id": {"orig_h": "10.164.94.120", "orig_p": 39681, "resp_h": "10.47.3.155", "resp_p": 3389},
             "proto": "tcp", "service": None, "duration": "4.266ms", "orig_bytes": 97, "resp_bytes": 19,
             "conn_state": "RSTR", "history": "ShADTdtr", "orig_pkts": 10, "resp_pkts": 6},
            {"_path": "conn", "ts": "2018-03-24T17:15:22Z", "uid": "C2",
             "id": {"orig_h": "10.164.94.120", "orig_p": 39682, "resp_h": "8.8.8.8", "resp_p": 53},
             "proto": "udp", "duration": "20ms", "orig_bytes": 40, "resp_bytes": 80, "conn_state": "SF",
             "history": "Dd", "orig_pkts": 1, "resp_pkts": 1},
            {"_path": "notice", "ts": "2018-03-24T17:15:20.629574Z", "uid": "C3",
             "id": {"orig_h": "10.164.94.120", "orig_p": 39611, "resp_h": "10.47.3.200", "resp_p": 443},
             "note": "SSL::Invalid_Server_Cert", "msg": "SSL certificate validation failed",
             "src": "10.164.94.120", "dst": "10.47.3.200", "p": 443, "actions": ["Notice::ACTION_LOG"]},
            {"_path": "alert", "event_type": "alert", "ts": "2018-03-24T17:15:23Z",
             "src_ip": "10.164.94.120", "src_port": 40000, "dest_ip": "10.47.3.155", "dest_port": 3389,
             "alert": {"signature": "ET SCAN test", "severity": 2, "action": "allowed"}},
            {"_path": "dns", "ts": "2018-03-24T17:15:22Z", "uid": "C2",
             "id": {"orig_h": "10.164.94.120", "orig_p": 39682, "resp_h": "8.8.8.8", "resp_p": 53},
             "query": "example.com"},
            {"_path": "stats", "ts": "2018-03-24T17:15:00Z", "peer": "zeek"},
        ]
        self.path = os.path.join(self.tmp, "zeek.json.gz")
        with gzip.open(self.path, "wt") as fh:
            json.dump(recs, fh)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_zui_export_is_read(self):
        self.assertEqual(detect(self.path), "zeek")
        ds = load([self.path])
        res = correlate(ds)
        s = res["summary"]
        self.assertEqual(s["flows"], 2)
        self.assertEqual(s["threat_alerts"], 2)            # Zeek notice + Suricata alert
        self.assertEqual(s["zeek_event_counts"], {"dns": 1})
        self.assertEqual(s["window_start"], "2018-03-24T17:15:20Z")   # the notice is the first record
        self.assertEqual(res["coverage"]["capture_loss_pct"], 0.5)
        hosts = {h["host"]: h for h in res["hosts"]}
        self.assertEqual(hosts["10.164.94.120"]["outbound_flows"], 2)
        self.assertEqual(hosts["10.47.3.155"]["inbound_flows"], 1)
        self.assertEqual(hosts["10.164.94.120"]["blast"]["external_destinations"], 1)

    def test_large_array_is_streamed_across_chunks(self):
        from vulnflow.parsers import zeek
        recs = [{"_path": "dns", "ts": T + i, "uid": f"C{i}", "query": "x" * 50} for i in range(3000)]
        path = os.path.join(self.tmp, "big.json")
        with open(path, "w") as fh:
            json.dump(recs, fh)
        with open(path) as fh:
            out = list(zeek._json_array(fh, chunk=4096))
        self.assertEqual(len(out), 3000)
        self.assertEqual(out[-1]["uid"], "C2999")


class SuricataMidstreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _eve(self, events):
        path = os.path.join(self.tmp, "eve.json")
        with open(path, "w") as fh:
            fh.write("".join(json.dumps(e) + "\n" for e in events))
        return path

    def test_server_first_flow_is_turned_round(self):
        path = self._eve([{
            "timestamp": "2015-03-05T15:04:28.580509+0000", "event_type": "flow", "proto": "TCP",
            "src_ip": "198.58.111.64", "src_port": 80, "dest_ip": "192.168.0.51", "dest_port": 38607,
            "flow": {"pkts_toserver": 12, "pkts_toclient": 9, "bytes_toserver": 8028,
                     "bytes_toclient": 1037, "start": "2015-03-05T15:04:28.611670+0000", "state": "new"},
            "tcp": {"tcp_flags": "00"}}])
        res = correlate(load([path]))
        hosts = {h["host"]: h for h in res["hosts"]}
        self.assertEqual(hosts["192.168.0.51"]["inbound_flows"], 0)
        self.assertEqual(hosts["192.168.0.51"]["outbound_flows"], 1)
        self.assertEqual(hosts["192.168.0.51"]["blast"]["top_external_destinations"], [["198.58.111.64", 1]])

    def test_syn_seen_keeps_direction_and_icmp_error_is_not_a_reply(self):
        path = self._eve([
            {"timestamp": "2015-03-05T15:00:00+0000", "event_type": "flow", "proto": "TCP",
             "src_ip": "192.168.0.51", "src_port": 80, "dest_ip": "203.0.113.5", "dest_port": 40000,
             "flow": {"pkts_toserver": 3, "pkts_toclient": 3, "bytes_toserver": 300, "bytes_toclient": 300,
                      "state": "closed"}, "tcp": {"syn": True}},
            # Suricata files the ICMP "prohibited" error under the UDP flow it answers
            {"timestamp": "2015-03-05T15:00:01+0000", "event_type": "flow", "proto": "UDP",
             "src_ip": "192.168.0.2", "src_port": 123, "dest_ip": "194.71.144.71", "dest_port": 123,
             "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 90, "bytes_toclient": 70,
                      "state": "new"}}])
        res = correlate(load([path]))
        hosts = {h["host"]: h for h in res["hosts"]}
        self.assertEqual(hosts["192.168.0.51"]["outbound_flows"], 1)
        self.assertEqual(hosts["192.168.0.2"]["blast"]["external_destinations"], 0)


if __name__ == "__main__":
    unittest.main()
