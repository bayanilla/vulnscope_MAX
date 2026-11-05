"""Streaming load, Parquet/DuckDB storage, cross-sensor de-duplication and scan windows."""
import gzip
import os
import shutil
import tempfile
import unittest

from vulnflow.correlate import Config, correlate
from vulnflow.normalize import Dataset, load
from vulnflow.parsers import detect
from vulnflow.samples import generate

PA_HEADER = ("Receive Time,Type,Source address,Destination address,Source Port,Destination Port,"
             "IP Protocol,Action,Bytes Sent,Bytes Received,Start Time,Source Zone,Destination Zone,Application\n")


def pa_row(start, src, sport, dst, dport, action="allow"):
    return f"{start},TRAFFIC,{src},{dst},{sport},{dport},tcp,{action},500,900,{start},untrust,dmz,ssl\n"


def zeek_conn(ts, src, sport, dst, dport, state="SF"):
    return ('{"ts":%s,"uid":"C%s","id.orig_h":"%s","id.orig_p":%d,"id.resp_h":"%s","id.resp_p":%d,'
            '"proto":"tcp","conn_state":"%s","orig_bytes":480,"resp_bytes":880}\n'
            % (ts, sport, src, sport, dst, dport, state))


NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2><Report name="t"><ReportHost name="10.0.0.5"><HostProperties>
<tag name="host-ip">10.0.0.5</tag>
<tag name="HOST_START_TIMESTAMP">1760000000</tag><tag name="HOST_END_TIMESTAMP">1760003600</tag>
</HostProperties>
<ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginID="97833" pluginName="MS17-010">
<cvss3_base_score>8.1</cvss3_base_score><exploit_available>true</exploit_available>
</ReportItem></ReportHost></Report></NessusClientData_v2>
"""


class ScaleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text, gz=False):
        p = os.path.join(self.tmp, name)
        with (gzip.open(p, "wt") if gz else open(p, "w")) as fh:
            fh.write(text)
        return p

    def pair(self):
        # 1760000000 = 2025-10-09 08:53:20 UTC
        zeek = self.write("conn.log",
                          zeek_conn(1760000000.5, "203.0.113.9", 51000, "10.0.0.5", 443)   # PA saw it at :21
                          + zeek_conn(1760000020.0, "203.0.113.9", 51001, "10.0.0.5", 443)  # PA saw it 9.5 s later
                          + zeek_conn(1760000040.0, "203.0.113.9", 51002, "10.0.0.5", 443))  # PA did not see it
        pa = self.write("traffic.csv", PA_HEADER
                        + pa_row("2025/10/09 08:53:21", "203.0.113.9", 51000, "10.0.0.5", 443)
                        + pa_row("2025/10/09 08:53:49", "203.0.113.9", 51001, "10.0.0.5", 443))
        return [zeek, pa]

    def test_same_session_from_zeek_and_firewall_counted_once(self):
        ds = load(self.pair())
        self.assertEqual(len(ds.flows), 4)
        self.assertEqual(ds.cross_sensor_duplicates, 1)
        matched = [f for f in ds.flows if f.src_port == 51000]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].source, "traffic.csv")      # firewall record kept (zones, action)
        self.assertEqual(matched[0].src_zone, "untrust")
        self.assertEqual(correlate(ds)["summary"]["cross_sensor_duplicates_removed"], 1)

    def test_skew_tolerance_is_configurable(self):
        self.assertEqual(len(load(self.pair(), skew_seconds=None).flows), 5)
        self.assertEqual(len(load(self.pair(), skew_seconds=10).flows), 3)

    def test_gzipped_paloalto_and_generic(self):
        pa = self.write("traffic.csv.gz", PA_HEADER + pa_row("2025/10/09 08:53:21", "203.0.113.9", 51000,
                                                             "10.0.0.5", 443), gz=True)
        flows = self.write("flows.csv.gz", "ts,src_ip,src_port,dst_ip,dst_port,proto,action\n"
                           "1760000000,10.0.0.1,5000,10.0.0.2,22,tcp,allow\n", gz=True)
        self.assertEqual(detect(pa), "paloalto")
        ds = load([pa, flows])
        self.assertEqual(sorted(f.dst_port for f in ds.flows), [22, 443])
        self.assertEqual([s.kept for s in ds.stats], [1, 1])

    def test_truncated_gzip_keeps_records_read_before_the_error(self):
        body = "".join(zeek_conn(1760000000 + i, "10.0.0.1", 10000 + i, "10.0.0.2", 80) for i in range(5000))
        p = self.write("conn.log.gz", body, gz=True)
        with open(p, "rb") as fh:
            data = fh.read()
        with open(p, "wb") as fh:
            fh.write(data[: len(data) // 2])
        ds = load([p])
        self.assertGreater(len(ds.flows), 0)
        self.assertLess(len(ds.flows), 5000)
        self.assertTrue(any("could not be parsed" in n for n in ds.stats[0].notes))

    def test_small_batches_match_one_batch(self):
        files = generate(os.path.join(self.tmp, "in"))
        one, many = load(files), load(files, batch_size=97)
        self.assertEqual(list(one.flows), list(many.flows))
        self.assertEqual(correlate(one)["findings"], correlate(many)["findings"])

    def test_flow_view_is_time_ordered_and_indexable(self):
        p = self.write("flows.csv", "ts,src_ip,dst_ip,dst_port,proto\n"
                       "1760000300,10.0.0.1,10.0.0.2,80,tcp\n"
                       ",10.0.0.1,10.0.0.3,80,tcp\n"
                       "1760000100,10.0.0.1,10.0.0.4,80,tcp\n")
        ds = load([p])
        self.assertEqual([f.dst_ip for f in ds.flows], ["10.0.0.4", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(ds.flows[0].dst_ip, "10.0.0.4")
        self.assertEqual(ds.flows[-1].ts, None)
        self.assertEqual(ds.flows[0].ts.tzinfo is not None, True)
        with self.assertRaises(IndexError):
            ds.flows[3]

    def test_scan_window_limits_telemetry_to_the_scan_period(self):
        scan = self.write("scan.nessus", NESSUS)
        day = 86400
        flows = self.write("flows.csv", "ts,src_ip,src_port,dst_ip,dst_port,proto,action,bytes_out,bytes_in\n"
                           f"{1760000000 + 600},198.51.100.1,40000,10.0.0.5,445,tcp,allow,100,200\n"
                           f"{1760000000 + 30 * day},198.51.100.2,40001,10.0.0.5,445,tcp,allow,100,200\n")
        ds = load([scan, flows])
        self.assertIsNotNone(ds.findings[0].scan_start)
        windowed = correlate(ds, Config())["findings"][0]["exposure"]
        self.assertEqual(windowed["external_sources"], 1)
        self.assertEqual(windowed["window"]["days"], 7)
        everything = correlate(ds, Config(scan_window_days=None))["findings"][0]["exposure"]
        self.assertEqual(everything["external_sources"], 2)
        self.assertNotIn("window", everything)

    def test_list_dataset_matches_loaded_dataset(self):
        files = generate(os.path.join(self.tmp, "in"))
        loaded = load(files)
        manual = Dataset(flows=list(loaded.flows), findings=loaded.findings, threats=loaded.threats,
                         scanned_hosts=loaded.scanned_hosts)
        a, b = correlate(loaded), correlate(manual)
        a.pop("generated"), b.pop("generated")
        a.pop("inputs"), b.pop("inputs")
        a["summary"].pop("zeek_event_counts"), b["summary"].pop("zeek_event_counts")
        a["summary"].pop("ot_protocol_counts"), b["summary"].pop("ot_protocol_counts")
        a["summary"].pop("duplicate_flows_removed"), b["summary"].pop("duplicate_flows_removed")
        self.assertEqual(a, b)

    def test_workdir_is_removed_after_close(self):
        work = os.path.join(self.tmp, "work")
        ds = load(self.pair(), workdir=work)
        self.assertTrue(os.listdir(work))
        ds.close()
        self.assertEqual(os.listdir(work), [])


if __name__ == "__main__":
    unittest.main()
