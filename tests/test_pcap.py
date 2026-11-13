"""PCAP input (converted with Zeek) and the container server mode."""
import gzip
import http.client
import os
import shutil
import socket
import stat
import tempfile
import threading
import unittest
from unittest import mock

from vulnflow import pcap, web
from vulnflow.web import folders, server
from vulnflow.correlate import Config
from vulnflow.pipeline import run

PCAP_HEADER = (b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8 + b"\xff\xff\x00\x00\x01\x00\x00\x00")
PCAPNG_HEADER = b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a" + b"\x00" * 16

# Stands in for Zeek: writes a conn.log (and a log VulnScope must skip) into its working folder,
# reading the capture from the -r argument or stdin, like `zeek -C -r <file|-> local`.
FAKE_ZEEK = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "zeek version 9.9.9"; exit 0; fi
if [ "$3" = "-" ]; then cat > /dev/null; else test -r "$3" || exit 1; fi
printf '#separator \\\\x09\\n#path\\tconn\\n#fields\\tts\\tuid\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p\\tproto\\tservice\\tduration\\torig_bytes\\tresp_bytes\\tconn_state\\n#types\\ttime\\tstring\\taddr\\tport\\taddr\\tport\\tenum\\tstring\\tinterval\\tcount\\tcount\\tstring\\n1762850000.0\\tC1\\t10.0.1.5\\t40000\\t10.0.2.10\\t445\\ttcp\\tsmb\\t0.5\\t100\\t200\\tSF\\n1762850001.0\\tC2\\t10.0.1.6\\t40001\\t10.0.2.10\\t80\\ttcp\\thttp\\t0.5\\t100\\t200\\tSF\\n' > conn.log
echo "loaded" > loaded_scripts.log
"""


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with (gzip.open if name.endswith(".gz") else open)(path, "wb") as fh:
            fh.write(data)
        return path

    def fake_zeek(self):
        path = os.path.join(self.tmp, "zeek")
        with open(path, "w") as fh:
            fh.write(FAKE_ZEEK)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def test_detects_pcap_pcapng_and_gzip_by_content(self):
        self.assertTrue(pcap.is_pcap(self.write("a.bin", PCAP_HEADER)))
        self.assertTrue(pcap.is_pcap(self.write("b.pcapng", PCAPNG_HEADER)))
        self.assertTrue(pcap.is_pcap(self.write("c.pcap.gz", PCAP_HEADER)))
        self.assertFalse(pcap.is_pcap(self.write("conn.log", b"#separator \\x09\n")))
        self.assertFalse(pcap.is_pcap(self.write("d.pcap", b"")))

    def test_missing_zeek_gives_install_hint(self):
        cap = self.write("office.pcap", PCAP_HEADER)
        with mock.patch.dict(os.environ, {"VULNSCOPE_ZEEK": os.path.join(self.tmp, "nope")}):
            with self.assertRaises(ValueError) as ctx:
                run([cap], os.path.join(self.tmp, "out"), Config(), workdir=os.path.join(self.tmp, "w"))
        self.assertIn("brew install zeek", str(ctx.exception))

    def test_pcap_is_converted_and_analyzed(self):
        caps = [self.write("office.pcap", PCAP_HEADER), self.write("lab.pcapng.gz", PCAPNG_HEADER)]
        work = os.path.join(self.tmp, "w")
        with mock.patch.dict(os.environ, {"VULNSCOPE_ZEEK": self.fake_zeek()}):
            res, _ = run(caps, os.path.join(self.tmp, "out"), Config(), workdir=work)
        rows = {i["file"]: i for i in res["inputs"]}
        self.assertEqual(rows["office.pcap"]["format"], "pcap")
        self.assertIn("Zeek 9.9.9", " ".join(rows["office.pcap"]["notes"]))
        self.assertIn("office-conn.log", rows)
        self.assertIn("lab-conn.log", rows)
        self.assertFalse(any("loaded_scripts" in f for f in rows))
        self.assertEqual(res["summary"]["flows"], 2)          # the two captures hold the same sessions
        self.assertFalse(any(n.startswith("vulnscope-pcap-") for n in os.listdir(work)))  # cleaned up

    def test_unreadable_capture_is_reported_not_fatal(self):
        good = self.write("good.pcap", PCAP_HEADER)
        bad = self.write("bad.pcap", PCAP_HEADER)
        zeek = self.fake_zeek()
        real = pcap.subprocess.run

        def flaky(cmd, **kw):
            if len(cmd) > 3 and cmd[3].endswith("bad.pcap"):
                return real(["sh", "-c", "echo 'fatal error: problem with trace file' >&2; exit 1"], **kw)
            return real(cmd, **kw)
        with mock.patch.dict(os.environ, {"VULNSCOPE_ZEEK": zeek}), \
                mock.patch.object(pcap.subprocess, "run", side_effect=flaky):
            res, _ = run([good, bad], os.path.join(self.tmp, "out"), Config(), workdir=os.path.join(self.tmp, "w"))
        notes = {i["file"]: " ".join(i["notes"]) for i in res["inputs"]}
        self.assertIn("could not read this capture", notes["bad.pcap"])
        self.assertIn("problem with trace file", notes["bad.pcap"])


class ContainerModeTests(unittest.TestCase):
    def test_container_mode_keeps_dns_rebinding_check(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        started = threading.Event()
        servers = []

        def fake_forever(srv, data_dir, llm_cfg):
            servers.append(srv)
            started.set()
            srv.serve_forever()
        with mock.patch.object(server, "_serve_forever", fake_forever):
            threading.Thread(target=web.serve, args=("0.0.0.0", port, os.path.join(tmp, "r"), Config()),
                             kwargs={"container": True, "public_port": 18099}, daemon=True).start()
            self.assertTrue(started.wait(10))
        self.addCleanup(servers[0].server_close)
        self.addCleanup(servers[0].shutdown)

        def get(host):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/", headers={"Host": host})
            status = conn.getresponse().status
            conn.close()
            return status
        self.assertEqual(get("localhost:18099"), 200)        # the port published on the host
        self.assertEqual(get(f"127.0.0.1:{port}"), 200)       # healthcheck inside the container
        self.assertEqual(get("evil.example:18099"), 421)
        self.assertEqual(get("192.168.1.20:18099"), 421)

    def test_without_container_mode_non_loopback_is_still_refused(self):
        with self.assertRaises(SystemExit):
            web.serve("0.0.0.0", 0, tempfile.mkdtemp(), Config())


if __name__ == "__main__":
    unittest.main()


class ContainerBrowseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.realpath(os.path.join(self.tmp, "home"))
        self.data = os.path.realpath(os.path.join(self.tmp, "data"))
        os.makedirs(os.path.join(self.home, "Documents", "case1"))
        os.makedirs(self.data)

    def patched(self, host_root):
        return mock.patch.multiple(folders, BROWSE_ROOTS=[self.home, self.data], HOST_ROOT=host_root)

    def test_browse_stays_inside_shared_folders(self):
        with self.patched(""):
            top = folders.list_folder("")
            self.assertEqual(top["path"], self.home)
            self.assertIsNone(top["parent"])                     # no climbing into the container
            self.assertEqual(top["roots"], [self.home, self.data])
            self.assertEqual(folders.list_folder("/etc")["path"], self.home)
            self.assertEqual(folders.list_folder(os.path.join(self.home, "Documents"))["parent"], self.home)

    def test_windows_paths_are_translated(self):
        with self.patched("C:\\Users\\bay"):
            self.assertEqual(folders.host_to_container("C:\\Users\\bay\\Documents\\case1"),
                             self.home + "/Documents/case1")
            self.assertEqual(folders.host_to_container("c:/users/bay"), self.home)
            self.assertEqual(folders.host_to_container("D:\\other"), "D:\\other")
            self.assertEqual(folders.list_folder("C:\\Users\\bay\\Documents")["dirs"], ["case1"])

    def test_locate_folder_from_browser_dialog(self):
        case = os.path.join(self.home, "Documents", "case1")
        with open(os.path.join(case, "conn.log"), "w") as fh:
            fh.write("x" * 10)
        os.makedirs(os.path.join(self.home, "Old", "case1"))           # same name, other contents
        with open(os.path.join(self.home, "Old", "case1", "conn.log"), "w") as fh:
            fh.write("y" * 3)
        with self.patched(""):
            self.assertEqual(folders.locate_folder("case1", [["conn.log", 10]]), {"matches": [case]})
            self.assertIn("error", folders.locate_folder("case1", [["conn.log", 999]]))
            self.assertIn("error", folders.locate_folder("case1", [["../../etc/passwd", 0]]))

    def test_locate_folder_tells_copies_apart_by_file_time(self):
        picked = os.path.join(self.home, "Documents", "telemetry_only")
        copies = [os.path.join(self.home, d, "telemetry_only") for d in ("Downloads", "Old")]
        for i, folder in enumerate([picked] + copies):
            os.makedirs(folder, exist_ok=True)
            for name in ("conn.log", "dns.log"):
                path = os.path.join(folder, name)
                with open(path, "w") as fh:
                    fh.write("z" * 20)
                os.utime(path, (1_700_000_000 + i * 3600, 1_700_000_000 + i * 3600))
        samples = [[n, 20, 1_700_000_000_000] for n in ("conn.log", "dns.log")]
        with self.patched(""):
            self.assertEqual(folders.locate_folder("telemetry_only", samples), {"matches": [picked]})
            # without file times (older page) every copy still matches, so the user picks
            self.assertEqual(len(folders.locate_folder("telemetry_only", [s[:2] for s in samples])["matches"]), 3)
