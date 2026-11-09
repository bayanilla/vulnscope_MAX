"""DuckDB sizing from machine RAM, and the guardrails around it."""
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

import duckdb

from vulnflow import resources as r
from vulnflow.resources import GiB, MiB, Machine


def machine(total_gib=16, avail_gib=None, cpus=8):
    avail = None if avail_gib is None else int(avail_gib * GiB)
    return Machine(total=int(total_gib * GiB), available=avail, cpus=cpus)


class ParseSize(unittest.TestCase):
    def test_units(self):
        self.assertEqual(r.parse_size("8GB"), 8 * 1000 ** 3)
        self.assertEqual(r.parse_size("6 GiB"), 6 * GiB)
        self.assertEqual(r.parse_size("512mb"), 512 * 1000 ** 2)
        self.assertEqual(r.parse_size("1.5g"), 1_500_000_000)
        self.assertEqual(r.parse_size("50%", whole=10 * GiB), 5 * GiB)

    def test_rejects_garbage(self):
        for bad in ("lots", "8XB", "", "150%"):
            with self.assertRaises(ValueError):
                r.parse_size(bad, whole=GiB)
        with self.assertRaises(ValueError):
            r.parse_size("50%")


class Plan(unittest.TestCase):
    def plan(self, m, env=None, **kw):
        return r.plan(machine=m, env=env or {}, workdir=tempfile.gettempdir(), **kw)

    def test_auto_is_60_percent_of_ram(self):
        b = self.plan(machine(16))
        self.assertEqual(b.source, "auto")
        self.assertAlmostEqual(b.memory / GiB, 9.6, places=1)
        self.assertEqual(b.ceiling, 12 * GiB)                  # 25% kept for the OS
        self.assertEqual(b.threads, 8)
        self.assertFalse(b.warnings)

    def test_scales_up_on_big_servers(self):
        b = self.plan(machine(128, cpus=32))
        self.assertAlmostEqual(b.memory / GiB, 76.8, places=1)
        self.assertEqual(b.threads, 32)

    def test_small_container_keeps_reserve(self):
        b = self.plan(machine(2, cpus=4))
        self.assertEqual(b.ceiling, int(0.5 * GiB))            # 1.5 GiB minimum reserve
        self.assertLessEqual(b.memory, b.ceiling)
        self.assertEqual(b.threads, 1)                          # < 1 GiB per thread available

    def test_busy_machine_gets_less(self):
        b = self.plan(machine(16, avail_gib=4))
        self.assertAlmostEqual(b.memory / GiB, 3.2, places=1)
        self.assertTrue(any("free right now" in w for w in b.warnings))

    def test_env_override_respected(self):
        b = self.plan(machine(16), {"VULNSCOPE_DUCKDB_MEMORY": "4GiB"})
        self.assertEqual((b.memory, b.source), (4 * GiB, "VULNSCOPE_DUCKDB_MEMORY"))
        self.assertFalse(b.warnings)

    def test_env_override_clamped(self):
        b = self.plan(machine(16), {"VULNSCOPE_DUCKDB_MEMORY": "64GB"})
        self.assertEqual(b.memory, 12 * GiB)
        self.assertIn("more than this machine can spare", b.warnings[0])

    def test_env_percent(self):
        b = self.plan(machine(16), {"VULNSCOPE_DUCKDB_MEMORY": "50%"})
        self.assertEqual(b.memory, 6 * GiB)                     # half of the 12 GiB usable

    def test_bad_env_falls_back_to_auto(self):
        b = self.plan(machine(16), {"VULNSCOPE_DUCKDB_MEMORY": "lots"})
        self.assertEqual(b.source, "auto")
        self.assertTrue(b.warnings)

    def test_argument_beats_env(self):
        b = self.plan(machine(16), {"VULNSCOPE_DUCKDB_MEMORY": "8GB"}, memory_limit="2GiB")
        self.assertEqual((b.memory, b.source), (2 * GiB, "argument"))

    def test_jobs_split_the_budget(self):
        b = self.plan(machine(16), jobs=2)
        self.assertAlmostEqual(b.memory / GiB, 4.8, places=1)
        self.assertEqual(b.ceiling, 6 * GiB)

    def test_threads_override_capped_at_cpus(self):
        self.assertEqual(self.plan(machine(16, cpus=4), {"VULNSCOPE_DUCKDB_THREADS": "64"}).threads, 4)
        self.assertEqual(self.plan(machine(16), {"VULNSCOPE_DUCKDB_THREADS": "2"}).threads, 2)

    def test_spill_capped_to_free_disk(self):
        with mock.patch.object(r, "_free_disk", return_value=100 * GiB):
            self.assertEqual(self.plan(machine(16)).max_temp, 80 * GiB)
            b = self.plan(machine(16), {"VULNSCOPE_DUCKDB_MAX_TEMP": "500GB"})
            self.assertEqual(b.max_temp, 80 * GiB)
            self.assertTrue(b.warnings)
            self.assertEqual(self.plan(machine(16), {"VULNSCOPE_DUCKDB_MAX_TEMP": "10GiB"}).max_temp, 10 * GiB)


class CgroupDetection(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)

    def test_v2_container_limit_and_usage(self):
        self.write("cg/cgroup.controllers", "cpu memory")
        self.write("cg/memory.max", str(4 * GiB))
        self.write("cg/memory.current", str(3 * GiB))
        self.write("cg/memory.stat", f"anon 1\ninactive_file {GiB}\n")
        self.write("cg/cpu.max", "250000 100000")
        self.write("proc", "0::/\n")
        root, proc = os.path.join(self.root, "cg"), os.path.join(self.root, "proc")
        self.assertEqual(r.cgroup_memory(root, proc), (4 * GiB, 2 * GiB))
        self.assertLessEqual(r.cpu_count(root, proc), 3)

    def test_v2_unlimited(self):
        self.write("cg/cgroup.controllers", "memory")
        self.write("cg/memory.max", "max")
        self.write("cg/cpu.max", "max 100000")
        self.write("proc", "0::/\n")
        root, proc = os.path.join(self.root, "cg"), os.path.join(self.root, "proc")
        self.assertEqual(r.cgroup_memory(root, proc), (None, None))

    def test_v1_nested_takes_tightest(self):
        self.write("cg/memory/memory.limit_in_bytes", "9223372036854771712")
        self.write("cg/memory/a/memory.limit_in_bytes", str(8 * GiB))
        self.write("cg/memory/a/b/memory.limit_in_bytes", str(3 * GiB))
        self.write("cg/memory/a/b/memory.usage_in_bytes", str(GiB))
        self.write("cg/cpu/cpu.cfs_quota_us", "-1")
        self.write("cg/cpu/cpu.cfs_period_us", "100000")
        self.write("proc", "4:memory:/a/b\n3:cpu,cpuacct:/\n")
        root, proc = os.path.join(self.root, "cg"), os.path.join(self.root, "proc")
        self.assertEqual(r.cgroup_memory(root, proc), (3 * GiB, GiB))

    def test_this_machine_is_readable(self):
        m = Machine.detect()
        self.assertGreater(m.total, 256 * MiB)
        self.assertGreaterEqual(m.cpus, 1)


class JobSlots(unittest.TestCase):
    def test_second_job_refused_with_clear_message(self):
        with mock.patch.dict(os.environ, {"VULNSCOPE_MAX_JOBS": "1"}):
            with r.job_slot():
                self.assertTrue(r.busy())
                with self.assertRaises(r.BusyError) as ctx:
                    with r.job_slot():
                        pass
                self.assertIn("already running", str(ctx.exception))
                self.assertIsInstance(ctx.exception, ValueError)    # shown to the user, not a traceback
            self.assertFalse(r.busy())

    def test_two_slots_across_threads(self):
        got = []
        gate = threading.Event()

        def worker():
            with r.job_slot():
                got.append("ok")
                gate.wait(5)
        with mock.patch.dict(os.environ, {"VULNSCOPE_MAX_JOBS": "2"}):
            t = threading.Thread(target=worker)
            t.start()
            while not got:
                pass
            with r.job_slot():
                self.assertTrue(r.busy())
            gate.set()
            t.join()
        self.assertFalse(r.busy())


class UploadPageWhileBusy(unittest.TestCase):
    def test_second_folder_analysis_refused(self):
        import re
        import urllib.parse
        import urllib.request
        from http.server import ThreadingHTTPServer
        from vulnflow.correlate import Config
        from vulnflow.web import make_handler
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(tmp, "runs"), Config()))
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        base = f"http://127.0.0.1:{server.server_port}/"
        try:
            with urllib.request.urlopen(base) as resp:
                csrf = re.search(r'name="csrf" value="([^"]+)"', resp.read().decode())[1]
            body = urllib.parse.urlencode({"csrf": csrf, "path": tmp}).encode()
            req = urllib.request.Request(base + "analyze-folder", body, headers={"Origin": base.rstrip("/")})
            with mock.patch.dict(os.environ, {"VULNSCOPE_MAX_JOBS": "1"}), r.job_slot():
                with urllib.request.urlopen(req) as resp:
                    self.assertIn("Another analysis is already running", resp.read().decode())
            runs = os.path.join(tmp, "runs")
            self.assertFalse(os.path.isdir(runs) and os.listdir(runs))        # nothing started
        finally:
            server.shutdown()
            server.server_close()


class FriendlyErrors(unittest.TestCase):
    def test_duckdb_oom_becomes_actionable(self):
        con = duckdb.connect()
        con.execute("SET memory_limit = '32MB'")
        con.execute("SET threads = 1")
        con.execute("SET temp_directory = ''")         # no spilling: force the error
        b = r.plan(machine=machine(16), env={"VULNSCOPE_DUCKDB_MEMORY": "1GiB"}, workdir=tempfile.gettempdir())
        with self.assertRaises(duckdb.Error) as ctx:
            con.execute("SELECT list(range) FROM range(20000000) GROUP BY range % 7").fetchall()
        err = r.explain(ctx.exception, b)
        self.assertIsInstance(err, r.ResourceError)
        self.assertIn("1.0 GiB", str(err))
        self.assertIn("up to 12.0 GiB", str(err))

    def test_at_ceiling_suggests_splitting(self):
        b = r.plan(machine=machine(16), env={"VULNSCOPE_DUCKDB_MEMORY": "64GB"}, workdir=tempfile.gettempdir())
        err = r.explain(duckdb.OutOfMemoryException("Out of Memory Error: x"), b)
        self.assertIn("split the input", str(err))

    def test_disk_full(self):
        err = r.explain(OSError(28, "No space left on device"), None)
        self.assertIn("disk space", str(err))

    def test_spill_cap_reported_as_disk(self):
        exc = duckdb.OutOfMemoryException("Out of Memory Error: failed to offload data block.\n"
                                          "This limit was set by the 'max_temp_directory_size' setting.")
        self.assertIn("disk space", str(r.explain(exc, None)))

    def test_other_errors_untouched(self):
        self.assertIsNone(r.explain(ValueError("bad file"), None))


class StoreApplies(unittest.TestCase):
    def test_store_uses_budget(self):
        from vulnflow.store import Store
        with mock.patch.dict(os.environ, {"VULNSCOPE_DUCKDB_MEMORY": "700MiB",
                                          "VULNSCOPE_DUCKDB_THREADS": "1"}):
            s = Store()
        try:
            mem, threads = s.con.execute(
                "SELECT current_setting('memory_limit'), current_setting('threads')").fetchone()
            self.assertEqual(threads, 1)
            self.assertTrue(mem.startswith(("700", "734")), mem)   # DuckDB may print MiB or MB
            self.assertEqual(s.budget.source, "VULNSCOPE_DUCKDB_MEMORY")
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
