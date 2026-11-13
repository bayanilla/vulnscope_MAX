"""Compare reports: IOCs and vulnerabilities counted across saved reports, the re-hunt over saved
data, the command line and the web page."""
import contextlib
import csv
import http.client
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import uuid
from collections import defaultdict
from http.server import ThreadingHTTPServer
from unittest import mock

from vulnflow import cli, combine, compare, sample_gootloader, saved
from vulnflow.correlate import Config
from vulnflow.errors import UserError
from vulnflow.ioc_archive import Matcher, read_archives
from vulnflow.pipeline import run
from vulnflow.samples import generate
from vulnflow.web import SAVED_SANDBOX, make_handler

PLANT_IOCS = ("type,indicator,disposition,sources,articleUrls\n"
              "ip,203.0.113.45,Actionable,Research,https://research.example/a\n"
              "ip,8.8.8.8,Actionable,Research,\n"
              "cve,CVE-2024-21887,Actionable,Research,\n"
              "domain,never-seen.example,Actionable,Research,\n")
# Run ids as the upload server names them: <name>_<time>.
NOV, DEC, SEG, LAW = ("Plant-3-November_2026-11-01_09-00-00", "Plant-3-December_2026-12-01_09-00-00",
                      "Segment-6_2026-11-05_10-00-00", "Law-firm_2026-11-08_14-30-00")


def matches_by_key(matches):
    return {(m["type"], m["value"]): (m["hosts"], m["observed"]) for m in matches}


class CompareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        plant = generate(os.path.join(cls.tmp, "plant"))
        goot = sample_gootloader.generate(os.path.join(cls.tmp, "gootloader"))
        cls.plant_iocs = os.path.join(cls.tmp, "iocs", "plant_iocs.csv")
        os.makedirs(os.path.dirname(cls.plant_iocs))
        with open(cls.plant_iocs, "w", encoding="utf-8") as fh:
            fh.write(PLANT_IOCS)
        cls.law_iocs = next(p for p in goot if p.endswith("ioc_indicators.csv"))
        cls.data = os.path.join(cls.tmp, "data")
        cls.folder = {}
        for run_id, paths, report in (
                (NOV, plant + [cls.plant_iocs], {"name": "Plant 3 November", "network": "Plant 3"}),
                (DEC, plant, {"name": "Plant 3 December", "network": "Plant 3"}),
                (SEG, [p for p in plant if not p.endswith(".nessus")], {"name": "Segment 6"}),
                (LAW, goot, {"name": "Law firm intrusion"})):
            out = os.path.join(cls.data, run_id, "out")
            with contextlib.redirect_stderr(io.StringIO()):
                run(paths, out, article_previews=False, report=report)
            cls.folder[run_id] = out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def reports(self, *run_ids):
        return [compare.describe(self.folder[r], r) for r in run_ids]

    def results(self, run_id):
        return saved.load_results(self.folder[run_id])

    def copy(self, run_id, name):
        folder = os.path.join(self.tmp, name)
        shutil.copytree(self.folder[run_id], folder)
        self.addCleanup(shutil.rmtree, folder, True)
        return folder

    @staticmethod
    def row(rows, value):
        return next(r for r in rows if r.get("value", r.get("plugin_id")) == value)

    # -- the re-hunt ---------------------------------------------------------------------------
    def test_rehunt_finds_what_the_analysis_found(self):
        """Looking for a report's own IOC CSV in its saved data finds the same indicators, hosts
        and counts as the analysis did: flows, scan findings, IPS/IDS alerts and Zeek events."""
        for run_id, csv_path in ((NOV, self.plant_iocs), (LAW, self.law_iocs)):
            with self.subTest(run_id):
                res = self.results(run_id)
                archive, _ = read_archives([csv_path])
                found, notes = compare.hunt(compare.describe(self.folder[run_id]), archive,
                                            {h["host"] for h in res["hosts"]})
                self.assertEqual(notes, [])
                self.assertTrue(res["ioc_matches"])
                self.assertEqual(matches_by_key(found), matches_by_key(res["ioc_matches"]))
        labels = {label for m in self.results(LAW)["ioc_matches"] for label in m["observed"]}
        self.assertIn("IDS/IPS alert", labels)                      # read back from normalized/threats.csv
        self.assertTrue({"dns event", "http event"} & labels)

    def test_event_prefilter_never_skips_a_match(self):
        archive, _ = read_archives([self.law_iocs])
        rep = compare.describe(self.folder[LAW])
        quick, _ = compare.hunt(rep, archive, set())
        with mock.patch.object(compare, "_event_may_match", return_value=True):
            full, _ = compare.hunt(rep, archive, set())
        self.assertEqual(quick, full)
        arch = {("domain", "evil.example"): {}, ("url", "http://evil.example/x"): {}}
        for fields in ({"query": "evil.example"}, {"dns.QUERY": "EVIL.example"}, {"host": ["a.example", "evil.example"]},
                       {"über.server_name": "evil.example"}, {"uri": "http://evil.example/x"}):
            line = json.dumps({"stream": "dns", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "fields": fields})
            m = Matcher(arch, set())
            m.event("dns", "10.0.0.1", "10.0.0.2", fields)
            self.assertTrue(m.matches(), fields)                  # the analysis would match it ...
            self.assertTrue(compare._event_may_match(line, arch), line)   # ... so the quick check lets it through
        for fields in ({"query": "other.example"}, {"resp_h": "evil.example"}, {"query": 5}):
            line = json.dumps({"stream": "dns", "fields": fields})
            self.assertFalse(compare._event_may_match(line, arch), line)

    def test_missing_saved_data_is_noted(self):
        archive, _ = read_archives([self.law_iocs])
        folder = self.copy(LAW, "law-without-alerts")
        os.remove(os.path.join(folder, "normalized", "threats.csv"))   # as written before threats.csv existed
        os.remove(os.path.join(folder, "normalized", "zeek_events.jsonl"))
        rep = compare.describe(folder)
        self.assertGreater(rep.threat_alerts, 0)
        found, notes = compare.hunt(rep, archive, set())
        self.assertNotIn("IDS/IPS alert", {label for m in found for label in m["observed"]})
        self.assertTrue(any("IPS/IDS alert" in n for n in notes), notes)
        self.assertTrue(any("Zeek events" in n for n in notes), notes)
        shutil.rmtree(os.path.join(folder, "normalized"))
        self.assertEqual(compare.hunt(rep, archive, set())[0], [])
        self.assertIn("wasn't found", compare.hunt(rep, archive, set())[1][0])

    # -- counting ------------------------------------------------------------------------------
    def test_counts_reports_and_networks(self):
        reports = self.reports(NOV, DEC, SEG, LAW)
        reports[1].network = " PLANT  3"                              # typed differently, still the same network
        result = compare.compare(reports, crosscheck=False)
        s = result["summary"]
        self.assertEqual((s["reports"], s["networks"]), (4, 3))       # November and December are one network
        self.assertEqual([r["name"] for r in result["reports"]],       # oldest first
                         sorted([r["name"] for r in result["reports"]],
                                key=lambda n: next(r["generated"] for r in result["reports"] if r["name"] == n)))
        vuln = next(v for v in result["vulns"] if "CVE-2024-21887" in v["cves"])
        self.assertEqual((vuln["reports"], vuln["networks"]), (2, 1))
        self.assertEqual(s["vulns_shared"], sum(1 for v in result["vulns"] if v["reports"] > 1))
        self.assertEqual(result["rehunt"]["indicators"], 0)
        self.assertEqual(s["found_by_hunt"], 0)
        for row in result["iocs"]:                                     # only what the analyses matched
            self.assertTrue(all(seen["how"] == ["analysis"] for seen in row["seen"]), row)
        segment = next(r for r in result["reports"] if r["name"] == "Segment 6")
        self.assertEqual((segment["network"], segment["telemetry_only"], segment["ioc_matches"]),
                         ("Segment 6", True, None))                    # no network name: its report name

    def test_rehunt_looks_for_each_reports_iocs_in_the_others(self):
        result = compare.compare(self.reports(NOV, DEC, SEG))
        own = matches_by_key(self.results(NOV)["ioc_matches"])
        names = [r["name"] for r in result["reports"]]
        ip = self.row(result["iocs"], "8.8.8.8")
        self.assertEqual((ip["reports"], ip["networks"]), (3, 2))
        how = {names[s["r"]]: s["how"] for s in ip["seen"]}
        self.assertEqual(how, {"Plant 3 November": ["analysis", "re-hunt"], "Plant 3 December": ["re-hunt"],
                               "Segment 6": ["re-hunt"]})
        nov = next(s for s in ip["seen"] if names[s["r"]] == "Plant 3 November")
        self.assertEqual(nov["observed"], own[("ip", "8.8.8.8")][1])     # seen twice, counted once
        cve = self.row(result["iocs"], "CVE-2024-21887")
        self.assertEqual(sorted(names[s["r"]] for s in cve["seen"]), ["Plant 3 December", "Plant 3 November"])
        new = sum(1 for r in result["iocs"] for s in r["seen"] if s["how"] == ["re-hunt"])
        self.assertGreater(new, 0)
        self.assertEqual(result["summary"]["found_by_hunt"], new)
        self.assertEqual(sum(r["found_by_hunt"] for r in result["reports"]), new)
        self.assertEqual(result["rehunt"], {"crosscheck": True, "files": [], "indicators": len(own), "reports": 3})

    def test_ioc_csv_is_looked_for_in_every_report(self):
        result = compare.compare(self.reports(DEC, SEG), [self.plant_iocs], crosscheck=False)
        self.assertEqual(result["rehunt"]["files"], ["plant_iocs.csv"])
        ip = self.row(result["iocs"], "203.0.113.45")
        self.assertEqual((ip["reports"], ip["networks"]), (2, 2))
        self.assertEqual((ip["disposition"], ip["sources"], ip["articles"]),
                         ("Actionable", ["Research"], ["https://research.example/a"]))
        self.assertIn("IDS/IPS alert", ip["seen"][0]["observed"])
        self.assertNotIn("never-seen.example", [r["value"] for r in result["iocs"]])

    def test_same_analysis_is_counted_once(self):
        twin = compare.describe(self.copy(NOV, "nov-copy"))
        result = compare.compare(self.reports(NOV) + [twin], crosscheck=False)
        self.assertEqual(result["summary"]["reports"], 1)
        self.assertTrue(any("same analysis" in n for n in result["notes"]), result["notes"])

    def test_bad_ioc_csv_names_the_file_only(self):
        secret = os.path.join(self.tmp, "server", "private", "dir")
        os.makedirs(secret, exist_ok=True)
        bad = os.path.join(secret, "bad.csv")
        with open(bad, "w") as fh:
            fh.write("foo,bar\n1,2\n")
        with self.assertRaises(UserError) as cm:
            compare.compare(self.reports(NOV), [bad])
        self.assertIn("bad.csv", str(cm.exception))
        self.assertNotIn("private", str(cm.exception))
        with open(bad, "wb") as fh:
            fh.write(b"type,indicator\n\xff\xfe\x00\x81broken\n")
        with self.assertRaises(UserError) as cm:
            compare.compare(self.reports(NOV), [bad])
        self.assertIn("can't be read as a CSV file", str(cm.exception))
        with self.assertRaises(UserError):
            compare.compare([])

    # -- files and folders ---------------------------------------------------------------------
    def test_written_files(self):
        reps = self.reports(NOV, DEC, SEG)
        reps[0].name = "</script><script>alert(1)</script>"            # report text goes into the page ...
        reps[1].network = "=cmd|' /C calc'!A0"                          # ... and into spreadsheets
        result = compare.compare(reps)
        out = os.path.join(self.tmp, "written")
        self.addCleanup(shutil.rmtree, out, True)
        paths = compare.write(result, out)
        self.assertEqual(sorted(paths), ["comparison.html", "comparison.json", "explorer.html", "explorer.json",
                                         "ioc_overlap.csv", "vulnerability_overlap.csv"])
        with open(paths["comparison.json"], encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["summary"], result["summary"])
        with open(paths["ioc_overlap.csv"], newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), sum(len(r["seen"]) for r in result["iocs"]))   # one row per report
        ip = [r for r in rows if r["indicator"] == "8.8.8.8"]
        self.assertEqual({r["reports"] for r in ip}, {"3"})
        with open(paths["vulnerability_overlap.csv"], newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), sum(len(r["seen"]) for r in result["vulns"]))
        self.assertIn("'=cmd|' /C calc'!A0", {r["network"] for r in rows})
        self.assertNotIn("=cmd|' /C calc'!A0", {r["network"] for r in rows})
        with open(paths["comparison.html"], encoding="utf-8") as fh:
            page = fh.read()
        self.assertIn('id="cmp-data"', page)
        self.assertNotIn("<script>alert(1)", page)
        blob = re.search(r'<script type="application/json" id="cmp-data">(.*?)</script>', page, re.S)[1]
        self.assertEqual(json.loads(blob)["reports"][0]["name"], "</script><script>alert(1)</script>")
        self.assertEqual(json.loads(blob)["explorer"]["file"], "explorer.html")      # the page links the map

    # -- all networks on one map (combine.py) --------------------------------------------------
    def combined(self, *run_ids):
        result = compare.compare(self.reports(*run_ids))
        return (result,) + combine.build(result)

    @staticmethod
    def island_of(data):
        return {i["name"]: k for k, i in enumerate(data["combined"]["reports"])}

    def test_map_keeps_each_network_apart(self):
        """Each report is an island: its hosts, subnets, links and cards keep to it, even where two
        networks use the same addresses. Outside addresses are one each, merged over every network."""
        result, data, drawer, notes = self.combined(NOV, SEG, LAW)
        self.assertEqual(notes, [])
        c, isl = data["combined"], self.island_of(data)
        self.assertEqual(sorted(isl), sorted(r["name"] for r in result["reports"]))
        self.assertEqual([n["name"] for n in data["networks"]], [i["network"] for i in c["reports"]])
        ids = [n["id"] for n in data["nodes"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual((c["drawn"], c["hosts"]), (len(ids), len(ids)))         # small enough to draw whole
        for n in data["nodes"]:
            self.assertTrue(n["id"].endswith(f"@{n['net']}") and n["subnet"].endswith(f"@{n['net']}"), n)
        nov, seg = isl["Plant 3 November"], isl["Segment 6"]
        self.assertEqual([i for i in ids if i.startswith("10.10.1.10@")], [f"10.10.1.10@{min(nov, seg)}",
                                                                           f"10.10.1.10@{max(nov, seg)}"])
        island = lambda hid: hid.rsplit("@", 1)[1]
        for a, b, *_ in data["links"] + data["risky_links"] + data["subnet_links"]:
            self.assertEqual(island(a), island(b))
        for a, b, *_ in data["links"] + data["risky_links"]:
            self.assertTrue(a in ids and b in ids)
        self.assertEqual({s["id"] for s in data["subnets"]}, {n["subnet"] for n in data["nodes"]})
        self.assertTrue(set(data["focus"]) <= set(ids))
        for hid, card in data["focus"].items():
            self.assertTrue(all(island(p["ip"]) == island(hid) for p in card["peers"] + card["hop2"]))
            self.assertLessEqual(len(card["peers"]), combine.KEEP["peers"])
            self.assertLessEqual(len(card["attackers"]), combine.KEEP["attackers"])
            self.assertGreaterEqual(card["peers_total"], len(card["peers"]))
        out = {e["ip"]: e for e in data["internet"]}
        self.assertEqual(len(out), len(data["internet"]))
        dns = out["8.8.8.8"]                                       # an IOC, reached from both plant networks
        self.assertTrue({nov, seg} <= set(dns["islands"]), dns["islands"])
        self.assertGreater(dns["hosts_total"], combine.MAX_TARGETS)
        self.assertEqual(len(dns["targets"]), combine.MAX_TARGETS)  # beams to the worst hosts of each network
        self.assertEqual({island(t[0]) for t in dns["targets"]}, {str(k) for k in dns["islands"]})
        own = [saved.explorer_blob(saved.read_text(os.path.join(self.folder[r], "explorer.html"), "x"),
                                   self.results(r)["generated"]) for r in (NOV, SEG, LAW)]
        self.assertEqual(data["counts"]["flows"], sum(d["counts"]["flows"] for d in own))
        self.assertEqual(c["hosts"], sum(len(d["nodes"]) for d in own))
        self.assertEqual((data["start"], data["timeline"]), (None, None))   # no Timeline over many networks

    def test_map_highlights_what_more_than_one_report_has(self):
        result, data, drawer, notes = self.combined(NOV, DEC, SEG, LAW)
        c, isl = data["combined"], self.island_of(data)
        items = c["items"]
        self.assertEqual(len(items), sum(1 for r in result["iocs"] + result["vulns"] if r["reports"] > 1))
        ip = next(i for i in items if i["k"] == "ioc" and i["label"] == "8.8.8.8")
        row = next(r for r in result["iocs"] if r["value"] == "8.8.8.8")
        names = [r["name"] for r in result["reports"]]
        self.assertEqual((ip["reports"], ip["networks"]), (row["reports"], row["networks"]))
        self.assertEqual(ip["islands"], sorted(isl[names[s["r"]]] for s in row["seen"]))
        self.assertGreaterEqual(len(ip["islands"]), 3)          # both months of Plant 3 and Segment 6 at least
        hosts = {f"{h}@{isl[names[s['r']]]}" for s in row["seen"] for h in s["related"]}
        j = items.index(ip)
        self.assertEqual({n["id"] for n in data["nodes"] if j in n.get("sh", ())}, hosts)   # lit in every network
        self.assertEqual(ip["drawn"], len(hosts))
        self.assertEqual(sorted(next(m for m in data["ioc_matches"] if m["value"] == "8.8.8.8")["hosts"]),
                         sorted(hosts))
        vuln = next(i for i in items if i["k"] == "vuln" and "CVE-2024-21887" in i["cves"])
        self.assertEqual(vuln["islands"], sorted([isl["Plant 3 November"], isl["Plant 3 December"]]))
        for n in data["nodes"]:
            self.assertTrue(all(items[j]["reports"] > 1 for j in n.get("sh", ())))
        for k, rep in enumerate(c["reports"]):                   # [plain, IOC or vulnerability, shared]
            mine = [n for n in data["nodes"] if n["net"] == k]
            self.assertEqual(sum(rep["levels"]), len(mine))
            self.assertEqual(rep["levels"][2], sum(1 for n in mine if n.get("sh")))
        self.assertTrue(c["reports"][isl["Plant 3 November"]]["levels"][2])
        self.assertTrue(data["vulnerability_data_available"])
        self.assertTrue(c["reports"][isl["Segment 6"]]["telemetry_only"])

    def test_map_is_trimmed_fairly(self):
        """Over MAX_NODES: shared-item hosts first, then the other IOC and vulnerability hosts, then
        the rest, taken in turn from each report, each in its report's own order."""
        result = compare.compare(self.reports(NOV, SEG, LAW))
        full = combine.build(result)[0]
        level = lambda n: 2 if n.get("sh") else 1 if (n.get("sev") or full["ioc_counts"].get(n["id"])) else 0
        by_level = [sum(1 for n in full["nodes"] if level(n) == lv) for lv in (0, 1, 2)]
        cap = by_level[2] + by_level[1] // 2                     # cuts into the IOC and vulnerability hosts
        with mock.patch.object(combine, "MAX_NODES", cap):
            data = combine.build(result)[0]
        c, ids = data["combined"], {n["id"] for n in data["nodes"]}
        self.assertEqual((c["drawn"], c["hosts"], len(ids)), (cap, len(full["nodes"]), cap))
        self.assertEqual(sorted((level(n) for n in data["nodes"]), reverse=True),
                         sorted((level(n) for n in full["nodes"]), reverse=True)[:cap])
        self.assertEqual([n["id"] for n in data["nodes"]], [n["id"] for n in full["nodes"] if n["id"] in ids])
        took, left = defaultdict(int), defaultdict(int)
        for k in range(len(c["reports"])):
            for lv in (0, 1, 2):
                mine = [n["id"] for n in full["nodes"] if n["net"] == k and level(n) == lv]
                kept = [i for i in mine if i in ids]
                self.assertEqual(kept, mine[:len(kept)])           # its report's riskiest first
                if lv == 1:
                    took[k], left[k] = len(kept), len(mine) - len(kept)
        for a in took:                                            # in turn from each report
            for b in took:
                if left[a]:
                    self.assertLessEqual(took[b], took[a] + 1, (took, left))
        self.assertEqual(sum(r["drawn"] for r in c["reports"]), cap)
        self.assertEqual(sum(s["drawn"] for s in data["subnets"]), cap)
        self.assertTrue(set(data["focus"]) <= ids)
        for a, b, *_ in data["links"] + data["risky_links"]:
            self.assertTrue(a in ids and b in ids)
        for m in data["ioc_matches"]:
            self.assertTrue(set(m["hosts"]) <= ids)
        for e in data["internet"]:
            self.assertTrue(all(t[0] in ids for t in e["targets"]))
            self.assertGreaterEqual(e["hosts_total"], len(e["targets"]))

    def test_reports_that_cant_be_drawn_are_noted(self):
        gone = self.copy(DEC, "dec-no-explorer")
        os.remove(os.path.join(gone, "explorer.html"))
        mixed = self.copy(SEG, "seg-mixed")                       # its explorer.html from another analysis
        page = os.path.join(mixed, "explorer.html")
        with open(page, encoding="utf-8") as fh:
            text = fh.read()
        with open(page, "w", encoding="utf-8") as fh:
            fh.write(text.replace(f'"generated":"{saved.load_results(mixed)["generated"]}"',
                                  '"generated":"2020-01-01T00:00:00Z"', 1))
        result = compare.compare(self.reports(NOV) + [compare.describe(gone, "dec"), compare.describe(mixed, "seg")])
        with mock.patch.object(combine, "DRAWER_HOSTS", 10 ** 6):
            data, drawer, notes = combine.build(result)
        self.assertEqual(len(notes), 2, notes)
        self.assertIn("Plant 3 December isn't on the all-networks map: it has no Explorer page (explorer.html).", notes)
        self.assertTrue(any(n.startswith("Segment 6 isn't on the all-networks map: explorer.html is from a "
                                         "different analysis") and n.endswith("runs.") for n in notes), notes)
        c = data["combined"]
        self.assertEqual([i["name"] for i in c["reports"]], ["Plant 3 November"])
        self.assertEqual({x["name"]: x["island"] for x in c["compared"]},
                         {"Plant 3 November": 0, "Plant 3 December": None, "Segment 6": None})
        self.assertTrue(all(n["id"].endswith("@0") for n in data["nodes"]))
        self.assertEqual(next(i for i in c["items"] if i["label"] == "8.8.8.8")["islands"], [0])
        self.assertTrue(all(h.endswith("@0") for m in data["ioc_matches"] for h in m["hosts"]))
        named = next(m for m in drawer if m["value"] == "8.8.8.8")["hosts"]   # the details still name every host
        self.assertTrue(any(h.endswith(" (Segment 6)") for h in named), named)
        self.assertTrue(any(h.endswith(" (Plant 3)") for h in named), named)
        self.assertEqual(len(named), len(set(named)))

        with open(os.path.join(mixed, "explorer.html"), "w", encoding="utf-8") as fh:
            fh.write('<script id="vf-data" type="application/json">' + json.dumps(
                {"generated": saved.load_results(mixed)["generated"], "nodes": [{"ip": "10.0.0.1"}], "links": [],
                 "focus": {}}) + "</script>")
        result = compare.compare([compare.describe(gone, "dec"), compare.describe(mixed, "seg")])
        self.assertEqual(combine.build(result), (None, [], [
            "Plant 3 December isn't on the all-networks map: it has no Explorer page (explorer.html).",
            "Segment 6 isn't on the all-networks map: its Explorer data can't be read (missing field 'id')."]))
        out = os.path.join(self.tmp, "nothing-drawn")
        self.addCleanup(shutil.rmtree, out, True)
        os.makedirs(out)
        for name in ("explorer.html", "explorer.json"):          # left by an earlier comparison in this folder
            with open(os.path.join(out, name), "w") as fh:
                fh.write("old")
        paths = compare.write(result, out)
        self.assertNotIn("explorer.html", paths)
        self.assertEqual(sorted(os.listdir(out)), ["comparison.html", "comparison.json", "ioc_overlap.csv",
                                                   "vulnerability_overlap.csv"])
        self.assertEqual(result["explorer"], {"file": None, "notes": result["explorer"]["notes"]})
        self.assertEqual(len(result["explorer"]["notes"]), 2)

    def test_map_page(self):
        reps = self.reports(NOV, SEG)
        reps[1].network = "</script><script>alert(1)</script>"
        result = compare.compare(reps)
        out = os.path.join(self.tmp, "map-page")
        self.addCleanup(shutil.rmtree, out, True)
        paths = compare.write(result, out)
        self.assertEqual(result["explorer"]["file"], "explorer.html")
        self.assertEqual({k: result["explorer"][k] for k in ("reports", "networks", "notes")},
                         {"reports": 2, "networks": 2, "notes": []})
        with open(paths["explorer.html"], encoding="utf-8") as fh:
            page = fh.read()
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn('<span id="report-name"', page)
        self.assertIn("<title>All networks · ", page)
        blob = json.loads(re.search(r'<script id="vf-data" type="application/json">(.*?)</script>', page, re.S)[1])
        with open(paths["explorer.json"], encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), blob)
        self.assertEqual(blob["report"]["name"], "All networks")
        self.assertIn("2 reports from 2 networks", blob["report"]["description"])
        self.assertIn("</script><script>alert(1)</script>", {n["name"] for n in blob["networks"]})
        drawer = json.loads(re.search(r'<script id="ioc-provenance-data" type="application/json">(.*?)</script>',
                                      page, re.S)[1])
        named = next(m for m in drawer if m["value"] == "8.8.8.8")["hosts"]
        self.assertTrue(all(h.endswith((" (Plant 3)", " (</script><script>alert(1)</script>)"))
                            for h in named[:-1]), named)           # the drawer names each host's network ...
        mapped = next(m for m in blob["ioc_matches"] if m["value"] == "8.8.8.8")["hosts"]
        nov = next(k for k, r in enumerate(blob["combined"]["reports"]) if r["network"] == "Plant 3")
        self.assertIn(f"{named[0].split()[0]}@{nov}", mapped)      # ... the map its own ids
        with mock.patch.object(combine, "DRAWER_HOSTS", 2):
            many = combine.build(result)[1]
        named = next(m for m in many if m["value"] == "8.8.8.8")["hosts"]
        self.assertEqual(len(named), 3)
        self.assertRegex(named[-1], r"^and [\d,]+ more \(see comparison\.json\)$")

    def test_explorer_href(self):
        self.assertEqual(combine.explorer_href("/runs/abc/"), "/runs/abc/explorer.html")
        self.assertEqual(combine.explorer_href("../abc/out/explorer.html"), "../abc/out/explorer.html")
        self.assertEqual(combine.explorer_href("../abc/out/executive_summary.html"), "")
        self.assertEqual(combine.explorer_href(""), "")

    def test_find_reports(self):
        found = compare.find_reports([self.data])
        self.assertEqual(sorted(found), sorted(self.folder.values()))
        link = os.path.join(self.tmp, "linked")
        os.symlink(self.folder[NOV], link)
        self.addCleanup(os.remove, link)
        self.assertEqual(len(compare.find_reports([self.folder[NOV], link])), 1)    # the same folder twice
        with self.assertRaises(UserError):
            compare.find_reports([os.path.join(self.tmp, "no-such-folder")])

    def test_summary_cache(self):
        path = os.path.join(self.tmp, "cache", "index.json")
        first = compare.SummaryCache(path).describe(self.folder[NOV], NOV)
        cache = compare.SummaryCache(path)
        cache.describe(self.folder[NOV], NOV)
        cache.save()
        with mock.patch.object(compare, "describe", side_effect=AssertionError("read again")):
            self.assertEqual(compare.SummaryCache(path).describe(self.folder[NOV], NOV), first)
        folder = self.copy(NOV, "nov-edited")
        cache.describe(folder, "edited")
        cache.save()
        res = saved.load_results(folder)
        res["report"]["name"] = "Renamed"
        with open(os.path.join(folder, "results.json"), "w", encoding="utf-8") as fh:
            json.dump(res, fh)
        self.assertEqual(compare.SummaryCache(path).describe(folder, "edited").name, "Renamed")

    def test_command_line(self):
        out = os.path.join(self.tmp, "cli-out")
        self.addCleanup(shutil.rmtree, out, True)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["compare", self.data, "-o", out, "--no-crosscheck",
                             "--network", f"{self.folder[SEG]}=Plant 3"])
        self.assertEqual(code, 0, stderr.getvalue())
        self.assertIn("Compared 4 report(s) from 2 network(s).", stdout.getvalue())
        self.assertRegex(stdout.getvalue(), r"All networks on one map: [\d,]+ of [\d,]+ hosts from 4 report\(s\) in explorer\.html")
        self.assertTrue(os.path.isfile(os.path.join(out, "explorer.html")))
        with open(os.path.join(out, "comparison.json"), encoding="utf-8") as fh:
            result = json.load(fh)
        self.assertEqual({r["network"] for r in result["reports"]}, {"Plant 3", "Law firm intrusion"})
        for r in result["reports"]:                                  # links work from the output folder
            self.assertTrue(r["href"].endswith("/out/explorer.html"), r["href"])
            self.assertTrue(os.path.isfile(os.path.normpath(os.path.join(out, r["href"]))), r["href"])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["compare", self.data, "-o", out, "--network", "no-equals-sign"]), 2)
            self.assertEqual(cli.main(["compare", os.path.join(self.tmp, "nothing-here"), "-o", out]), 2)
            self.assertEqual(cli.main(["compare", os.path.join(self.tmp, "iocs"), "-o", out]), 1)
        self.assertIn("No report folders found", err.getvalue())


class CompareWebTests(unittest.TestCase):
    """The Compare page on the upload server: tick saved runs, optionally add an IOC CSV."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        plant = generate(os.path.join(cls.tmp, "plant"))
        cls.data = os.path.join(cls.tmp, "data")
        for run_id, paths, report in ((NOV, plant, {"name": "Plant 3 November", "network": "Plant 3"}),
                                      (SEG, [p for p in plant if not p.endswith(".nessus")], {"name": "Segment 6"})):
            with contextlib.redirect_stderr(io.StringIO()):
                run(paths, os.path.join(cls.data, run_id, "out"), article_previews=False, report=report)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.data, Config()))
        cls.port = cls.srv.server_port
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, True)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{self.port}", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read().decode(errors="replace")
        conn.close()
        return resp.status, data, resp

    def post(self, fields, files=(), csrf=None):
        status, page, _ = self.request("GET", "/compare")
        self.assertEqual(status, 200)
        token = re.search(r'name="csrf" value="([^"]+)"', page)[1] if csrf is None else csrf
        boundary = uuid.uuid4().hex
        body = b""
        for name, value in [("csrf", token)] + list(fields):
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").encode()
        for filename, content in files:
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"ioc_csv\"; filename=\"{filename}\"\r\n"
                     "Content-Type: text/csv\r\n\r\n").encode() + content + b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        return self.request("POST", "/compare", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    def comparisons(self):
        root = os.path.join(self.data, "comparisons")
        return sorted(n for n in os.listdir(root) if os.path.isdir(os.path.join(root, n))) if os.path.isdir(root) else []

    def test_compare_ticked_reports(self):
        status, page, _ = self.request("GET", "/compare")
        self.assertIn("Plant 3 November", page)
        self.assertIn(f'name="run_{SEG}"', page)
        self.assertIn(f'name="net_{SEG}" value="Segment 6"', page)
        status, page, resp = self.post([(f"run_{NOV}", "1"), (f"run_{SEG}", "1"), (f"net_{SEG}", " Plant\n3 "),
                                        ("crosscheck", "1")], [("my iocs.csv", PLANT_IOCS.encode())])
        self.assertEqual(status, 303, page)
        where = resp.getheader("Location")
        self.assertRegex(where, r"^/compare/\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d(-\d+)?/$")
        status, page, resp = self.request("GET", where)
        self.assertEqual(status, 200)
        self.assertIn(SAVED_SANDBOX, resp.getheader("Content-Security-Policy"))        # an opaque origin
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertIn('id="cmp-data"', page)
        status, text, _ = self.request("GET", where + "comparison.json")
        result = json.loads(text)
        self.assertEqual((result["summary"]["reports"], result["summary"]["networks"]), (2, 1))   # renamed network
        self.assertEqual(result["rehunt"]["files"], ["my_iocs.csv"])
        ip = next(r for r in result["iocs"] if r["value"] == "8.8.8.8")
        self.assertEqual(ip["reports"], 2)
        status, page, resp = self.request("GET", where + "explorer.html")       # all networks on one map
        self.assertEqual(status, 200)
        self.assertIn(SAVED_SANDBOX, resp.getheader("Content-Security-Policy"))
        self.assertIn('id="vf-data"', page)
        status, text, resp = self.request("GET", where + "explorer.json")
        self.assertEqual(status, 200)
        self.assertEqual([r["name"] for r in json.loads(text)["combined"]["reports"]],
                         [r["name"] for r in result["reports"]])
        run_of = {"Plant 3 November": NOV, "Segment 6": SEG}                    # each host links to its own report
        self.assertEqual({r["href"] for r in json.loads(text)["combined"]["reports"]},
                         {f"/runs/{run_of[r['name']]}/explorer.html" for r in result["reports"]})
        status, text, resp = self.request("GET", where + "ioc_overlap.csv")
        self.assertEqual(status, 200)
        self.assertTrue(text.startswith("type,indicator,reports"))
        for bad in ("about.json", "in/0/my_iocs.csv", "../../" + NOV + "/out/results.json", "index.html"):
            self.assertEqual(self.request("GET", where + bad)[0], 404, bad)
        self.assertIn(where, self.request("GET", "/compare")[1])                       # listed as an earlier comparison

    def test_refused_requests_leave_nothing_behind(self):
        before = self.comparisons()
        status, page, _ = self.post([(f"run_{NOV}", "1")], csrf="not-the-token")
        self.assertEqual(status, 403)
        status, page, _ = self.post([("crosscheck", "1")])
        self.assertEqual(status, 400)
        self.assertIn("Tick at least one report", page)
        status, page, _ = self.post([(f"run_{NOV}", "1")], [("wrong.csv", b"foo,bar\n1,2\n")])
        self.assertEqual(status, 400)
        self.assertIn("wrong.csv", page)
        self.assertNotIn(self.data, page)
        self.assertIn(f'name="run_{NOV}" value="1" aria-label="Compare Plant 3 November" checked', page)  # kept ticked
        self.assertEqual(self.comparisons(), before)

    def test_comparisons_are_not_runs(self):
        self.post([(f"run_{NOV}", "1")])
        self.assertEqual(self.request("GET", "/runs/comparisons/")[0], 404)
        self.assertNotIn('name="run_comparisons"', self.request("GET", "/compare")[1])


if __name__ == "__main__":
    unittest.main()
