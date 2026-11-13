"""Compare saved reports: which IOCs and vulnerabilities show up in more than one report, and in
how many networks.

A report is a finished run's output folder (results.json next to its pages). From results.json
come the vulnerabilities (Nessus plugins, per host) and the IOC matches, when the run had an IOC
CSV. A re-hunt then looks for IOCs again in each report's saved normalized data (flows, scan
findings, IPS/IDS alerts, Zeek events) with the analysis' own matching rules (ioc_archive.Matcher),
so an indicator learned later, or matched in only one report, is found in reports that were
analyzed without it. Nothing in a report folder is changed.

A network is the report's network name (Report details, or ``--network-name``), else its report
name, else its folder name. Internal addresses repeat between networks, so items are counted by
what they are (plugin, indicator) and per report, never by internal address alone.
"""
from __future__ import annotations

import csv
import json
import os
import re
import shutil
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import resources, saved
from .errors import UserError
from .ioc_archive import FIELD_KINDS, TYPES, Matcher, indicator_value, read_archives
from .runname import RUN_ID

SAMPLE_HOSTS = 12        # related hosts per report drawn on the page (comparison.json has them all)
CSV_HOSTS = 1000         # related hosts per CSV cell (a spreadsheet cell holds about 32,000 characters)
FIND_DEPTH = 4           # how far inside a folder the command line looks for report folders
META = ("disposition", "sources", "articles", "first_seen", "last_seen")
SEVERITY = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


@dataclass
class Report:
    """One saved report, as listed for choosing and as counted in a comparison."""
    key: str                         # the run id on the upload server, else the folder path
    folder: str                      # its output folder (results.json)
    name: str = ""
    network: str = ""                # network name, as saved (may be empty)
    description: str = ""
    generated: str = ""
    hosts: int = 0
    findings: int = 0
    ioc_matches: int | None = None   # None: analyzed without an IOC CSV
    telemetry_only: bool = False
    threat_alerts: int = 0
    href: str = ""                   # where the comparison page links to it
    reopened_from: str = ""          # a reopened copy: the folder it was opened from
    data_folder: str = ""            # where its normalized/ data is (a reopened copy: the original folder)
    error: str = ""                  # why it can't be read (listed, but can't be chosen)

    @property
    def label(self) -> str:
        """The network this report counts as."""
        return self.network or self.name or folder_label(self.folder)

    @property
    def title(self) -> str:
        return self.name or folder_label(self.folder)


def network_key(label: str) -> str:
    """Network names that differ only in case or spacing are one network ("Plant 3", "plant  3")."""
    return " ".join(label.split()).casefold()


def folder_label(folder: str) -> str:
    """A report folder's own name: ".../<run id>/out" is named by the run id."""
    folder = os.path.normpath(folder)
    base = os.path.basename(folder)
    return os.path.basename(os.path.dirname(folder)) if base == "out" else base


# -- finding and describing reports ------------------------------------------------------------
def reopened(rep: Report) -> Report:
    """A report reopened on the upload page keeps its raw data in the folder it was opened from."""
    marker = saved.read_marker(os.path.dirname(os.path.normpath(rep.folder)))
    if marker is not None:
        source = str(marker.get("source") or "")
        rep.reopened_from = str(marker.get("shown") or source)
        rep.data_folder = source if source and os.path.isdir(source) else rep.folder
    return rep


def describe(folder: str, key: str | None = None) -> Report:
    """The summary listed for one report folder (reads its whole results.json)."""
    rep = Report(key=key or folder, folder=folder, data_folder=folder)
    try:
        res = saved.load_results(folder)
    except saved.SavedRunError as exc:
        rep.error = str(exc)
        return rep
    report, summary = res.get("report") or {}, res["summary"]
    matches = res.get("ioc_matches")
    rep.name = str(report.get("name") or "")
    rep.network = str(report.get("network") or "")
    rep.description = str(report.get("description") or "")
    rep.generated = res["generated"]
    rep.hosts, rep.findings = len(res["hosts"]), len(res["findings"])
    rep.ioc_matches = len(matches) if isinstance(matches, list) else None
    rep.telemetry_only = not summary.get("vulnerability_data_available", True)
    rep.threat_alerts = _int(summary.get("threat_alerts"))
    return rep


def _int(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


class SummaryCache:
    """Report summaries kept between listings, so the list doesn't re-read every results.json
    (they can be tens of MB). An entry is used only while results.json keeps its size and time."""

    def __init__(self, path: str | None):
        self.path, self.entries, self.dirty = path, {}, False
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                self.entries = data if isinstance(data, dict) else {}
            except (OSError, ValueError):
                self.entries = {}

    def describe(self, folder: str, key: str) -> Report:
        try:
            st = os.stat(os.path.join(folder, "results.json"))
        except OSError:
            return describe(folder, key)
        stamp = [st.st_size, st.st_mtime_ns]
        hit = self.entries.get(folder)
        if isinstance(hit, dict) and hit.get("stamp") == stamp and isinstance(hit.get("report"), dict):
            try:
                return Report(**{**hit["report"], "key": key, "folder": folder, "data_folder": folder})
            except TypeError:
                pass                          # written by another version: describe again
        rep = describe(folder, key)
        if not rep.error:
            self.entries[folder] = {"stamp": stamp, "report": asdict(rep)}
            self.dirty = True
        return rep

    def save(self):
        if not (self.path and self.dirty):
            return
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.entries, fh)
        os.replace(tmp, self.path)
        self.dirty = False


def server_reports(data_dir: str, cache: SummaryCache | None = None) -> list[Report]:
    """The upload server's saved runs, newest first. A reopened report keeps reading its raw
    data from the folder it was opened from."""
    cache = cache or SummaryCache(None)
    out = []
    try:
        names = os.listdir(data_dir)
    except OSError:
        return []
    for run_id in names:
        folder = os.path.join(data_dir, run_id, "out")
        if not re.fullmatch(RUN_ID, run_id) or not saved.is_report_folder(folder):
            continue
        rep = reopened(cache.describe(folder, run_id))
        rep.href = f"/runs/{run_id}/"
        out.append(rep)
    cache.save()
    return sorted(out, key=lambda r: (r.generated, r.key), reverse=True)


def find_reports(paths: list[str], depth: int = FIND_DEPTH) -> list[str]:
    """Report folders given directly, or found inside the given folders (for example a server's
    data folder, where each run's report is <run id>/out)."""
    found: list[str] = []

    def walk(folder, level):
        if saved.is_report_folder(folder):
            found.append(folder)
            return                             # a report's own subfolders hold no other reports
        if level >= depth:
            return
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if not e.name.startswith(".") and e.is_dir(follow_symlinks=False):
                walk(e.path, level + 1)

    for path in paths:
        if not os.path.isdir(path):
            raise UserError(f"Not a folder: {path}")
        walk(os.path.abspath(path), 0)
    seen, unique = set(), []
    for f in found:
        real = os.path.realpath(f)
        if real not in seen:
            seen.add(real)
            unique.append(f)
    return unique


# -- reading one report ------------------------------------------------------------------------
def _digest(rep: Report) -> dict:
    """What a comparison needs from one report's results.json; the rest is let go at once."""
    res = saved.load_results(rep.folder)
    vulns: dict[str, dict] = {}
    for f in res["findings"]:
        key = str(f.get("plugin_id") or f.get("plugin_name") or "").strip()
        if not key:
            continue
        sev = f.get("severity") if isinstance(f.get("severity"), int) else 0
        v = vulns.setdefault(key, {"name": "", "severity": -1, "cvss": None, "cves": set(),
                                   "exploit": False, "hosts": set()})
        v["name"] = v["name"] or str(f.get("plugin_name") or key)
        v["severity"] = max(v["severity"], sev)
        cvss = f.get("cvss")
        if isinstance(cvss, (int, float)) and not isinstance(cvss, bool):
            v["cvss"] = cvss if v["cvss"] is None else max(v["cvss"], cvss)
        v["cves"].update(c for c in f.get("cves") or [] if isinstance(c, str))
        v["exploit"] = v["exploit"] or bool(f.get("exploit_available"))
        v["hosts"].add(f["host"])
    iocs: dict[tuple[str, str], dict] = {}
    for row in res.get("ioc_matches") or []:
        if not isinstance(row, dict) or row.get("type") not in TYPES or not isinstance(row.get("value"), str):
            continue
        iocs[(row["type"], row["value"])] = row
    return {"vulns": vulns, "iocs": iocs, "hosts": {h["host"] for h in res["hosts"]}}


# -- looking for IOCs again in a report's saved data -------------------------------------------
# Keys of Zeek fields that hold domains, URLs, hashes or packages ("dns.query" counts as "query";
# the part before the last dot may hold JSON escapes, which json.dumps writes for non-ASCII names).
_EVENT_KEY = re.compile(r'"((?:(?:[^"\\]|\\.)*\.)?(?:' + "|".join(sorted(map(re.escape, FIELD_KINDS), key=len, reverse=True))
                        + r'))"\s*:\s*', re.IGNORECASE)
_DECODER = json.JSONDecoder()


def hunt(rep: Report, archive: dict, observed_hosts: set[str], workdir: str | None = None) -> tuple[list[dict], list[str]]:
    """IOC matches in a report's saved normalized data, found with the analysis' own rules.
    Returns the matches (the shape of results.json "ioc_matches") and notes on what was missing."""
    base = os.path.join(rep.data_folder or rep.folder, "normalized")
    have = lambda name: os.path.isfile(os.path.join(base, name))
    path = lambda name: os.path.join(base, name)
    notes: list[str] = []
    if not os.path.isdir(base):
        return [], ["Its saved data (the normalized folder) wasn't found, so it wasn't searched again"
                    + (" (the folder it was reopened from may have moved)." if rep.reopened_from else ".")]
    kinds = {kind for kind, _ in archive}
    scanned = _column_values(path("findings.csv"), "host_ip") if have("findings.csv") else set()
    m = Matcher(archive, scanned or observed_hosts)
    if "ip" in kinds:
        ips = sorted(value for kind, value in archive if kind == "ip")
        if have("flows.csv"):
            for src, dst, n in _flow_pairs(path("flows.csv"), ips, workdir):
                m.flow(src or "", dst or "", int(n))
        else:
            notes.append("No saved flows (normalized/flows.csv), so IP indicators couldn't be looked for in its traffic.")
        if have("threats.csv"):
            with open(path("threats.csv"), newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    m.flow(row.get("src_ip") or "", row.get("dst_ip") or "", label="IDS/IPS alert")
        elif rep.threat_alerts:
            notes.append(f"Its {rep.threat_alerts} IPS/IDS alert(s) weren't saved by the VulnScope version that made it, "
                         "so an IP seen only in an alert isn't found by the re-hunt.")
    if "cve" in kinds and have("findings.csv"):
        with open(path("findings.csv"), newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                m.finding(row.get("host_ip") or "", (row.get("cves") or "").split())
    if kinds & set(FIELD_KINDS.values()):
        if have("zeek_events.jsonl"):
            _hunt_events(path("zeek_events.jsonl"), archive, m)
        else:
            notes.append("No saved Zeek events (normalized/zeek_events.jsonl), so domains, URLs and hashes weren't looked for.")
    return m.matches(), notes


def _column_values(path: str, column: str) -> set[str]:
    with open(path, newline="", encoding="utf-8") as fh:
        return {row[column] for row in csv.DictReader(fh) if row.get(column)}


def _sql_text(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _flow_pairs(path: str, ips: list[str], workdir: str | None) -> list[tuple]:
    """(src, dst, sessions) for every address pair in a saved flows.csv that involves one of
    ``ips``. DuckDB reads the file in a streaming scan, so a multi-GB file is fine."""
    import duckdb
    tmp = tempfile.mkdtemp(prefix="vulnscope-compare-", dir=workdir)
    con = duckdb.connect()
    try:
        budget = resources.plan(workdir=tmp)
        con.execute(f"SET temp_directory = {_sql_text(os.path.join(tmp, 'spill'))}")
        con.execute(f"SET memory_limit = '{budget.memory // resources.MiB}MiB'")
        con.execute(f"SET threads = {int(budget.threads)}")
        con.execute("CREATE TEMP TABLE hunt(ip VARCHAR)")
        con.execute("INSERT INTO hunt SELECT unnest(?::VARCHAR[])", [ips])
        return con.execute(
            f"SELECT src_ip, dst_ip, count(*)::BIGINT FROM read_csv({_sql_text(path)}, header=true, all_varchar=true, "
            "delim=',', quote='\"', escape='\"', strict_mode=false, null_padding=true) "
            "WHERE src_ip IN (SELECT ip FROM hunt) OR dst_ip IN (SELECT ip FROM hunt) "
            "GROUP BY src_ip, dst_ip").fetchall()
    except duckdb.Error as exc:
        raise UserError(f"Could not read {path}: {exc}") from None
    finally:
        con.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _hunt_events(path: str, archive: dict, m: Matcher):
    """Zeek events: only lines with a field value that is one of the indicators are parsed in
    full and handed to the matcher, which keeps a large file quick to scan."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not _event_may_match(line, archive):
                continue
            try:
                row = json.loads(line)
                fields = row.get("fields")
            except (ValueError, AttributeError):
                continue
            if isinstance(fields, dict):
                m.event(str(row.get("stream") or ""), str(row.get("src_ip") or ""), str(row.get("dst_ip") or ""), fields)


def _event_may_match(line: str, archive: dict) -> bool:
    for key in _EVENT_KEY.finditer(line):
        kind = FIELD_KINDS[key.group(1).lower().rsplit(".", 1)[-1]]
        try:
            value, _ = _DECODER.raw_decode(line, key.end())
        except ValueError:
            return True                       # can't tell: let the full parse decide
        for v in (value if isinstance(value, list) else [value]):
            if isinstance(v, str) and (kind, indicator_value(kind, v)) in archive:
                return True
    return False


# -- the comparison ----------------------------------------------------------------------------
def _meta(row: dict) -> dict:
    return {k: row.get(k) for k in META}


def _merge_meta(into: dict, row: dict):
    """Several reports or IOC CSVs can describe one indicator: keep the earliest first-seen, the
    latest last-seen, every source and link, and the first disposition given."""
    if not into.get("disposition") and row.get("disposition"):
        into["disposition"] = str(row["disposition"])
    for k in ("sources", "articles"):
        have = into.setdefault(k, [])
        for v in row.get(k) or []:
            if isinstance(v, str) and v not in have:
                have.append(v)
    first, last = row.get("first_seen"), row.get("last_seen")
    if isinstance(first, str) and first and (not into.get("first_seen") or first < into["first_seen"]):
        into["first_seen"] = first
    if isinstance(last, str) and last and last > (into.get("last_seen") or ""):
        into["last_seen"] = last


def compare(reports: list[Report], ioc_csvs: list[str] = (), crosscheck: bool = True,
            workdir: str | None = None, log=None) -> dict:
    """Count, for every IOC and vulnerability, the reports and networks it appears in.

    ``ioc_csvs``: IOC CSVs to look for in every report's saved data. ``crosscheck``: also look
    for every IOC that any of the reports matched in all the others."""
    log = log or (lambda _msg: None)
    if not reports:
        raise UserError("Choose at least one report to compare.")
    notes: list[str] = []
    chosen: list[Report] = []
    analyses: dict[tuple, Report] = {}
    for rep in reports:
        if rep.error:
            notes.append(f"{rep.title} was left out: {rep.error}")
            continue
        # A reopened copy, or the same folder twice, is the same analysis: count it once.
        same = (rep.generated, rep.name, rep.hosts, rep.findings, rep.ioc_matches, rep.telemetry_only)
        twin = analyses.get(same)
        if twin is not None:
            notes.append(f"{rep.title} is the same analysis as {twin.title} (made {rep.generated}); counted once.")
            continue
        analyses[same] = rep
        chosen.append(rep)
    if not chosen:
        raise UserError("None of the chosen reports could be read. " + " ".join(notes))
    chosen.sort(key=lambda r: (r.generated, r.title))    # oldest first: left to right on the page

    vulns: dict[str, dict] = {}
    iocs: dict[tuple[str, str], dict] = {}
    observed_hosts: list[set[str]] = []
    for i, rep in enumerate(chosen):
        log(f"Reading {rep.title} ...")
        d = _digest(rep)
        observed_hosts.append(d["hosts"])
        for key, v in d["vulns"].items():
            row = vulns.setdefault(key, {"plugin_id": key, "name": v["name"], "severity": -1, "cvss": None,
                                         "cves": set(), "exploit": False, "seen": {}})
            row["severity"] = max(row["severity"], v["severity"])
            if v["cvss"] is not None:
                row["cvss"] = v["cvss"] if row["cvss"] is None else max(row["cvss"], v["cvss"])
            row["cves"] |= v["cves"]
            row["exploit"] = row["exploit"] or v["exploit"]
            row["seen"][i] = v["hosts"]
        for key, match in d["iocs"].items():
            _add_ioc(iocs, key, i, match, "analysis")

    archive: dict[tuple[str, str], dict] = {}
    if crosscheck:
        for key, row in iocs.items():
            archive[key] = {"id": f"{key[0]}:{key[1]}", "type": key[0], "value": key[1], **_meta(row)}
    hunt_files = []
    if ioc_csvs:
        try:
            extra, stats = read_archives(list(ioc_csvs))
        except UserError as exc:
            msg = str(exc)
            for path in ioc_csvs:               # name the file, not where the server keeps it
                msg = msg.replace(path, os.path.basename(path))
            raise UserError(msg) from None
        except (UnicodeError, csv.Error) as exc:
            raise UserError(f"The IOC CSV can't be read as a CSV file ({exc}).") from None
        hunt_files = [s.file for s in stats]
        for key, row in extra.items():
            _merge_meta(archive.setdefault(key, {"id": row["id"], "type": key[0], "value": key[1],
                                                 "articles": [], "sources": [], "first_seen": "",
                                                 "last_seen": "", "disposition": ""}), row)
    hunted: dict[int, dict] = {}
    if archive:
        with resources.job_slot():       # scanning saved flows can be heavy: one at a time, like analyses
            for i, rep in enumerate(chosen):
                log(f"Looking for {len(archive)} indicator(s) in {rep.title} ...")
                found, hunt_notes = hunt(rep, archive, observed_hosts[i], workdir)
                new = 0
                for match in found:
                    key = (match["type"], match["value"])
                    had = i in iocs.get(key, {}).get("seen", {})
                    _add_ioc(iocs, key, i, match, "re-hunt")
                    new += not had
                hunted[i] = {"matches": len(found), "new": new, "notes": hunt_notes}

    labels = [network_key(rep.label) for rep in chosen]
    vuln_rows = [_vuln_row(row, labels) for row in vulns.values()]
    vuln_rows.sort(key=lambda r: (-r["reports"], -r["networks"], -r["severity"], -r["hosts"], r["name"].lower()))
    ioc_rows = [_ioc_row(key, row, labels) for key, row in iocs.items()]
    ioc_rows.sort(key=lambda r: (-r["reports"], -r["networks"], -r["hosts"], r["type"], r["value"]))
    report_rows = []
    for i, rep in enumerate(chosen):
        h = hunted.get(i)
        report_rows.append({
            "key": rep.key, "name": rep.title, "network": rep.label, "description": rep.description,
            "generated": rep.generated, "hosts": rep.hosts, "findings": rep.findings,
            "ioc_matches": rep.ioc_matches, "telemetry_only": rep.telemetry_only, "href": rep.href,
            "reopened_from": rep.reopened_from, "folder": rep.folder,
            "hunted": h is not None, "hunt_matches": h["matches"] if h else 0,
            "found_by_hunt": h["new"] if h else 0, "notes": h["notes"] if h else []})
    shared = lambda rows: sum(1 for r in rows if r["reports"] > 1)
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "reports": report_rows,
        "summary": {"reports": len(chosen), "networks": len(set(labels)),
                    "iocs": len(ioc_rows), "iocs_shared": shared(ioc_rows),
                    "vulns": len(vuln_rows), "vulns_shared": shared(vuln_rows),
                    "found_by_hunt": sum(h["new"] for h in hunted.values())},
        "rehunt": {"crosscheck": crosscheck, "files": hunt_files, "indicators": len(archive),
                   "reports": len(hunted)},
        "notes": notes,
        "iocs": ioc_rows,
        "vulns": vuln_rows,
    }


def _add_ioc(iocs: dict, key: tuple[str, str], i: int, match: dict, how: str):
    row = iocs.setdefault(key, {"type": key[0], "value": key[1], "articles": [], "sources": [],
                                "first_seen": "", "last_seen": "", "disposition": "", "seen": {}})
    _merge_meta(row, match)
    at = row["seen"].setdefault(i, {"hosts": set(), "observed": {}, "how": set()})
    at["hosts"].update(h for h in match.get("hosts") or [] if isinstance(h, str))
    for label, n in (match.get("observed") or {}).items():
        if isinstance(n, int):          # the analysis and a re-hunt see the same records: no double count
            at["observed"][label] = max(at["observed"].get(label, 0), n)
    at["how"].add(how)


def _vuln_row(row: dict, labels: list[str]) -> dict:
    seen = sorted(row["seen"].items())
    sev = max(row["severity"], 0)
    return {"plugin_id": row["plugin_id"], "name": row["name"], "severity": sev,
            "severity_name": SEVERITY.get(sev, str(sev)), "cvss": row["cvss"],
            "cves": sorted(row["cves"]), "exploit": row["exploit"],
            "reports": len(seen), "networks": len({labels[i] for i, _ in seen}),
            "hosts": sum(len(h) for _, h in seen),
            "seen": [{"r": i, "hosts": len(h), "related": sorted(h)} for i, h in seen]}


def _ioc_row(key: tuple[str, str], row: dict, labels: list[str]) -> dict:
    seen = sorted(row["seen"].items())
    return {"type": key[0], "value": key[1], **{k: row[k] for k in META},
            "reports": len(seen), "networks": len({labels[i] for i, _ in seen}),
            "hosts": sum(len(at["hosts"]) for _, at in seen),
            "seen": [{"r": i, "hosts": len(at["hosts"]), "related": sorted(at["hosts"]),
                      "observed": dict(sorted(at["observed"].items())), "how": sorted(at["how"])}
                     for i, at in seen]}


# -- writing it out ----------------------------------------------------------------------------
def write(result: dict, outdir: str) -> dict[str, str]:
    """comparison.html (open it in a browser; works offline), ioc_overlap.csv,
    vulnerability_overlap.csv and comparison.json."""
    from .report import csv_row
    os.makedirs(outdir, exist_ok=True)
    paths = {}
    p = os.path.join(outdir, "comparison.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1)
    paths["comparison.json"] = p
    reports = result["reports"]

    def related(hosts):
        cell = " ".join(hosts[:CSV_HOSTS])
        return cell + (f" (+{len(hosts) - CSV_HOSTS} more in comparison.json)" if len(hosts) > CSV_HOSTS else "")

    p = os.path.join(outdir, "ioc_overlap.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "indicator", "reports", "networks", "hosts", "report", "network", "analyzed",
                    "report_hosts", "related_hosts", "observed", "found_by", "disposition", "sources"])
        for r in result["iocs"]:
            for s in r["seen"]:
                rep = reports[s["r"]]
                w.writerow(csv_row([r["type"], r["value"], r["reports"], r["networks"], r["hosts"], rep["name"],
                                    rep["network"], rep["generated"], s["hosts"], related(s["related"]),
                                    "; ".join(f"{n} {label}" for label, n in s["observed"].items()),
                                    " + ".join(s["how"]), r["disposition"] or "", "; ".join(r["sources"] or [])]))
    paths["ioc_overlap.csv"] = p
    p = os.path.join(outdir, "vulnerability_overlap.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["plugin_id", "vulnerability", "severity", "cvss", "cves", "exploit_available", "reports",
                    "networks", "hosts", "report", "network", "analyzed", "report_hosts", "related_hosts"])
        for r in result["vulns"]:
            for s in r["seen"]:
                rep = reports[s["r"]]
                w.writerow(csv_row([r["plugin_id"], r["name"], r["severity_name"], r["cvss"], " ".join(r["cves"]),
                                    r["exploit"], r["reports"], r["networks"], r["hosts"], rep["name"],
                                    rep["network"], rep["generated"], s["hosts"], related(s["related"])]))
    paths["vulnerability_overlap.csv"] = p
    p = os.path.join(outdir, "comparison.html")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(page(result))
    paths["comparison.html"] = p
    return paths


def page(result: dict) -> str:
    """The comparison as one self-contained page (data, styles and script inline)."""
    import html
    from .branding import icon_data_uri, product_name
    from .report import CSS, THEME_INIT, theme_control
    static = os.path.join(os.path.dirname(__file__), "static")

    def read(name):
        with open(os.path.join(static, name), encoding="utf-8") as fh:
            return fh.read()
    slim = {**result,
            "iocs": [{**r, "seen": [{**s, "related": s["related"][:SAMPLE_HOSTS]} for s in r["seen"]]} for r in result["iocs"]],
            "vulns": [{**r, "seen": [{**s, "related": s["related"][:SAMPLE_HOSTS]} for s in r["seen"]]} for r in result["vulns"]]}
    blob = json.dumps(slim, separators=(",", ":")).replace("<", "\\u003c")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>Compare reports · {html.escape(product_name())}</title><link rel=\"icon\" href=\"{icon_data_uri()}\">"
            f"{THEME_INIT}<style>{CSS}{read('compare.css')}</style></head><body>{theme_control()}"
            f"<main id=\"cmp\" data-sample=\"{SAMPLE_HOSTS}\"><h1>Seen in more than one report</h1>"
            "<noscript><p>This page needs JavaScript. The same data is in ioc_overlap.csv, "
            "vulnerability_overlap.csv and comparison.json next to it.</p></noscript></main>"
            f"<script type=\"application/json\" id=\"cmp-data\">{blob}</script>"
            f"<script>{read('compare.js')}</script></body></html>")
