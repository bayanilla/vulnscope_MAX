"""Compare reports: tick saved runs, optionally add an IOC CSV to look for again, and see which
IOCs and vulnerabilities show up in more than one of them (compare.py does the work). Each
comparison is saved under <data_dir>/comparisons/<time>/ and opened from there."""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import traceback

from .. import compare, multipart, resources, runname
from ..errors import UserError
from .pages import asset, busy_overlay, error_html, page, page_config
from .runs import SAVED_SANDBOX

FOLDER = "comparisons"                          # inside the data folder; never a run id (no out/)
COMPARISON_ID = r"\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d(?:-\d{1,3})?"
FILES = ("comparison.html", "comparison.json", "ioc_overlap.csv", "vulnerability_overlap.csv",
         "explorer.html", "explorer.json")
MAX_UPLOAD = 64 * 1024 * 1024                   # an IOC CSV and the ticked boxes
RECENT = 12
HINT = ("Looking for IOCs again in large reports can take a few minutes. Keep this tab open; "
        "the comparison opens here when it's ready.")

PICK = """<h1>Compare reports</h1>
<p>See which IOCs and vulnerabilities show up in more than one report, and in how many networks.
Nothing in the reports is changed.</p>
{error}
<form method="post" action="/compare" enctype="multipart/form-data" class="cmp-pick" data-busy="Comparing reports…" data-busy-hint="{hint}">
<input type="hidden" name="csrf" value="{csrf}">
<h2>Saved reports <span class="hint">({count})</span></h2>
{table}
<h2>Look for IOCs again <span class="hint">(optional)</span></h2>
<label class="check"><input type="checkbox" name="crosscheck" value="1"{crosscheck}> <span>Look for every IOC matched in any
chosen report in all of them<br><span class="hint">Finds an indicator in reports that were analyzed without it, using each
report's saved traffic, scan findings and Zeek events.</span></span></label>
<label for="ioc_csv">IOC CSV</label>
<input id="ioc_csv" type="file" name="ioc_csv" accept=".csv,text/csv">
<div class="hint">The same format as on the upload page (type and indicator columns). Every chosen report is searched for it.</div>
<div class="btnrow"><button type="submit" id="cmp-go">Compare</button> <span class="hint" id="cmp-count" role="status" aria-live="polite"></span></div>
</form>
{recent}
<p class="hint">To include a report saved somewhere else, open it on the <a href="/">upload page</a> first (choose its
output folder; the button changes to Open report). It then appears in this list.</p>
<p><a href="/">New analysis</a></p>"""


def _root(app) -> str:
    return os.path.join(app.data_dir, FOLDER)


def _reports(app) -> list[compare.Report]:
    return compare.server_reports(app.data_dir, compare.SummaryCache(os.path.join(_root(app), "index.json")))


def _table(reports: list[compare.Report], selected: set[str], labels: dict[str, str]) -> str:
    if not reports:
        return '<p class="cmp-empty">No saved reports yet. <a href="/">Analyze a folder</a> first.</p>'
    rows = []
    for r in reports:
        rid = html.escape(r.key, quote=True)
        if r.error:
            rows.append(f'<tr class="off"><td></td><td>{html.escape(r.key)}<div class="hint">{html.escape(r.error)}</div></td>'
                        '<td></td><td></td><td></td><td></td><td></td></tr>')
            continue
        label = labels.get(r.key, r.label)
        made = html.escape(r.generated.replace("T", " ")[:16])
        name = (f'<a href="{html.escape(r.href, quote=True)}" target="_blank" rel="noopener">{html.escape(r.title)}</a>'
                + (f'<div class="hint">Reopened from {html.escape(r.reopened_from)}</div>' if r.reopened_from else "")
                + (f'<div class="hint">{html.escape(r.key)}</div>' if r.name else ""))
        iocs = "no IOC CSV" if r.ioc_matches is None else f"{r.ioc_matches:,}"
        rows.append(
            f'<tr data-text="{html.escape((r.title + " " + label + " " + r.key).lower(), quote=True)}">'
            f'<td><input type="checkbox" name="run_{rid}" value="1" aria-label="Compare {html.escape(r.title, quote=True)}"'
            f'{" checked" if r.key in selected else ""}></td>'
            f'<td>{name}</td>'
            f'<td><input type="text" class="cmp-net" name="net_{rid}" value="{html.escape(label, quote=True)}" '
            f'data-saved="{html.escape(r.label, quote=True)}" maxlength="{runname.NETWORK_MAX}" aria-label="Network of {html.escape(r.title, quote=True)}"></td>'
            f'<td>{made}</td><td class="num">{r.hosts:,}</td>'
            f'<td class="num">{"no scan" if r.telemetry_only else f"{r.findings:,}"}</td><td class="num">{iocs}</td></tr>')
    return ('<div class="cmp-controls"><button type="button" class="secondary" id="cmp-all">Select all</button>'
            '<button type="button" class="secondary" id="cmp-none">Clear</button>'
            '<input type="search" id="cmp-filter" placeholder="Filter by name or network" aria-label="Filter reports"></div>'
            '<p class="hint">Reports with the same network count as one network. A network comes from Report details when the '
            'report was made; change it here for this comparison (your browser remembers the change).</p>'
            '<div class="cmp-scroll"><table class="cmp-table"><thead><tr><th scope="col"><span class="hint">Use</span></th><th scope="col">Report</th>'
            '<th scope="col">Network</th><th scope="col">Analyzed</th><th scope="col" class="num">Hosts</th>'
            '<th scope="col" class="num">Findings</th><th scope="col" class="num">IOC matches</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _recent(app) -> str:
    root = _root(app)
    try:
        names = sorted((n for n in os.listdir(root) if re.fullmatch(COMPARISON_ID, n)), reverse=True)
    except OSError:
        return ""
    items = []
    for name in names[:RECENT]:
        try:
            with open(os.path.join(root, name, "about.json"), encoding="utf-8") as fh:
                about = json.load(fh)
            reports = [str(r) for r in about.get("reports", [])]
            s = about.get("summary", {})
            what = (f'{s.get("iocs_shared", 0):,} shared IOCs, {s.get("vulns_shared", 0):,} shared vulnerabilities'
                    f' · {", ".join(reports[:4])}{" …" if len(reports) > 4 else ""}')
        except (OSError, ValueError, AttributeError):
            continue
        items.append(f'<li><a href="/compare/{name}/">{html.escape(name.replace("_", " "))}</a> '
                     f'<span class="hint">{html.escape(what)}</span></li>')
    return f"<h2>Earlier comparisons</h2><ul>{''.join(items)}</ul>" if items else ""


def view(req, error: str = "", selected: set[str] | None = None, labels: dict[str, str] | None = None,
         crosscheck: bool = True, code: int = 200):
    """GET /compare: the list of saved reports to choose from."""
    app = req.app
    reports = _reports(app)
    body = PICK.format(error=error_html(error), hint=html.escape(HINT), csrf=app.csrf,
                       count=f"{len(reports):,}", table=_table(reports, selected or set(), labels or {}),
                       crosscheck=" checked" if crosscheck else "", recent=_recent(app))
    head = f"<style>{asset('forms.css')}{asset('compare.css')}</style>"
    scripts = (busy_overlay() + page_config({"csrf": app.csrf})
               + f"<script>{asset('busy.js')}</script><script>{asset('compare_pick.js')}</script>")
    req.send(code, page("Compare reports", body + scripts, head))


def run(req):
    """POST /compare: compare the ticked reports and open the result."""
    app = req.app
    length = req.length()
    if length <= 0 or length > MAX_UPLOAD:
        req.close_connection = True
        return view(req, f"The IOC CSV must be smaller than {MAX_UPLOAD // 1048576} MB.", code=413)
    root = _root(app)
    os.makedirs(root, exist_ok=True)
    cid = _new_id(root)
    out = os.path.join(root, cid)
    upload = os.path.join(out, "in")
    os.makedirs(upload)
    try:
        fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""), upload,
                                        lambda i, name: _keep_name(upload, i, name))
        if not app.csrf_ok(fields.get("csrf", "")):
            shutil.rmtree(out, ignore_errors=True)
            return req.send_text(403, "Forbidden")
        selected = {k[4:] for k, v in fields.items() if k.startswith("run_") and v == "1"}
        labels = {k[4:]: " ".join(v.split())[:runname.NETWORK_MAX] for k, v in fields.items() if k.startswith("net_")}
        crosscheck = fields.get("crosscheck") == "1"
        csvs = [path for name, path in parts if name == "ioc_csv"]
    except UserError as exc:                     # a broken upload
        shutil.rmtree(out, ignore_errors=True)
        req.close_connection = True
        return view(req, str(exc), code=400)
    try:
        reports = [r for r in _reports(app) if r.key in selected and not r.error]
        if not reports:
            raise UserError("Tick at least one report to compare.")
        for r in reports:
            r.network = labels.get(r.key) or r.network
        if (crosscheck or csvs) and resources.busy():
            raise UserError("An analysis is running on this machine. Wait for it to finish, or compare "
                            "without looking for IOCs again.")
        result = compare.compare(reports, csvs, crosscheck=crosscheck, workdir=out)
        compare.write(result, out)
        with open(os.path.join(out, "about.json"), "w", encoding="utf-8") as fh:
            json.dump({"generated": result["generated"], "summary": result["summary"],
                       "reports": [r["name"] for r in result["reports"]]}, fh)
    except UserError as exc:
        shutil.rmtree(out, ignore_errors=True)
        return view(req, str(exc), selected, labels, crosscheck, 400)
    except Exception:
        traceback.print_exc()
        shutil.rmtree(out, ignore_errors=True)
        return view(req, "The comparison failed; see the server console for details.", selected, labels, crosscheck, 500)
    req.redirect(f"/compare/{cid}/")


def _keep_name(folder: str, i: int, name: str) -> str:
    """Each uploaded CSV in its own numbered folder, under its own (made safe) name, so the
    comparison names the file the person chose."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name.replace("\\", "/")))[:120] or "iocs.csv"
    os.makedirs(os.path.join(folder, str(i)), exist_ok=True)
    return os.path.join(str(i), safe)


def _new_id(root: str) -> str:
    base = runname.stamp()
    for n in range(1, 1000):
        cid = base if n == 1 else f"{base}-{n}"
        try:
            os.makedirs(os.path.join(root, cid))
            return cid
        except FileExistsError:
            continue
    raise RuntimeError("Could not create a comparison folder")


def file(req, cid: str, name: str):
    """GET /compare/<id>/[file]: a saved comparison. Its page shows text taken from the reports
    (some may be reopened from folders this server doesn't control), so it runs in an opaque
    origin: it needs nothing from this server's API."""
    name = name or "comparison.html"
    if name not in FILES:
        return req.send_text(404, "Not found")
    path = os.path.join(_root(req.app), cid, name)
    if not os.path.isfile(path):
        return req.send_text(404, "Not found")
    req.send_file(path, {"Content-Security-Policy": SAVED_SANDBOX, "Cache-Control": "no-store"})
