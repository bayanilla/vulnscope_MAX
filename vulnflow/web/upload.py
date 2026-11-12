"""The upload page and the two ways to start an analysis from it: uploading files, or reading a
folder on this machine in place. Both end in ``_analyze``; a completed report's output folder is
reopened instead (see saved.py)."""
from __future__ import annotations

import dataclasses
import html
import os
import re
import shutil
import traceback

from .. import multipart, resources, runname, saved
from ..branding import icon_data_uri, product_name
from ..errors import UserError
from ..parsers import FORMATS
from ..pipeline import input_files, run
from ..report import CSS, THEME_INIT, theme_control
from . import folders
from .pages import asset, busy_overlay, error_html, page_config

ANALYZE_HINT = "Large folders can take several minutes. Keep this tab open; the report opens here when it's ready."

FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{product_name}</title><link rel="icon" href="{icon}">
{theme_init}<style>{css}{forms_css}</style></head><body>{theme_ui}
<h1>Analyze files with {product_name}</h1>
<p>Point the workflow at network telemetry, with optional Nessus results, or upload files. It cleans and
normalizes the data and produces an executive summary and a technical report. Without scan data,
vulnerability status remains unknown.</p>
{error}
<section id="report-details" aria-labelledby="rd-title"><h2 id="rd-title">Report details <span class="hint">(optional)</span></h2>
<label for="report_name">Report name</label>
<input id="report_name" type="text" name="report_name" value="{report_name}" maxlength="100" placeholder="e.g. Plant 3 network review, November" autocomplete="off">
<label for="report_network">Network</label>
<input id="report_network" type="text" name="report_network" value="{report_network}" maxlength="60" placeholder="e.g. Plant 3" autocomplete="off">
<div class="hint">The network or site the data comes from. When you <a href="/compare">compare reports</a>, reports with the same
network count as one network.</div>
<label for="report_description">Description</label>
<textarea id="report_description" name="report_description" maxlength="2000" rows="3" placeholder="Scope, case number, who asked for it&hellip;">{report_description}</textarea>
<div class="hint">Shown at the top of the reports and in the Explorer. Results are saved in a folder named after the report
plus the date and time (for example <code>Plant-3-network-review_2026-11-12_10-19-14</code>); without a name, the usual
folder name plus the date and time.</div></section>
<form method="post" action="/analyze-folder" data-busy="Analyzing…" data-busy-hint="{analyze_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="path">Folder on this computer</label>
<div class="pathrow"><input id="path" type="text" name="path" value="{path}" placeholder="{path_example}" autocomplete="off" spellcheck="false">
<button type="button" id="browse" class="secondary">Browse&hellip;</button></div>
<input type="file" id="pick-dir" webkitdirectory directory multiple hidden>
<div id="pick-msg" class="hint" role="status" aria-live="polite"></div>
<div id="picker" hidden><div class="pk-head"><button type="button" id="pk-up" class="secondary" title="Parent folder">&uarr; Up</button>
<code id="pk-where"></code></div><div id="pk-roots"></div><ul id="pk-list"></ul>
<div class="pk-foot"><span id="pk-info" class="hint"></span><button type="button" id="pk-cancel" class="secondary">Cancel</button>
<button type="button" id="pk-use">Use this folder</button></div></div>
<div class="hint">{folder_hint}The files are read where they are, including subfolders; nothing is copied or uploaded. Hidden files are skipped.</div>
<label for="nets2">Internal networks (optional)</label>
<input id="nets2" type="text" name="internal_nets" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16">
<div class="btnrow"><button type="submit" id="analyze-folder">Analyze folder</button></div>
<div class="hint">To see a completed report again, choose its output folder (the one with <code>results.json</code>
and <code>explorer.html</code>): the button changes to Open report, and nothing is reanalyzed.</div>
</form>
<h2>Or upload files</h2>
<form method="post" action="/analyze" enctype="multipart/form-data" data-busy="Analyzing…" data-busy-hint="{analyze_hint}">
<input type="hidden" name="csrf" value="{csrf}">
<label for="folder">Folder of telemetry and scans</label>
<input id="folder" type="file" name="folder" webkitdirectory directory multiple>
<div class="hint">Choose one folder to include its files and subfolders in a single analysis. A Nessus scan is optional.</div>
<label for="telemetry">Network telemetry</label>
<input id="telemetry" type="file" name="telemetry" multiple>
<div class="hint">Optional additional files: Zeek connection, DNS, SMTP and industrial protocol logs; Palo Alto traffic and threat logs; NetFlow / VPC flow / SIEM CSV; Zeek logs exported from Elastic/Filebeat (Kibana CSV or NDJSON); packet captures (.pcap/.pcapng, converted with Zeek).</div>
<label for="scans">Vulnerability scans</label>
<input id="scans" type="file" name="scans" multiple>
<div class="hint">Optional: Nessus .nessus (preferred) or Nessus CSV export. Without one, no vulnerability score or priority is assigned.</div>
<label for="ioc_archive">IOC CSV (optional)</label>
<input id="ioc_archive" type="file" name="ioc_archive" accept=".csv,text/csv">
<div class="hint">Use a CSV with type and indicator columns. Source links are optional.</div>
<label for="nets">Internal networks (optional)</label>
<input id="nets" type="text" name="internal_nets" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16">
<div class="hint">Anything outside these ranges is treated as the internet. Leave blank for private ranges.</div>
<button type="submit">Analyze</button>
</form>
<p class="hint">Formats are detected automatically: {formats}. Folder selection is supported by Chrome and other compatible browsers. Files stay on this machine.
<a href="/compare">Compare reports</a> · <a href="/settings">Security Assistant settings</a> · <a href="/branding">Branding</a></p>
{busy}{config}
<script>{busy_js}</script>
<script>{picker_js}</script>
<script>{upload_js}</script>
</body></html>"""

BUSY_MESSAGE = ("Another analysis is already running on this machine. "
                "Wait for it to finish and try again.")


def page(req, error: str = ""):
    """GET / and every refusal of the two analysis forms (the form keeps what was typed)."""
    app = req.app
    container = bool(folders.CONTAINER_DATA)
    req.send(200, FORM.format(
        css=CSS, forms_css=asset("forms.css"), theme_init=THEME_INIT, theme_ui=theme_control(),
        product_name=html.escape(product_name()), icon=icon_data_uri(), error=error_html(error),
        formats=", ".join(FORMATS) + ", pcap/pcapng (converted with Zeek)", csrf=app.csrf,
        analyze_hint=html.escape(ANALYZE_HINT),
        path=html.escape(app.last_path),
        report_name=html.escape(app.last_report.get("name", "")),
        report_network=html.escape(app.last_report.get("network", "")),
        report_description=html.escape(app.last_report.get("description", "")),
        path_example=html.escape(folders.path_example()),
        folder_hint=("Click Browse&hellip;, choose the folder and confirm; its path fills in here. "
                     "Your browser may ask twice to upload (the folder window's Upload button, "
                     "then &ldquo;Upload files to this site?&rdquo;): click Upload both times. "
                     "Nothing is sent; VulnScope only uses it to find the folder. ") if container else "",
        busy=busy_overlay(),
        config=page_config({"csrf": app.csrf, "native": folders.NATIVE_PICKER, "dialog": bool(folders.BROWSE_ROOTS)}),
        busy_js=asset("busy.js"), picker_js=asset("folder_picker.js"), upload_js=asset("upload.js")))


def _report_details(fields: dict) -> dict:
    return runname.clean(fields.get("report_name"), fields.get("report_description"), fields.get("report_network"))


def _config(req, nets: str):
    """The server's analysis settings, with the internal networks typed on the form (if any)."""
    base = req.app.base_cfg
    cfg = dataclasses.replace(base, internal_nets=list(base.internal_nets))
    nets = nets.strip()
    if nets:
        cfg.internal_nets = [n.strip() for n in re.split(r"[,\s]+", nets) if n.strip()]
    return cfg


def _analyze(req, run_id: str, files: list[str], nets: str, report: dict):
    """Analyze ``files`` into run ``run_id`` and open its page; on a problem the person can fix,
    show it on the upload page and drop the run folder."""
    root = req.app.run_root(run_id)
    try:
        run(files, os.path.join(root, "out"), _config(req, nets), workdir=root, report=report)
    except UserError as exc:
        shutil.rmtree(root, ignore_errors=True)
        return page(req, str(exc))
    except Exception:
        traceback.print_exc()          # the run folder is kept for a look at what went wrong
        return page(req, "The analysis failed; see the server console for details.")
    req.app.last_report = {}           # a new analysis starts with empty report details
    req.redirect(f"/runs/{run_id}/")


def analyze_upload(req):
    """POST /analyze: files uploaded from the browser, streamed to disk, then analyzed."""
    app = req.app
    if resources.busy():                          # refuse before reading a large upload
        req.close_connection = True
        return page(req, BUSY_MESSAGE)
    length = req.length()
    if length <= 0 or length > app.max_upload:
        req.close_connection = True               # don't read an oversized body at all
        return page(req, f"Upload must be between 1 byte and {app.max_upload // 1048576} MB.")
    # The name arrives inside the upload, after the files, so the run starts in a temporary
    # folder and is renamed "<name>_<timestamp>" once the form has been read.
    tmp_id = runname.new_run(app.data_dir, "upload")
    tmp_root = app.run_root(tmp_id)
    in_dir = os.path.join(tmp_root, "in")
    os.makedirs(in_dir)

    def safe_name(i, fname):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(fname.replace("\\", "/")))[:120] or "upload"
        return f"{i:02d}_{safe}"
    try:
        fields, parts = multipart.parse(req.rfile, length, req.headers.get("Content-Type", ""), in_dir, safe_name)
    except multipart.MultipartError as exc:
        shutil.rmtree(tmp_root, ignore_errors=True)
        req.close_connection = True
        return page(req, str(exc))
    if not app.csrf_ok(fields.get("csrf", "")):
        shutil.rmtree(tmp_root, ignore_errors=True)
        return req.send_text(403, "Forbidden")
    report = app.last_report = _report_details(fields)
    if not parts:
        shutil.rmtree(tmp_root, ignore_errors=True)
        return page(req, "Please choose at least one telemetry file and one scan file.")
    run_id = runname.new_run(app.data_dir, report["name"])
    os.rmdir(app.run_root(run_id))
    os.rename(tmp_root, app.run_root(run_id))
    files = [os.path.join(app.run_root(run_id), os.path.relpath(path, tmp_root)) for _, path in parts]
    return _analyze(req, run_id, files, fields.get("internal_nets", ""), report)


def analyze_folder(req):
    """POST /analyze-folder: a folder on the machine running the server, read in place; a
    completed report's output folder is reopened instead of analyzed."""
    app = req.app
    form = req.read_form()
    if form is None:
        return req.send_text(400, "Bad request")
    if not app.csrf_ok(form.get("csrf", "")):
        return req.send_text(403, "Forbidden")
    raw = form.get("path", "").strip().strip('"').strip("'")
    folder = folders.resolve(raw)
    app.last_path = raw
    app.last_report = report = _report_details(form)
    if not raw:
        return page(req, "Choose a folder first: click Browse… and pick one, or type its full path.")
    if not os.path.isdir(folder):
        return page(req, f"Folder not found: {raw}. Use the full path, for example {folders.path_example()}.")
    if saved.is_report_folder(folder):
        return _open_report(req, folder)
    if resources.busy():
        return page(req, BUSY_MESSAGE)
    data_dir = os.path.realpath(app.data_dir) + os.sep
    files = [f for f in input_files([folder], app.data_dir) if not os.path.realpath(f).startswith(data_dir)]
    if not files:
        return page(req, f"No files found in {folder}.")
    run_id = runname.new_run(app.data_dir, report["name"])
    os.makedirs(os.path.join(app.run_root(run_id), "in"))
    with open(os.path.join(app.run_root(run_id), "in", "SOURCE.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Read in place from {folder}\n" + "\n".join(files) + "\n")
    return _analyze(req, run_id, files, form.get("internal_nets", ""), report)


def _open_report(req, folder: str):
    """Rebuild a completed report's pages from its output folder, without reanalyzing."""
    app, root = req.app, None
    try:
        res, data = saved.load_folder(folder)
        run_id = runname.new_run(app.data_dir, (res.get("report") or {}).get("name", ""))
        root = app.run_root(run_id)
        saved.write(res, data, os.path.join(root, "out"), folder, app.last_path)
    except saved.SavedRunError as exc:
        if root:
            shutil.rmtree(root, ignore_errors=True)
        return page(req, str(exc))
    except Exception:
        traceback.print_exc()
        if root:
            shutil.rmtree(root, ignore_errors=True)
        return page(req, "The saved report could not be opened; see the server console for details.")
    req.redirect(f"/runs/{run_id}/")


def folder_kind(req):
    """POST /folder-kind: whether a folder is a completed report's output folder (the page
    relabels its button)."""
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden"})
    folder = folders.resolve(str(body.get("path") or ""))
    return req.send_json(200, {"report": bool(folder) and os.path.isdir(folder) and saved.is_report_folder(folder)})
