"""Local upload page (standard library only).

GET  /            upload form
POST /analyze     run the workflow on the uploaded files
GET  /runs/<id>/  links to a run's reports; files under it are served read-only
POST /runs/<id>/brief  generate the Security Assistant brief (when an LLM is configured)
POST /runs/<id>/article-briefs  generate Múcaro article briefs from matched sources
POST /runs/<id>/ask    JSON {question, history} -> {answer, answer_html}
GET/POST /settings     choose the AI provider and enter its API key (kept in memory only)
"""
from __future__ import annotations

import html
import os
import re
import secrets
import shutil
import subprocess
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import json

from . import multipart
from .branding import PRODUCT_NAME, icon_data_uri
from .correlate import Config
from dataclasses import replace
from urllib.parse import parse_qs

from .llm import PROVIDER_NAMES, Analyst, LLMConfig, LLMError, load_results, log_qa, write_brief
from .article_brief import generate_article_briefs
from .parsers import FORMATS
from .pipeline import run
from .report import CSS, THEME_INIT, md_body, save_article_briefs, theme_control
from .cli import _input_files

MAX_UPLOAD = 1024 * 1024 * 1024   # default cap; uploads stream to disk, so this is about disk and run time
TYPES = {".html": "text/html; charset=utf-8", ".md": "text/markdown; charset=utf-8",
         ".csv": "text/csv; charset=utf-8", ".json": "application/json",
         ".jsonl": "application/x-ndjson; charset=utf-8"}

FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{product_name}</title><link rel="icon" href="{icon}">
{theme_init}<style>{css} form{{border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin:16px 0}}
label{{display:block;font-weight:600;margin:14px 0 4px}} .hint{{color:var(--muted);font-size:.9rem}}
button{{margin-top:18px;padding:8px 18px;font-size:1rem}}
input[type=text]{{width:100%;max-width:520px;padding:6px}}
.pathrow{{display:flex;gap:8px;max-width:640px;align-items:center}} .pathrow input{{flex:1}} .pathrow button{{margin-top:0;white-space:nowrap}}
button.secondary{{background:transparent;color:var(--fg);border:1px solid var(--line)}}
#picker{{max-width:640px;margin-top:8px;border:1px solid var(--line);border-radius:var(--radius);padding:10px}}
.pk-head,.pk-foot{{display:flex;gap:8px;align-items:center}} .pk-head button,.pk-foot button{{margin-top:0;padding:4px 12px;font-size:.9rem;white-space:nowrap}}
.pk-foot{{margin-top:8px}} .pk-foot span{{flex:1}} #pk-where{{overflow-wrap:anywhere}}
#pk-list{{list-style:none;margin:8px 0 0;padding:0;max-height:280px;overflow:auto;border-top:1px solid var(--line)}}
#pk-list li{{padding:5px 8px;cursor:pointer;border-bottom:1px solid var(--line)}} #pk-list li:hover,#pk-list li:focus{{background:rgba(127,127,127,.15)}}
#pk-list li::before{{content:"📁  "}}</style></head><body>{theme_ui}
<h1>Analyze files with {product_name}</h1>
<p>Point the workflow at a folder of network telemetry and Nessus results, or upload files. It cleans and
normalizes the data, correlates scanned hosts with observed traffic, and produces an executive summary and a
technical report.</p>
{error}
<form method="post" action="/analyze-folder">
<input type="hidden" name="csrf" value="{csrf}">
<label for="path">Folder on this computer</label>
<div class="pathrow"><input id="path" type="text" name="path" value="{path}" placeholder="~/Documents/case-logs" autocomplete="off" spellcheck="false">
<button type="button" id="browse" class="secondary">Browse&hellip;</button></div>
<div id="picker" hidden><div class="pk-head"><button type="button" id="pk-up" class="secondary" title="Parent folder">&uarr; Up</button>
<code id="pk-where"></code></div><ul id="pk-list"></ul>
<div class="pk-foot"><span id="pk-info" class="hint"></span><button type="button" id="pk-cancel" class="secondary">Cancel</button>
<button type="button" id="pk-use">Use this folder</button></div></div>
<div class="hint">The files are read where they are, including subfolders; nothing is copied or uploaded. Hidden files are skipped.</div>
<label for="nets2">Internal networks (optional)</label>
<input id="nets2" type="text" name="internal_nets" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16">
<button type="submit">Analyze folder</button>
</form>
<h2>Or upload files</h2>
<form method="post" action="/analyze" enctype="multipart/form-data">
<label for="folder">Folder of telemetry and scans</label>
<input id="folder" type="file" name="folder" webkitdirectory directory multiple>
<div class="hint">Choose one folder to include its files and subfolders in a single analysis. Add a Nessus scan here or below.</div>
<label for="telemetry">Network telemetry</label>
<input id="telemetry" type="file" name="telemetry" multiple>
<div class="hint">Optional additional files: Zeek connection, DNS, SMTP and industrial protocol logs; Palo Alto traffic and threat logs; NetFlow / VPC flow / SIEM CSV.</div>
<label for="scans">Vulnerability scans</label>
<input id="scans" type="file" name="scans" multiple>
<div class="hint">Nessus .nessus (preferred) or Nessus CSV export.</div>
<label for="ioc_archive">Múcaro IOC Archive (optional)</label>
<input id="ioc_archive" type="file" name="ioc_archive" accept=".csv,text/csv">
<div class="hint">Export a 60-day IOC Archive CSV from Múcaro to link exact matches to their source articles.</div>
<label for="nets">Internal networks (optional)</label>
<input id="nets" type="text" name="internal_nets" placeholder="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16">
<div class="hint">Anything outside these ranges is treated as the internet. Leave blank for private ranges.</div>
<button type="submit">Analyze</button>
</form>
<p class="hint">Formats are detected automatically: {formats}. Folder selection is supported by Chrome and other compatible browsers. Files stay on this machine.
<a href="/settings">Security Assistant settings</a></p>
<script>
(function () {{
  const csrf = {csrf_js}, native = {native_js};
  const $ = id => document.getElementById(id), box = $("picker"), list = $("pk-list");
  let cur = null, parent = null;
  async function call(url, body) {{
    const r = await fetch(url, {{method: "POST", headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify(Object.assign({{csrf}}, body))}});
    return r.json();
  }}
  async function show(path) {{
    const d = await call("/browse", {{path}});
    if (d.error) {{ $("pk-info").textContent = d.error; return; }}
    cur = d.path; parent = d.parent; $("pk-where").textContent = d.path; $("pk-up").disabled = !d.parent;
    list.innerHTML = "";
    d.dirs.forEach(name => {{
      const li = document.createElement("li"); li.textContent = name; li.tabIndex = 0;
      const go = () => show((d.path.endsWith(d.sep) ? d.path : d.path + d.sep) + name);
      li.onclick = go; li.onkeydown = e => {{ if (e.key === "Enter") {{ e.preventDefault(); go(); }} }};
      list.appendChild(li);
    }});
    $("pk-info").textContent = d.files + " file" + (d.files === 1 ? "" : "s") + " here" +
      (d.dirs.length ? ", " + d.dirs.length + " subfolder" + (d.dirs.length === 1 ? "" : "s") : "");
    box.hidden = false;
  }}
  $("browse").onclick = async () => {{
    if (native) {{
      $("browse").disabled = true;
      try {{
        const d = await call("/pick-folder", {{path: $("path").value}});
        if (d.path) {{ $("path").value = d.path; box.hidden = true; return; }}
        if (d.cancelled) return;
      }} catch (e) {{}} finally {{ $("browse").disabled = false; }}
    }}
    show($("path").value);
  }};
  $("pk-up").onclick = () => parent && show(parent);
  $("pk-use").onclick = () => {{ $("path").value = cur; box.hidden = true; $("path").focus(); }};
  $("pk-cancel").onclick = () => {{ box.hidden = true; }};
}})();
</script>
</body></html>"""


def _page(title, body):
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)} · {PRODUCT_NAME}</title><link rel=\"icon\" href=\"{icon_data_uri()}\">{THEME_INIT}<style>{CSS}</style></head>"
            f"<body>{theme_control()}{body}</body></html>")


CHAT = """<section class="analyst-chat" data-ai-chat data-ask-url="ask"><h2>Security Assistant</h2>
<p class="hint">{where}</p>
{brief}
<div class="ai-chat-log" role="log" aria-label="Security Assistant conversation" aria-live="polite" aria-relevant="additions" tabindex="0"></div>
<form class="ai-chat-form"><label for="q">Ask about these results</label>
<textarea id="q" rows="3" maxlength="4000" placeholder="e.g. Why is fs01 a P1? How do I confirm the callback from web01 in Zeek?"></textarea>
<button type="submit" class="ai-chat-submit">Ask</button> <span class="ai-chat-busy hint" role="status"></span></form></section>"""


def _chat_asset(name: str) -> str:
    with open(os.path.join(os.path.dirname(__file__), "static", name), encoding="utf-8") as fh:
        return fh.read()


def _where(cfg: LLMConfig) -> str:
    return (html.escape(_where_text(cfg)) +
            ' <a href="/settings?next={next}">Change</a>. Answers are AI-generated; verify before acting.')


def _where_text(cfg: LLMConfig) -> str:
    dest = ("nothing leaves this machine" if cfg.provider == "mock" else
            f"correlated results (not raw logs) are sent to {cfg.destination()}")
    red = "; IPs and hostnames are replaced with tokens first" if cfg.redact else ""
    return f"Model: {cfg.label()}: {dest + red}."


SETTINGS = """<style>{css}</style><h1>Security Assistant settings</h1>
<p>Pick any provider. Nothing is sent to a model until you save a choice here. The API key is held in this
server's memory only: it is not written to disk, shown again, or logged, and it is forgotten when the server stops.</p>
{status}{error}
<form method="post" action="/settings">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="next" value="{next}">
<label for="provider">Provider</label>
<select id="provider" name="provider">{options}</select>
<label for="model">Model</label>
<input id="model" name="model" type="text" value="{model}" placeholder="e.g. claude-opus-5-5, an OpenAI model name, llama3.1">
<div class="hint">Required for OpenAI. Anthropic and self-hosted fall back to claude-opus-5-5 and llama3.1.</div>
<label for="base_url">Endpoint URL</label>
<input id="base_url" name="base_url" type="text" value="{base_url}" placeholder="OpenAI: https://api.openai.com/v1 · Ollama: http://localhost:11434/v1">
<div class="hint">OpenAI and self-hosted only. Leave blank for the default.</div>
<label for="api_key">API key</label>
<input id="api_key" name="api_key" type="password" autocomplete="off" placeholder="{key_hint}">
<div class="hint">Anthropic and OpenAI need one; self-hosted usually does not. Leave blank to keep the current key.</div>
<label><input type="checkbox" name="redact" value="1"{redact}> Replace IPs and hostnames with tokens before sending</label>
<button type="submit" name="action" value="save">Save</button>
<button type="submit" name="action" value="clear" class="secondary">Turn off AI and forget key</button>
</form><p><a href="{next}">Back</a></p>"""
SETTINGS_CSS = """form label{display:block;font-weight:600;margin:14px 0 4px} .hint{color:var(--muted);font-size:.9rem}
form input[type=text],form input[type=password],form select{width:100%;max-width:520px;padding:6px;font:inherit;box-sizing:border-box}
button{margin-top:18px;padding:8px 16px;cursor:pointer}
button.secondary{background:transparent;color:var(--fg);border:1px solid var(--line)}"""


NATIVE_PICKER = sys.platform == "darwin" and shutil.which("osascript") is not None


def list_folder(raw: str) -> dict:
    """Subfolders of `raw` (default: home), skipping hidden ones; falls back to the nearest existing parent."""
    path = os.path.realpath(os.path.expanduser(raw.strip().strip('"').strip("'") or "~"))
    while not os.path.isdir(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        return {"error": f"Cannot open {path}: {exc.strerror or exc}"}
    dirs, files = [], 0
    for e in entries:
        if e.name.startswith("."):
            continue
        try:
            if e.is_dir():
                dirs.append(e.name)
            elif e.is_file():
                files += 1
        except OSError:
            continue
    parent = os.path.dirname(path)
    return {"path": path, "parent": parent if parent != path else None, "sep": os.sep,
            "dirs": sorted(dirs, key=str.lower), "files": files}


def native_pick(start: str) -> dict:
    """Show the macOS Choose Folder dialog in front of the browser and return the chosen path."""
    start = os.path.realpath(os.path.expanduser(start.strip() or "~"))
    script = ['tell application (path to frontmost application as text)',
              'activate',
              'POSIX path of (choose folder with prompt "Choose a folder of telemetry and Nessus scans"'
              + (' default location (POSIX file %s)' % json.dumps(start) if os.path.isdir(start) else "") + ")",
              'end tell']
    try:
        out = subprocess.run(["osascript"] + sum((["-e", line] for line in script), []),
                             capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return {"error": "The folder dialog could not be opened."}
    if out.returncode != 0:
        return {"cancelled": True} if "-128" in out.stderr else {"error": "The folder dialog could not be opened."}
    return {"path": out.stdout.strip().rstrip("/") or "/"}


def make_handler(data_dir: str, base_cfg: Config, llm_cfg: LLMConfig | None = None,
                 max_upload: int = MAX_UPLOAD):
    """llm_cfg None hides the Security Assistant entirely; an unready LLMConfig shows it unconfigured."""
    state = {"llm": llm_cfg}
    csrf = secrets.token_urlsafe(24)   # guards form posts from other sites in the same browser

    class Handler(BaseHTTPRequestHandler):
        def _llm(self) -> LLMConfig | None:
            return replace(state["llm"]) if state["llm"] is not None else None

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin == f"http://{self.headers.get('Host', '')}"

        def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _form(self, error=""):
            err = f'<p style="color:#c0392b"><strong>{html.escape(error)}</strong></p>' if error else ""
            self._send(200, FORM.format(css=CSS, theme_init=THEME_INIT, theme_ui=theme_control(),
                                        product_name=PRODUCT_NAME, icon=icon_data_uri(),
                                        error=err, formats=", ".join(FORMATS), csrf=csrf,
                                        csrf_js=json.dumps(csrf), native_js="true" if NATIVE_PICKER else "false",
                                        path=html.escape(state.get("last_path", ""))))

        def _analyze_folder(self):
            """Analyze a folder on the machine running the server, reading the files in place."""
            length = int(self.headers.get("Content-Length") or 0)
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(min(length, 20000)).decode(errors="replace")).items()}
            if form.get("csrf") != csrf:
                return self._send(403, "Forbidden", "text/plain")
            raw = form.get("path", "").strip().strip('"').strip("'")
            folder = os.path.realpath(os.path.expanduser(raw)) if raw else ""
            state["last_path"] = raw
            if not folder or not os.path.isdir(folder):
                return self._form(f"Folder not found: {raw or '(empty)'}. Use the full path, for example ~/Documents/case-logs.")
            run_id = secrets.token_hex(8)
            out_dir = os.path.join(data_dir, run_id, "out")
            files = _input_files([folder], out_dir)
            files = [f for f in files if not os.path.realpath(f).startswith(os.path.realpath(data_dir) + os.sep)]
            if not files:
                return self._form(f"No files found in {folder}.")
            cfg = Config(internal_nets=base_cfg.internal_nets, hops=base_cfg.hops,
                         min_severity=base_cfg.min_severity)
            nets = form.get("internal_nets", "").strip()
            if nets:
                cfg.internal_nets = [n.strip() for n in re.split(r"[,\s]+", nets) if n.strip()]
            os.makedirs(os.path.join(data_dir, run_id, "in"))
            with open(os.path.join(data_dir, run_id, "in", "SOURCE.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"Read in place from {folder}\n" + "\n".join(files) + "\n")
            try:
                run(files, out_dir, cfg)
            except ValueError as exc:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._form(str(exc))
            except Exception:
                traceback.print_exc()
                return self._form("The analysis failed; see the server console for details.")
            self._send(303, "", headers={"Location": f"/runs/{run_id}/"})

        def _read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(min(length, 20000)) or b"{}")
            except ValueError:
                return None
            return body if isinstance(body, dict) and body.get("csrf") == csrf else None

        def _browse(self):
            """List the subfolders of a folder on this machine, for the folder picker."""
            body = self._read_json()
            if body is None:
                return self._json(403, {"error": "Forbidden"})
            return self._json(200, list_folder(str(body.get("path") or "")))

        def _pick_folder(self):
            """Open the operating system's own folder dialog (macOS) on the machine running the server."""
            body = self._read_json()
            if body is None:
                return self._json(403, {"error": "Forbidden"})
            if not NATIVE_PICKER:
                return self._json(200, {"unsupported": True})
            return self._json(200, native_pick(str(body.get("path") or "")))

        def do_GET(self):
            path = unquote(self.path.split("?", 1)[0])
            if path in ("/", "/index.html"):
                return self._form()
            if path == "/settings":
                nxt = parse_qs(self.path.split("?", 1)[1]).get("next", ["/"])[0] if "?" in self.path else "/"
                return self._settings(nxt)
            m = re.fullmatch(r"/runs/([a-f0-9]{16})/(.*)", path)
            if not m:
                return self._send(404, "Not found", "text/plain")
            run_dir = os.path.realpath(os.path.join(data_dir, m[1], "out"))
            if m[2] == "ai-status":
                if not os.path.isdir(run_dir):
                    return self._send(404, "Not found", "text/plain")
                cfg = self._llm()
                return self._send(200, json.dumps({
                    "enabled": cfg is not None, "ready": bool(cfg and cfg.ready),
                    "description": _where_text(cfg) if cfg and cfg.ready else "No AI provider selected yet.",
                }), "application/json", {"Cache-Control": "no-store"})
            if not m[2]:
                return self._run_index(m[1], run_dir)
            target = os.path.realpath(os.path.join(run_dir, m[2]))
            if not target.startswith(run_dir + os.sep) or not os.path.isfile(target):
                return self._send(404, "Not found", "text/plain")
            with open(target, "rb") as fh:
                self._send(200, fh.read(), TYPES.get(os.path.splitext(target)[1], "application/octet-stream"))

        def _run_index(self, run_id, run_dir):
            if not os.path.isdir(run_dir):
                return self._send(404, "Not found", "text/plain")
            links = [("Executive summary", "executive_summary.html"),
                     ("Technical report", "technical_report.html"),
                     ("Correlated findings (CSV)", "correlated_findings.csv"),
                     ("Full results (JSON)", "results.json"),
                     ("Normalized flows (CSV)", "normalized/flows.csv"),
                     ("Normalized findings (CSV)", "normalized/findings.csv"),
                     ("Zeek stream events (JSONL)", "normalized/zeek_events.jsonl"),
                     ("Industrial protocol events (JSONL)", "normalized/ot_events.jsonl"),
                     ("Executive summary (Markdown)", "executive_summary.md"),
                     ("Technical report (Markdown)", "technical_report.md")]
            if os.path.exists(os.path.join(run_dir, "ai_analyst_brief.html")):
                links.insert(2, ("Security Assistant brief", "ai_analyst_brief.html"))
            if os.path.exists(os.path.join(run_dir, "ai_chat_log.md")):
                links.append(("AI Q&A log (Markdown)", "ai_chat_log.md"))
            items = "".join(f'<li><a href="/runs/{run_id}/{p}" target="_blank" rel="noopener">{t}</a></li>' for t, p in links)
            if os.path.exists(os.path.join(run_dir, "explorer.html")):
                items = (f'<p class="explore"><a href="/runs/{run_id}/explorer.html" target="_blank" rel="noopener"><b>Open the host explorer</b></a>'
                         " Click a host to see who is targeting it and how far a compromise could reach.</p>"
                         f"<ul>{items}</ul>")
            else:
                items = f"<ul>{items}</ul>"
            here = f"/runs/{run_id}/"
            cfg, ai = self._llm(), ""
            if cfg is not None and not cfg.ready:
                ai = ("<h2>Security Assistant</h2><p>No AI provider selected yet. Use Anthropic, OpenAI or a model you host "
                      f'to interpret these results and answer questions.</p><p><a href="/settings?next={here}">'
                      "Choose a provider and enter an API key</a></p>")
            elif cfg is not None:
                brief = ("" if os.path.exists(os.path.join(run_dir, "ai_analyst_brief.html")) else
                         f'<form method="post" action="brief"><input type="hidden" name="csrf" value="{csrf}">'
                         '<button type="submit">Generate Security Assistant brief</button>'
                         ' <span class="hint">Takes a minute or two.</span></form>')
                ai = CHAT.format(where=_where(cfg).replace("{next}", here), brief=brief)
            article_ui = ""
            try:
                result = load_results(run_dir)
                article_urls = {url for match in result.get("ioc_matches", []) for url in match.get("articles", [])}
                saved_urls = set(result.get("article_briefs", {}))
                if article_urls:
                    remaining = len(article_urls - saved_urls)
                    article_ui = (f"<h2>Múcaro article briefs</h2><p>{len(saved_urls & article_urls)} saved; "
                                  f"{remaining} matched article(s) without a saved brief.</p>")
                    if remaining and cfg is not None and cfg.provider == "openai" and cfg.redact:
                        article_ui += (f'<p><a href="/settings?next={here}">Turn off IP/hostname redaction</a>'
                                       ' to include exact source indicators in article briefs.</p>')
                    elif remaining and cfg is not None and cfg.provider == "openai" and cfg.api_key:
                        article_ui += (f'<form method="post" action="article-briefs">'
                                       f'<input type="hidden" name="csrf" value="{csrf}">'
                                       '<button type="submit">Generate article briefs with OpenAI</button>'
                                       ' <span class="hint">Sends matched article text to OpenAI using your configured key.</span></form>')
                    elif remaining and cfg is not None:
                        article_ui += (f'<p><a href="/settings?next={here}">Choose OpenAI and enter an API key</a>'
                                       ' to generate these article briefs.</p>')
            except (OSError, ValueError):
                pass
            chat_style = f"<style>{_chat_asset('analyst_chat.css')}</style>" if ai and cfg and cfg.ready else ""
            chat_script = f"<script>{_chat_asset('analyst_chat.js')}</script>" if chat_style else ""
            body = (f"{chat_style}<h1>Results</h1>{items}{article_ui}{ai}"
                    f"<p><a href=\"/\">New analysis</a></p>{chat_script}")
            self._send(200, _page("Results", body))

        def _json(self, code, obj):
            self._send(code, json.dumps(obj), "application/json")

        def _ai(self, run_id, action):
            run_dir = os.path.join(data_dir, run_id, "out")
            if not os.path.isdir(run_dir):
                return self._send(404, "Not found", "text/plain")
            cfg = self._llm()
            if cfg is None or not cfg.ready:
                return self._json(400, {"error": "No AI provider selected. Open AI settings to choose one."})
            try:
                res = load_results(run_dir)
                if action in ("brief", "article-briefs"):
                    length = int(self.headers.get("Content-Length") or 0)
                    form = parse_qs(self.rfile.read(min(length, 10000)).decode(errors="replace"))
                    if form.get("csrf", [""])[0] != csrf:
                        return self._send(403, "Forbidden", "text/plain")
                    if action == "article-briefs":
                        summary = generate_article_briefs(res, cfg)
                        if summary["generated"]:
                            save_article_briefs(res, run_dir)
                        notes = (f'<h1>Article briefs</h1><p>Generated {summary["generated"]} brief(s); '
                                 f'{summary["saved"]} saved with this report; '
                                 f'{summary["unavailable"]} article(s) could not be read.</p>')
                        if summary["errors"]:
                            notes += ("<p>Some briefs could not be generated:</p><ul>" +
                                      "".join(f"<li>{html.escape(error)}</li>" for error in summary["errors"]) + "</ul>")
                        notes += f'<p><a href="/runs/{run_id}/">Open updated reports and Explorer</a></p>'
                        return self._send(200, _page("Article briefs", notes))
                    write_brief(res, run_dir, cfg)
                    return self._send(303, "", headers={"Location": f"/runs/{run_id}/ai_analyst_brief.html"})
                if "application/json" not in self.headers.get("Content-Type", ""):
                    return self._json(415, {"error": "Send JSON."})
                length = int(self.headers.get("Content-Length") or 0)
                if not 0 < length <= 1_000_000:
                    return self._json(413, {"error": "Request too large."})
                req = json.loads(self.rfile.read(length))
                question = str(req.get("question", ""))
                history = req.get("history") if isinstance(req.get("history"), list) else []
                answer = Analyst(res, cfg).ask(question, history)
                log_qa(run_dir, cfg, question, answer)
                return self._json(200, {"answer": answer, "answer_html": md_body(answer)})
            except LLMError as exc:
                if action in ("brief", "article-briefs"):
                    return self._send(502, _page("AI brief failed", f"<h1>AI brief failed</h1><p>{html.escape(str(exc))}</p>"
                                                 f"<p><a href=\"/runs/{run_id}/\">Back</a></p>"))
                return self._json(502, {"error": str(exc)})
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                if action == "article-briefs":
                    return self._send(500, _page("Article briefs failed",
                        f"<h1>Article briefs failed</h1><p>{html.escape(str(exc))}</p>"
                        f'<p><a href="/runs/{run_id}/">Back</a></p>'))
                return self._json(400, {"error": "Malformed request."})

        def _settings(self, nxt, error="", code=200):
            if state["llm"] is None:
                return self._send(404, "The Security Assistant is turned off on this server.", "text/plain")
            if not re.fullmatch(r"/(runs/[a-f0-9]{16}/)?", nxt):
                nxt = "/"
            cfg = state["llm"]
            options = "".join(f'<option value="{p}"{" selected" if p == cfg.provider else ""}>{n}</option>'
                              for p, n in PROVIDER_NAMES.items() if p != "mock" or cfg.provider == "mock")
            if not cfg.provider:
                options = '<option value="" selected>Choose a provider</option>' + options
            status = (f'<p><strong>Current:</strong> {html.escape(cfg.label())}, API key {cfg.masked_key()}.</p>'
                      if cfg.ready else "<p><strong>Current:</strong> none selected.</p>")
            err = f'<p style="color:#c0392b"><strong>{html.escape(error)}</strong></p>' if error else ""
            body = SETTINGS.format(
                css=SETTINGS_CSS, status=status, error=err, csrf=csrf, next=html.escape(nxt), options=options,
                model=html.escape(cfg.model), base_url=html.escape(cfg.base_url),
                key_hint="key is set; leave blank to keep it" if cfg.api_key else "paste key",
                redact=" checked" if cfg.redact else "")
            self._send(code, _page("Security Assistant settings", body))

        def _save_settings(self):
            length = int(self.headers.get("Content-Length") or 0)
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(min(length, 20000)).decode(errors="replace")).items()}
            if form.get("csrf") != csrf:
                return self._send(403, "Forbidden", "text/plain")
            nxt = form.get("next", "/")
            if state["llm"] is None:
                return self._send(404, "Not found", "text/plain")
            if form.get("action") == "clear":
                state["llm"] = LLMConfig()
                return self._send(303, "", headers={"Location": nxt if re.fullmatch(r"/(runs/[a-f0-9]{16}/)?", nxt) else "/"})
            cur = state["llm"]
            provider = form.get("provider", "")
            new = LLMConfig(provider=provider, model=form.get("model", "").strip(),
                            base_url=form.get("base_url", "").strip(),
                            # keep the stored key when the field is left blank and the provider is unchanged
                            api_key=form.get("api_key", "").strip() or (cur.api_key if provider == cur.provider else ""),
                            redact=form.get("redact") == "1")
            if provider in ("anthropic", "local", "mock"):
                if new.model == "" and provider == cur.provider:
                    new.model = cur.model
            try:
                if not provider:
                    raise LLMError("Choose a provider.")
                new.resolved()
                if new.needs_key():
                    raise LLMError(f"{PROVIDER_NAMES[provider]} needs an API key.")
            except LLMError as exc:
                return self._settings(nxt, str(exc), 400)
            state["llm"] = new
            self._send(303, "", headers={"Location": nxt if re.fullmatch(r"/(runs/[a-f0-9]{16}/)?", nxt) else "/"})

        def do_POST(self):
            if not self._same_origin():
                return self._send(403, "Cross-origin request refused", "text/plain")
            if self.path == "/settings":
                return self._save_settings()
            m = re.fullmatch(r"/runs/([a-f0-9]{16})/(brief|article-briefs|ask)", self.path)
            if m:
                return self._ai(m[1], m[2])
            if self.path == "/analyze-folder":
                return self._analyze_folder()
            if self.path == "/browse":
                return self._browse()
            if self.path == "/pick-folder":
                return self._pick_folder()
            if self.path != "/analyze":
                return self._send(404, "Not found", "text/plain")
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > max_upload:
                self.close_connection = True              # don't read an oversized body at all
                return self._form(f"Upload must be between 1 byte and {max_upload // 1048576} MB.")
            run_id = secrets.token_hex(8)
            in_dir = os.path.join(data_dir, run_id, "in")
            os.makedirs(in_dir)

            def safe_name(i, fname):
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(fname.replace("\\", "/")))[:120] or "upload"
                return f"{i:02d}_{safe}"
            try:
                fields, parts = multipart.parse(self.rfile, length, self.headers.get("Content-Type", ""),
                                                in_dir, safe_name)
            except multipart.MultipartError as exc:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                self.close_connection = True
                return self._form(str(exc))
            files = [path for _, path in parts]
            nets = fields.get("internal_nets", "").strip()
            if not files:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._form("Please choose at least one telemetry file and one scan file.")
            cfg = Config(internal_nets=base_cfg.internal_nets, hops=base_cfg.hops,
                         min_severity=base_cfg.min_severity)
            if nets:
                cfg.internal_nets = [n.strip() for n in re.split(r"[,\s]+", nets) if n.strip()]
            try:
                run(files, os.path.join(data_dir, run_id, "out"), cfg)
            except ValueError as exc:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._form(str(exc))
            except Exception:
                traceback.print_exc()
                return self._form("The analysis failed; see the server console for details.")
            self._send(303, "", headers={"Location": f"/runs/{run_id}/"})

    return Handler


def serve(host: str, port: int, data_dir: str, cfg: Config, llm_cfg: LLMConfig | None = None,
          max_upload: int = MAX_UPLOAD):
    os.makedirs(data_dir, exist_ok=True)
    srv = ThreadingHTTPServer((host, port), make_handler(os.path.abspath(data_dir), cfg, llm_cfg, max_upload))
    print(f"Upload page: http://{host}:{port}/  (results stored in {os.path.abspath(data_dir)})")
    if llm_cfg is not None:
        print(f"Security Assistant: {llm_cfg.label() if llm_cfg.ready else 'no provider yet; choose one at /settings'}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
