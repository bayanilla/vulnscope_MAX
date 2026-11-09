"""Local upload page (standard library only).

GET  /            upload form
POST /analyze     run the workflow on the uploaded files
GET  /runs/<id>/  links to a run's reports; files under it are served read-only
POST /runs/<id>/brief  generate the Security Assistant brief (when an LLM is configured)
POST /runs/<id>/article-briefs  generate article briefs from matched sources
POST /runs/<id>/ask    JSON {question, history} -> {answer, answer_html}
GET  /runs/<id>/radar-status  whether on-demand Radar lookup is configured
POST /runs/<id>/radar  Radar context for an observed IP or domain IOC
GET/POST /branding     set the name before "VulnScope" and an optional logo (saved per user; password protected)
GET/POST /settings     choose the AI provider and enter its API key (kept in memory only)
"""
from __future__ import annotations

import html
import dataclasses
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import json

from . import multipart
from . import branding
from .branding import icon_data_uri, product_name
from .correlate import Config
from dataclasses import replace
from urllib.parse import parse_qs

from .llm import DEFAULT_BASE_URLS, PROVIDER_ALIASES, PROVIDER_NAMES, Analyst, LLMConfig, LLMError, load_results, log_qa, write_brief
from .article_brief import generate_article_briefs
from .parsers import FORMATS
from . import resources
from .pipeline import run
from .radar import RadarError, lookup as radar_lookup
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
<p>Point the workflow at network telemetry, with optional Nessus results, or upload files. It cleans and
normalizes the data and produces an executive summary and a technical report. Without scan data,
vulnerability status remains unknown.</p>
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
<input type="hidden" name="csrf" value="{csrf}">
<label for="folder">Folder of telemetry and scans</label>
<input id="folder" type="file" name="folder" webkitdirectory directory multiple>
<div class="hint">Choose one folder to include its files and subfolders in a single analysis. A Nessus scan is optional.</div>
<label for="telemetry">Network telemetry</label>
<input id="telemetry" type="file" name="telemetry" multiple>
<div class="hint">Optional additional files: Zeek connection, DNS, SMTP and industrial protocol logs; Palo Alto traffic and threat logs; NetFlow / VPC flow / SIEM CSV.</div>
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
<a href="/settings">Security Assistant settings</a> · <a href="/branding">Branding</a></p>
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
            f"<title>{html.escape(title)} · {html.escape(product_name())}</title><link rel=\"icon\" href=\"{icon_data_uri()}\">{THEME_INIT}<style>{CSS}</style></head>"
            f"<body>{theme_control()}{body}</body></html>")


CHAT = """<section id="analyst-chat" class="analyst-chat results-assistant-drawer" data-ai-chat data-ask-url="ask"
role="dialog" aria-modal="false" aria-labelledby="ai-chat-title" hidden>
<div class="ai-chat-header"><h2 id="ai-chat-title">Security Assistant</h2>
<button type="button" class="ai-chat-close" aria-label="Close Security Assistant">Close</button></div>
<p class="ai-chat-status">{status}</p><a class="ai-chat-settings" href="{settings}">Change provider</a>
{brief}
<div class="ai-chat-log" role="log" aria-label="Security Assistant conversation" aria-live="polite"
aria-relevant="additions" tabindex="0"{unready}></div>
<form class="ai-chat-form"{unready}><label for="q">Ask about these results</label>
<textarea id="q" rows="3" maxlength="4000" placeholder="e.g. Why is fs01 a P1? How do I confirm the callback from web01 in Zeek?"></textarea>
<button type="submit" class="ai-chat-submit">Ask</button> <span class="ai-chat-busy hint" role="status"></span></form></section>"""

RESULTS_CHAT_CSS = """
.results-assistant-intro{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 16px}
.results-assistant-trigger{margin:0}
.results-assistant-drawer[hidden],.results-assistant-drawer [hidden],.article-brief-progress[hidden]{display:none!important}
.results-assistant-drawer{position:fixed;top:0;right:0;bottom:0;width:min(520px,100vw);max-width:none;
z-index:1000;box-sizing:border-box;padding:18px;display:flex;flex-direction:column;gap:10px;
background:var(--bg);color:var(--fg);border-left:1px solid var(--line);box-shadow:-18px 0 48px #0008;
animation:assistant-slide-in .3s cubic-bezier(.2,.8,.2,1)}
.results-assistant-drawer .ai-chat-header{display:flex;align-items:center;justify-content:space-between;gap:12px}
.results-assistant-drawer h2{margin:0;font-size:18px}.results-assistant-drawer .ai-chat-close{margin:0}
.results-assistant-drawer .ai-chat-status{font-size:12px;margin:0;max-height:5em;overflow:auto}
.results-assistant-drawer .ai-chat-settings{align-self:flex-start;font-size:12px}
.results-assistant-drawer .ai-chat-log{height:auto;min-height:0;flex:1}
.results-assistant-drawer .ai-chat-form{flex:none}
.results-assistant-drawer .ai-chat-form label{margin-top:0}
.results-assistant-drawer .ai-chat-brief form{margin:0}
.article-brief-progress{display:inline-flex;align-items:center;gap:8px;margin-left:10px}
.article-brief-spinner{width:16px;height:16px;border:2px solid var(--line);border-top-color:var(--accent);
border-radius:50%;animation:article-brief-spin .8s linear infinite}
@keyframes assistant-slide-in{from{transform:translateX(100%)}to{transform:translateX(0)}}
@keyframes article-brief-spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.results-assistant-drawer,.article-brief-spinner{animation:none}}
"""

ARTICLE_PROGRESS_SCRIPT = """<script>
(() => {
  const form = document.getElementById('article-briefs-form');
  if (!form) return;
  const button = form.querySelector('button');
  const progress = form.querySelector('.article-brief-progress');
  form.addEventListener('submit', () => {
    button.disabled = true;
    button.textContent = 'Generating article briefs…';
    progress.hidden = false;
  });
  window.addEventListener('pageshow', () => {
    button.disabled = false;
    button.textContent = 'Generate article briefs with OpenAI';
    progress.hidden = true;
  });
})();
</script>"""


def _chat_asset(name: str) -> str:
    with open(os.path.join(os.path.dirname(__file__), "static", name), encoding="utf-8") as fh:
        return fh.read()


def _where(cfg: LLMConfig) -> str:
    return (html.escape(_where_text(cfg)) +
            ' <a href="/settings?next={next}">Change</a>. Answers are AI-generated; verify before acting.')


def _where_text(cfg: LLMConfig) -> str:
    if cfg.is_offline:
        return ("Built-in offline assistant: answers are put together from this run's results by fixed rules. "
                "No AI model is used and nothing leaves this machine.")
    dest = f"correlated results (not raw logs) are sent to {cfg.destination()}"
    red = "; IPs and hostnames are replaced with tokens first" if cfg.redact else ""
    return f"Model: {cfg.label()}: {dest + red}."


SETTINGS = """<style>{css}</style><h1>Security Assistant settings</h1>
<p>The Security Assistant works out of the box with the built-in offline assistant. Pick an AI provider here if you
want a model to interpret the results instead. Nothing is sent to a model until you save that choice. The API key is
held in this server's memory only: it is not written to disk, shown again, or logged, and it is forgotten when the
server stops.</p>
{status}{error}
<form method="post" action="/settings">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="next" value="{next}">
<label for="provider">Provider</label>
<select id="provider" name="provider">{options}</select>
<div class="hint">Built-in (offline, no AI) explains each run from its own results: host risk, CVEs, exposure, inbound and outbound traffic, attack paths and IOC matches. It needs no model, API key or network, and it can only answer about what is in the results.</div>
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
<button type="submit" name="action" value="clear" class="secondary">Use the built-in assistant and forget key</button>
</form><p><a href="{next}">Back</a></p>"""
SETTINGS_CSS = """form label{display:block;font-weight:600;margin:14px 0 4px} .hint{color:var(--muted);font-size:.9rem}
form input[type=text],form input[type=password],form select{width:100%;max-width:520px;padding:6px;font:inherit;box-sizing:border-box}
button{margin-top:18px;padding:8px 16px;cursor:pointer}
button.secondary{background:transparent;color:var(--fg);border:1px solid var(--line)}"""


BRANDING = """<style>{css}
.brand-preview{{display:flex;align-items:center;gap:10px;padding:12px 14px;margin:8px 0 4px;max-width:520px;
border:1px solid var(--line);border-radius:var(--radius);background:var(--bar);font-weight:800;font-size:1.1rem;letter-spacing:.02em}}
.brand-preview img{{height:28px;width:auto;max-width:110px;object-fit:contain}}
.check{{display:flex;gap:8px;align-items:center;font-weight:400;margin-top:10px}}
form{{border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin:16px 0;max-width:640px}}</style>
<h1>Branding</h1>
<p>Change the name shown at the top left of the upload page, reports and Explorer, and add a small logo
to the left of it. The choice is saved on this computer and used for every new analysis; pages that were
already generated keep the branding they were made with.</p>
{error}
<div class="hint">Preview</div>
<div class="brand-preview" id="bp">{logo}<span id="bp-name">{name}</span></div>
<form method="post" action="/branding" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="{csrf}">
<label for="prefix">Name before “VulnScope”</label>
<input id="prefix" name="prefix" type="text" value="{prefix}" maxlength="{max_prefix}" placeholder="e.g. Ford" autocomplete="off">
<div class="hint">Shown as “<i>name</i> VulnScope”. Leave blank to show just “VulnScope”. Up to {max_prefix} characters.</div>
<label for="logo">Logo (optional)</label>
<input id="logo" name="logo" type="file" accept="image/png,image/jpeg,image/gif,image/webp">
<div class="hint">PNG, JPEG, GIF or WebP, up to {max_kb} KB. It is shown about 24 pixels tall, so a square or wide image
with a transparent background works best. SVG isn't accepted. Leave empty to keep the current logo.</div>
{remove}
<button type="submit">Save branding</button>
</form>
<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
<form method="post" action="/branding" enctype="multipart/form-data" style="border:0;padding:0;margin:0;background:none">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="reset">
<button type="submit" class="secondary">Reset to Múcaro VulnScope</button></form>
<form method="post" action="/branding/lock" style="border:0;padding:0;margin:0;background:none">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit" class="secondary">Lock branding</button></form></div>
<p><a href="/">Back to the upload page</a></p>
<script>
(function () {{
  const input = document.getElementById("prefix"), out = document.getElementById("bp-name");
  input.addEventListener("input", () => {{
    const v = input.value.replace(/\\s+/g, " ").trim();
    out.textContent = v ? v + " VulnScope" : "VulnScope";
  }});
}})();
</script>"""
MAX_BRANDING_UPLOAD = branding.MAX_LOGO_BYTES + 64 * 1024
BRANDING_COOKIE = "vulnscope_branding"
BRANDING_UNLOCK_SECONDS = 30 * 60
BRANDING_FREE_ATTEMPTS = 5          # then a lockout that doubles with each further wrong password
BRANDING_LOCKED = """<style>{css}
form{{border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin:16px 0;max-width:640px}}</style>
<h1>Branding</h1>
<p>Changing the name and logo is password protected. Enter the Branding password to continue.</p>
{error}
<form method="post" action="/branding/unlock">
<input type="hidden" name="csrf" value="{csrf}">
<label for="password">Branding password</label>
<input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required autofocus>
<div class="hint">Capital letters and extra spaces don't matter. The page stays unlocked in this browser for 30 minutes.</div>
<button type="submit">Unlock</button>
</form>
<p><a href="/">Back to the upload page</a></p>"""


NATIVE_PICKER = sys.platform == "darwin" and shutil.which("osascript") is not None
LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")
SECURITY_HEADERS = {
    # The pages carry their own inline scripts and styles; nothing loads from other origins.
    "Content-Security-Policy": ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
                                "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"),
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",       # no-referrer would make browsers send Origin: null
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
TOKEN_COOKIE = "vulnscope_access"


def is_loopback_host(host: str) -> bool:
    """True for a bind address that only this machine can reach."""
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
                 max_upload: int = MAX_UPLOAD, access_token: str | None = None,
                 allowed_hosts: tuple[str, ...] = ()):
    """llm_cfg None hides the Security Assistant entirely; an unready LLMConfig falls back to the
    built-in offline assistant, so the assistant always works without a provider.

    Without ``access_token`` the server only answers requests whose Host header names this
    machine's loopback address (or one of ``allowed_hosts``), which defeats DNS rebinding.
    With ``access_token`` (remote access) every request must carry the token, as a cookie
    set from the one-time ``?token=`` link printed at start-up.
    """
    state = {"llm": llm_cfg if llm_cfg is None or llm_cfg.ready else LLMConfig.offline()}
    csrf = secrets.token_urlsafe(24)   # guards form posts from other sites in the same browser
    extra_hosts = {h.lower() for h in allowed_hosts}
    brand_lock = threading.Lock()
    brand_unlocks: dict[str, float] = {}               # unlock token -> expiry (monotonic seconds)
    brand_fails = {"count": 0, "until": 0.0}

    class Handler(BaseHTTPRequestHandler):
        timeout = 120                  # drop clients that stop sending mid-request

        def _llm(self) -> LLMConfig | None:
            return replace(state["llm"]) if state["llm"] is not None else None

        def _host_ok(self) -> bool:
            """Reject requests for any other host name (DNS rebinding) unless remote access is on."""
            if access_token:
                return True
            host = (self.headers.get("Host") or "").strip().lower()
            port = self.server.server_address[1]
            names = {f"{n}:{port}" for n in LOOPBACK_NAMES} | extra_hosts
            if port == 80:
                names |= set(LOOPBACK_NAMES)
            return host in names

        def _token_ok(self) -> bool:
            if not access_token:
                return True
            from http.cookies import SimpleCookie
            try:
                jar = SimpleCookie(self.headers.get("Cookie") or "")
            except Exception:
                return False
            got = jar.get(TOKEN_COOKIE)
            return bool(got) and secrets.compare_digest(got.value, access_token)

        def _gate(self) -> bool:
            """Host and access-token checks shared by every request. Sends the refusal itself."""
            if not self._host_ok():
                self._send(421, "Unknown host name. Open the upload page at the address the server printed.",
                           "text/plain")
                return False
            if access_token and not self._token_ok():
                query = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                given = query.get("token", [""])[0]
                if self.command == "GET" and given and secrets.compare_digest(given, access_token):
                    self._send(303, "", headers={
                        "Location": self.path.split("?", 1)[0],
                        "Set-Cookie": f"{TOKEN_COOKIE}={access_token}; HttpOnly; SameSite=Strict; Path=/"})
                    return False
                self._send(401, "Open the link with the access token that the server printed at start-up.",
                           "text/plain")
                return False
            return True

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin == f"http://{self.headers.get('Host', '')}"

        def _length(self) -> int:
            """Content-Length as a non-negative int; -1 when missing or malformed."""
            try:
                n = int(self.headers.get("Content-Length") or "")
            except ValueError:
                return -1
            return n if n >= 0 else -1

        def _read_body(self, cap: int) -> bytes | None:
            n = self._length()
            if n < 0 or n > cap:
                self.close_connection = True
                return None
            return self.rfile.read(n)

        def _read_form(self, cap: int = 20000) -> dict | None:
            raw = self._read_body(cap)
            if raw is None:
                return None
            return {k: v[0] for k, v in parse_qs(raw.decode(errors="replace")).items()}

        def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _form(self, error=""):
            err = f'<p style="color:#c0392b"><strong>{html.escape(error)}</strong></p>' if error else ""
            self._send(200, FORM.format(css=CSS, theme_init=THEME_INIT, theme_ui=theme_control(),
                                        product_name=html.escape(product_name()), icon=icon_data_uri(),
                                        error=err, formats=", ".join(FORMATS), csrf=csrf,
                                        csrf_js=json.dumps(csrf), native_js="true" if NATIVE_PICKER else "false",
                                        path=html.escape(state.get("last_path", ""))))

        def _analyze_folder(self):
            """Analyze a folder on the machine running the server, reading the files in place."""
            form = self._read_form()
            if form is None:
                return self._send(400, "Bad request", "text/plain")
            if not secrets.compare_digest(form.get("csrf", ""), csrf):
                return self._send(403, "Forbidden", "text/plain")
            raw = form.get("path", "").strip().strip('"').strip("'")
            folder = os.path.realpath(os.path.expanduser(raw)) if raw else ""
            state["last_path"] = raw
            if resources.busy():
                return self._form("Another analysis is already running on this machine. "
                                  "Wait for it to finish and try again.")
            if not folder or not os.path.isdir(folder):
                return self._form(f"Folder not found: {raw or '(empty)'}. Use the full path, for example ~/Documents/case-logs.")
            run_id = secrets.token_hex(8)
            out_dir = os.path.join(data_dir, run_id, "out")
            files = _input_files([folder], out_dir)
            files = [f for f in files if not os.path.realpath(f).startswith(os.path.realpath(data_dir) + os.sep)]
            if not files:
                return self._form(f"No files found in {folder}.")
            cfg = dataclasses.replace(base_cfg, internal_nets=list(base_cfg.internal_nets))
            nets = form.get("internal_nets", "").strip()
            if nets:
                cfg.internal_nets = [n.strip() for n in re.split(r"[,\s]+", nets) if n.strip()]
            os.makedirs(os.path.join(data_dir, run_id, "in"))
            with open(os.path.join(data_dir, run_id, "in", "SOURCE.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"Read in place from {folder}\n" + "\n".join(files) + "\n")
            try:
                run(files, out_dir, cfg, workdir=os.path.join(data_dir, run_id))
            except ValueError as exc:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._form(str(exc))
            except Exception:
                traceback.print_exc()
                return self._form("The analysis failed; see the server console for details.")
            self._send(303, "", headers={"Location": f"/runs/{run_id}/"})

        def _read_json(self):
            raw = self._read_body(20000)
            if raw is None:
                return None
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return None
            ok = isinstance(body, dict) and isinstance(body.get("csrf"), str) and \
                secrets.compare_digest(body["csrf"], csrf)
            return body if ok else None

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
            if not self._gate():
                return
            path = unquote(self.path.split("?", 1)[0])
            if path in ("/", "/index.html"):
                return self._form()
            if path == "/branding":
                return self._branding()
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
                    "offline": bool(cfg and cfg.is_offline),
                    "description": _where_text(cfg) if cfg and cfg.ready else "No AI provider selected yet.",
                    "csrf": csrf,
                }), "application/json", {"Cache-Control": "no-store"})
            if m[2] == "radar-status":
                if not os.path.isdir(run_dir):
                    return self._send(404, "Not found", "text/plain")
                return self._send(200, json.dumps({
                    "enabled": bool(os.environ.get("CLOUDFLARE_RADAR_API_TOKEN")),
                    "csrf": csrf,
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
            try:
                telemetry_only = not load_results(run_dir)["summary"].get("vulnerability_data_available", True)
            except (OSError, ValueError, LLMError):
                telemetry_only = False
            links = [("Executive summary", "executive_summary.html"),
                     ("Technical report", "technical_report.html"),
                     (("Vulnerability findings (CSV; unavailable)" if telemetry_only else "Correlated findings (CSV)"), "correlated_findings.csv"),
                     ("Full results (JSON)", "results.json"),
                     ("Normalized flows (CSV)", "normalized/flows.csv"),
                     (("Normalized findings (CSV; unavailable)" if telemetry_only else "Normalized findings (CSV)"), "normalized/findings.csv"),
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
                         + (" Click a host to inspect observed endpoints, ports, protocols, and direction.</p>"
                            if telemetry_only else " Click a host to see who is targeting it and how far a compromise could reach.</p>")
                         + f"<ul>{items}</ul>")
            else:
                items = f"<ul>{items}</ul>"
            here = f"/runs/{run_id}/"
            cfg, ai = self._llm(), ""
            trigger = ""
            if cfg is not None:
                brief = (f'<div class="ai-chat-brief"><form method="post" action="brief">'
                         f'<input type="hidden" name="csrf" value="{csrf}">'
                         '<button type="submit">Generate Security Assistant brief</button>'
                         f' <span class="hint">{"Instant; built from the results without AI." if cfg.is_offline else "Takes a minute or two."}</span></form></div>'
                         if cfg.ready and not os.path.exists(os.path.join(run_dir, "ai_analyst_brief.html")) else "")
                ai = CHAT.format(status=html.escape(_where_text(cfg) if cfg.ready else "No AI provider selected yet."),
                                 settings=f"/settings?next={here}", brief=brief,
                                 unready="" if cfg.ready else " hidden")
                trigger = ('<div class="results-assistant-intro">'
                           '<button id="btn-ai" class="results-assistant-trigger" type="button" '
                           'aria-controls="analyst-chat" aria-expanded="false">Security Assistant</button>'
                           f'<span class="hint">Ask about this run’s {"network observations" if telemetry_only else "findings"}, evidence, and next steps.</span>'
                           '</div>')
            article_ui = ""
            try:
                result = load_results(run_dir)
                article_urls = {url for match in result.get("ioc_matches", []) for url in match.get("articles", [])}
                saved_urls = set(result.get("article_briefs", {}))
                if article_urls:
                    remaining = len(article_urls - saved_urls)
                    article_ui = (f"<h2>Article briefs</h2><p>{len(saved_urls & article_urls)} saved; "
                                  f"{remaining} matched article(s) without a saved brief.</p>")
                    if remaining and cfg is not None and cfg.provider == "openai" and cfg.redact:
                        article_ui += (f'<p><a href="/settings?next={here}">Turn off IP/hostname redaction</a>'
                                       ' to include exact source indicators in article briefs.</p>')
                    elif remaining and cfg is not None and cfg.provider == "openai" and cfg.api_key:
                        article_ui += (f'<form id="article-briefs-form" method="post" action="article-briefs">'
                                       f'<input type="hidden" name="csrf" value="{csrf}">'
                                       '<button type="submit">Generate article briefs with OpenAI</button>'
                                       ' <span class="hint">Sends matched article text to OpenAI using your configured key.</span>'
                                       ' <span class="article-brief-progress" role="status" aria-live="polite" hidden>'
                                       '<span class="article-brief-spinner" aria-hidden="true"></span>'
                                       'Generating briefs. This may take a few minutes…</span></form>')
                    elif remaining and cfg is not None:
                        article_ui += (f'<p><a href="/settings?next={here}">Choose OpenAI and enter an API key</a>'
                                       ' to generate these article briefs.</p>')
            except (OSError, ValueError):
                pass
            chat_style = f"<style>{_chat_asset('analyst_chat.css')}{RESULTS_CHAT_CSS}</style>" if ai else ""
            chat_script = f"<script>{_chat_asset('analyst_chat.js')}</script>" if ai else ""
            status = ('<p role="status"><strong>No vulnerability data available; vulnerability status unknown.</strong> '
                      'Network observations and IOC matches are leads for review.</p>' if telemetry_only else '')
            body = (f"{chat_style}<h1>Results</h1>{status}{trigger}{items}{article_ui}{ai}"
                    f"<p><a href=\"/\">New analysis</a></p>{chat_script}{ARTICLE_PROGRESS_SCRIPT}")
            self._send(200, _page("Results", body))

        def _json(self, code, obj):
            self._send(code, json.dumps(obj), "application/json")

        def _radar(self, run_id):
            run_dir = os.path.join(data_dir, run_id, "out")
            if not os.path.isdir(run_dir):
                return self._json(404, {"error": "Analysis run not found."})
            body = self._read_json()
            if body is None:
                return self._json(403, {"error": "Forbidden."})
            kind, value = body.get("type"), body.get("value")
            if not isinstance(kind, str) or not isinstance(value, str) or len(value) > 253:
                return self._json(400, {"error": "Invalid indicator."})
            try:
                result = load_results(run_dir)
                if not any(row.get("type") == kind and row.get("value") == value
                           for row in result.get("ioc_matches", [])):
                    return self._json(404, {"error": "Indicator was not matched in this run."})
                context = radar_lookup(kind, value, os.environ.get("CLOUDFLARE_RADAR_API_TOKEN", ""))
                return self._send(200, json.dumps(context), "application/json",
                                  {"Cache-Control": "no-store"})
            except ValueError as exc:
                return self._json(400, {"error": str(exc)})
            except RadarError as exc:
                return self._json(502, {"error": str(exc)})
            except LLMError:
                return self._json(404, {"error": "Analysis results not found."})
            except OSError:
                return self._json(500, {"error": "Analysis results could not be read."})

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
                    form = self._read_form(10000)
                    if form is None or not secrets.compare_digest(form.get("csrf", ""), csrf):
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
                if not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), csrf):
                    return self._json(403, {"error": "Forbidden. Reload the page and try again."})
                if "application/json" not in self.headers.get("Content-Type", ""):
                    return self._json(415, {"error": "Send JSON."})
                length = self._length()
                if not 0 < length <= 1_000_000:
                    self.close_connection = True
                    return self._json(413, {"error": "Request too large."})
                req = json.loads(self.rfile.read(length))
                if not isinstance(req, dict):
                    return self._json(400, {"error": "Malformed request."})
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
                              for p, n in PROVIDER_NAMES.items())
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

        def _branding_unlocked(self) -> bool:
            from http.cookies import SimpleCookie
            try:
                got = SimpleCookie(self.headers.get("Cookie") or "").get(BRANDING_COOKIE)
            except Exception:
                return False
            if not got:
                return False
            now = time.monotonic()
            with brand_lock:
                for tok in [t for t, exp in brand_unlocks.items() if exp <= now]:
                    del brand_unlocks[tok]
                return any(secrets.compare_digest(got.value, tok) for tok in brand_unlocks)

        def _branding_locked(self, error="", code=200):
            err = f'<p style="color:#c0392b"><strong>{html.escape(error)}</strong></p>' if error else ""
            self._send(code, _page("Branding", BRANDING_LOCKED.format(css=SETTINGS_CSS, error=err, csrf=csrf)),
                       headers={"Cache-Control": "no-store"})

        def _unlock_branding(self):
            """Check the Branding password: scrypt hash, constant-time compare, lockout after repeated failures."""
            form = self._read_form(4096)
            if form is None:
                return self._send(400, "Bad request", "text/plain")
            if not secrets.compare_digest(form.get("csrf", ""), csrf):
                return self._send(403, "Forbidden", "text/plain")
            with brand_lock:
                wait = brand_fails["until"] - time.monotonic()
            if wait > 0:
                return self._branding_locked(
                    f"Too many wrong passwords. Try again in {max(1, round(wait / 60))} minute(s).", 429)
            if not branding.check_password(form.get("password", "")):
                with brand_lock:
                    brand_fails["count"] += 1
                    extra = brand_fails["count"] - BRANDING_FREE_ATTEMPTS
                    if extra >= 0:
                        brand_fails["until"] = time.monotonic() + min(3600, 60 * 2 ** extra)
                return self._branding_locked("That password isn't right.", 403)
            token = secrets.token_urlsafe(32)
            with brand_lock:
                brand_fails["count"], brand_fails["until"] = 0, 0.0
                brand_unlocks[token] = time.monotonic() + BRANDING_UNLOCK_SECONDS
            self._send(303, "", headers={
                "Location": "/branding",
                "Set-Cookie": f"{BRANDING_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/branding; "
                              f"Max-Age={BRANDING_UNLOCK_SECONDS}"})

        def _lock_branding(self):
            form = self._read_form(4096)
            if form is None or not secrets.compare_digest(form.get("csrf", ""), csrf):
                return self._send(403, "Forbidden", "text/plain")
            from http.cookies import SimpleCookie
            try:
                got = SimpleCookie(self.headers.get("Cookie") or "").get(BRANDING_COOKIE)
            except Exception:
                got = None
            if got:
                with brand_lock:
                    brand_unlocks.pop(got.value, None)
            self._send(303, "", headers={
                "Location": "/branding",
                "Set-Cookie": f"{BRANDING_COOKIE}=; HttpOnly; SameSite=Strict; Path=/branding; Max-Age=0"})

        def _branding(self, error="", code=200):
            if not self._branding_unlocked():
                return self._branding_locked(code=code)
            cur = branding.load()
            err = f'<p style="color:#c0392b"><strong>{html.escape(error)}</strong></p>' if error else ""
            remove = ('<label class="check"><input type="checkbox" name="remove_logo" value="1"> Remove the current logo</label>'
                      if cur.logo else "")
            body = BRANDING.format(css=SETTINGS_CSS, error=err, logo=branding.logo_img(""),
                                   name=html.escape(cur.name), prefix=html.escape(cur.prefix), csrf=csrf,
                                   max_prefix=branding.MAX_PREFIX, max_kb=branding.MAX_LOGO_BYTES // 1024,
                                   remove=remove)
            self._send(code, _page("Branding", body), headers={"Cache-Control": "no-store"})

        def _save_branding(self):
            """Save the analyst's name prefix and logo. The logo is checked by content, never trusted by name."""
            if not self._branding_unlocked():
                self.close_connection = True
                return self._branding_locked("Enter the Branding password first.", 403)
            length = self._length()
            if length <= 0 or length > MAX_BRANDING_UPLOAD:
                self.close_connection = True
                return self._branding(f"Logos must be {branding.MAX_LOGO_BYTES // 1024} KB or smaller.", 413)
            with tempfile.TemporaryDirectory(prefix="vulnscope-brand-") as tmp:
                try:
                    fields, parts = multipart.parse(self.rfile, length, self.headers.get("Content-Type", ""),
                                                    tmp, lambda i, _name: f"logo{i}")
                except multipart.MultipartError as exc:
                    self.close_connection = True
                    return self._branding(str(exc), 400)
                if not secrets.compare_digest(fields.get("csrf", ""), csrf):
                    return self._send(403, "Forbidden", "text/plain")
                logo = None
                for field, path in parts:
                    if field == "logo":
                        if os.path.getsize(path) > branding.MAX_LOGO_BYTES:
                            return self._branding(f"Logos must be {branding.MAX_LOGO_BYTES // 1024} KB or smaller.", 400)
                        with open(path, "rb") as fh:
                            logo = fh.read()
            try:
                if fields.get("action") == "reset":
                    branding.reset()
                else:
                    branding.update(fields.get("prefix", ""), logo, remove_logo=fields.get("remove_logo") == "1")
            except branding.BrandingError as exc:
                return self._branding(str(exc), 400)
            except OSError:
                traceback.print_exc()
                return self._branding("The branding couldn't be saved; see the server console for details.", 500)
            self._send(303, "", headers={"Location": "/branding"})

        def _save_settings(self):
            form = self._read_form()
            if form is None:
                return self._send(400, "Bad request", "text/plain")
            if not secrets.compare_digest(form.get("csrf", ""), csrf):
                return self._send(403, "Forbidden", "text/plain")
            nxt = form.get("next", "/")
            if state["llm"] is None:
                return self._send(404, "Not found", "text/plain")
            if form.get("action") == "clear":
                state["llm"] = LLMConfig.offline()
                return self._send(303, "", headers={"Location": nxt if re.fullmatch(r"/(runs/[a-f0-9]{16}/)?", nxt) else "/"})
            cur = state["llm"]
            provider = PROVIDER_ALIASES.get(form.get("provider", ""), form.get("provider", ""))
            base_url = form.get("base_url", "").strip()
            typed_key = form.get("api_key", "").strip()
            # A stored key is only reused for the same provider AND the same endpoint, so a changed
            # endpoint can never receive a key the person did not type for it.
            same_endpoint = provider == cur.provider and \
                (base_url or DEFAULT_BASE_URLS.get(provider, "")) == cur.base_url
            new = LLMConfig(provider=provider, model=form.get("model", "").strip(), base_url=base_url,
                            api_key=typed_key or (cur.api_key if same_endpoint else ""),
                            redact=form.get("redact") == "1")
            if provider in ("anthropic", "local"):
                if new.model == "" and provider == cur.provider:
                    new.model = cur.model
            try:
                if not provider:
                    raise LLMError("Choose a provider.")
                new.resolved(env_key=not base_url or base_url == DEFAULT_BASE_URLS.get(provider, ""))
                if new.needs_key():
                    raise LLMError(f"{PROVIDER_NAMES[provider]} needs an API key.")
            except LLMError as exc:
                return self._settings(nxt, str(exc), 400)
            state["llm"] = new
            self._send(303, "", headers={"Location": nxt if re.fullmatch(r"/(runs/[a-f0-9]{16}/)?", nxt) else "/"})

        def do_POST(self):
            if not self._gate():
                return
            if not self._same_origin():
                return self._send(403, "Cross-origin request refused", "text/plain")
            if self.path == "/settings":
                return self._save_settings()
            if self.path == "/branding":
                return self._save_branding()
            if self.path == "/branding/unlock":
                return self._unlock_branding()
            if self.path == "/branding/lock":
                return self._lock_branding()
            m = re.fullmatch(r"/runs/([a-f0-9]{16})/radar", self.path)
            if m:
                return self._radar(m[1])
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
            if resources.busy():                          # refuse before reading a large upload
                self.close_connection = True
                return self._form("Another analysis is already running on this machine. "
                                  "Wait for it to finish and try again.")
            length = self._length()
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
            if not secrets.compare_digest(fields.get("csrf", ""), csrf):
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._send(403, "Forbidden", "text/plain")
            files = [path for _, path in parts]
            nets = fields.get("internal_nets", "").strip()
            if not files:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._form("Please choose at least one telemetry file and one scan file.")
            cfg = dataclasses.replace(base_cfg, internal_nets=list(base_cfg.internal_nets))
            if nets:
                cfg.internal_nets = [n.strip() for n in re.split(r"[,\s]+", nets) if n.strip()]
            try:
                run(files, os.path.join(data_dir, run_id, "out"), cfg, workdir=os.path.join(data_dir, run_id))
            except ValueError as exc:
                shutil.rmtree(os.path.join(data_dir, run_id), ignore_errors=True)
                return self._form(str(exc))
            except Exception:
                traceback.print_exc()
                return self._form("The analysis failed; see the server console for details.")
            self._send(303, "", headers={"Location": f"/runs/{run_id}/"})

    return Handler


def serve(host: str, port: int, data_dir: str, cfg: Config, llm_cfg: LLMConfig | None = None,
          max_upload: int = MAX_UPLOAD, allow_remote: bool = False):
    """Serve on loopback only, unless ``allow_remote``: then every request needs a random access token."""
    remote = not is_loopback_host(host)
    if remote and not allow_remote:
        raise SystemExit(f"Refusing to listen on {host}: the upload page can read any folder this account can. "
                         "Use the default 127.0.0.1, or pass --allow-remote to require an access token.")
    os.umask(0o077)                                     # runs hold raw logs and scan results
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    os.chmod(data_dir, 0o700)
    token = secrets.token_urlsafe(24) if remote else None
    srv = ThreadingHTTPServer((host, port), make_handler(os.path.abspath(data_dir), cfg, llm_cfg, max_upload,
                                                         access_token=token, allowed_hosts=(f"{host}:{port}",)))
    if token:
        print(f"Upload page (remote access; keep this link private): http://{host}:{port}/?token={token}")
        print("Traffic is plain HTTP; use it only on a trusted network or through an SSH tunnel.")
    else:
        print(f"Upload page: http://{host}:{port}/", end="")
    print(f"  (results stored in {os.path.abspath(data_dir)})")
    print(f"Analyses: {resources.max_jobs()} at a time; " + resources.plan(workdir=data_dir).describe())
    if llm_cfg is not None:
        print(f"Security Assistant: {llm_cfg.label() if llm_cfg.ready else 'built-in offline assistant (no AI)'}"
              "; choose an AI model at /settings")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
