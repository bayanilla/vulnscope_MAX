"""A finished run: its page of links, its files (read-only), and the Security Assistant and Radar
calls made from those pages."""
from __future__ import annotations

import html
import json
import os

from .. import saved
from ..article_brief import generate_article_briefs
from ..llm import Analyst, LLMConfig, LLMError, load_results, log_qa, write_brief
from ..radar import RadarError, lookup as radar_lookup
from ..report import md_body, save_article_briefs
from .pages import asset, page

# Second CSP for pages of a reopened report (both policies apply). No allow-same-origin: scripts run,
# but in an opaque origin, so they can't call this server's API or read its other pages.
SAVED_SANDBOX = "sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox allow-downloads allow-modals"

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


def where_text(cfg: LLMConfig) -> str:
    if cfg.is_offline:
        return ("Built-in offline assistant: answers are put together from this run's results by fixed rules. "
                "No AI model is used and nothing leaves this machine.")
    dest = f"correlated results (not raw logs) are sent to {cfg.destination()}"
    red = "; IPs and hostnames are replaced with tokens first" if cfg.redact else ""
    return f"Model: {cfg.label()}: {dest + red}."


def get(req, run_id: str, rest: str):
    """GET /runs/<id>/<rest>: the run's page, its status calls, or one of its files."""
    run_dir = req.app.run_out(run_id)
    if rest == "ai-status":
        if not os.path.isdir(run_dir):
            return req.send_text(404, "Not found")
        cfg = req.app.llm_config()
        return req.send(200, json.dumps({
            "enabled": cfg is not None, "ready": bool(cfg and cfg.ready),
            "offline": bool(cfg and cfg.is_offline),
            "description": where_text(cfg) if cfg and cfg.ready else "No AI provider selected yet.",
            "csrf": req.app.csrf,
        }), "application/json", {"Cache-Control": "no-store"})
    if rest == "radar-status":
        if not os.path.isdir(run_dir):
            return req.send_text(404, "Not found")
        return req.send(200, json.dumps({
            "enabled": bool(os.environ.get("CLOUDFLARE_RADAR_API_TOKEN")),
            "csrf": req.app.csrf,
        }), "application/json", {"Cache-Control": "no-store"})
    if not rest:
        return index(req, run_id, run_dir)
    target = os.path.realpath(os.path.join(run_dir, rest))
    marker = saved.read_marker(os.path.dirname(run_dir))
    if not (target.startswith(run_dir + os.sep) and os.path.isfile(target)):
        # a reopened report's raw data stays in its folder (allow-listed names only)
        target = saved.source_file(marker, rest) if marker is not None else None
        if not target:
            return req.send_text(404, "Not found")
    # Pages of a reopened report carry text from files outside this server's control: run them
    # in an opaque origin so crafted content can't read or drive the rest of it.
    req.send_file(target, {"Content-Security-Policy": SAVED_SANDBOX} if marker is not None else None)


def index(req, run_id: str, run_dir: str):
    if not os.path.isdir(run_dir):
        return req.send_text(404, "Not found")
    try:
        results = load_results(run_dir)
        telemetry_only = not results["summary"].get("vulnerability_data_available", True)
        report = results.get("report") or {}
    except (OSError, ValueError, LLMError):
        results, telemetry_only, report = None, False, {}
    links = [("Executive summary", "executive_summary.html"),
             ("Technical report", "technical_report.html"),
             (("Vulnerability findings (CSV; unavailable)" if telemetry_only else "Correlated findings (CSV)"), "correlated_findings.csv"),
             ("Full results (JSON)", "results.json"),
             ("Normalized flows (CSV)", "normalized/flows.csv"),
             (("Normalized findings (CSV; unavailable)" if telemetry_only else "Normalized findings (CSV)"), "normalized/findings.csv"),
             ("IPS/IDS alerts (CSV)", "normalized/threats.csv"),
             ("Zeek stream events (JSONL)", "normalized/zeek_events.jsonl"),
             ("Industrial protocol events (JSONL)", "normalized/ot_events.jsonl"),
             ("Executive summary (Markdown)", "executive_summary.md"),
             ("Technical report (Markdown)", "technical_report.md")]
    reopened = saved.read_marker(os.path.dirname(run_dir))
    # list only what the run (or a reopened report's folder) has: runs made before a file existed lack it
    links = [(t, p) for t, p in links
             if os.path.exists(os.path.join(run_dir, p)) or (reopened is not None and saved.source_file(reopened, p))]
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
    cfg, ai, trigger = req.app.llm_config(), "", ""
    csrf = req.app.csrf
    if cfg is not None:
        brief = (f'<div class="ai-chat-brief"><form method="post" action="brief">'
                 f'<input type="hidden" name="csrf" value="{csrf}">'
                 '<button type="submit">Generate Security Assistant brief</button>'
                 f' <span class="hint">{"Instant; built from the results without AI." if cfg.is_offline else "Takes a minute or two."}</span></form></div>'
                 if cfg.ready and not os.path.exists(os.path.join(run_dir, "ai_analyst_brief.html")) else "")
        ai = CHAT.format(status=html.escape(where_text(cfg) if cfg.ready else "No AI provider selected yet."),
                         settings=f"/settings?next={here}", brief=brief,
                         unready="" if cfg.ready else " hidden")
        trigger = ('<div class="results-assistant-intro">'
                   '<button id="btn-ai" class="results-assistant-trigger" type="button" '
                   'aria-controls="analyst-chat" aria-expanded="false">Security Assistant</button>'
                   f'<span class="hint">Ask about this run’s {"network observations" if telemetry_only else "findings"}, evidence, and next steps.</span>'
                   '</div>')
    article_ui = _article_briefs(results, cfg, csrf, here) if results is not None else ""
    chat_style = f"<style>{asset('analyst_chat.css')}{RESULTS_CHAT_CSS}</style>" if ai else ""
    chat_script = f"<script>{asset('analyst_chat.js')}</script>" if ai else ""
    if reopened is not None:
        made = html.escape(str(reopened.get("generated", "")))
        where = html.escape(str(reopened.get("shown") or reopened.get("source", "")))
        items = (f'<p role="note">Saved report reopened from <code>{where}</code> (analysis made {made}); '
                 'nothing was reanalyzed and the folder was not changed.'
                 + ("" if reopened.get("explorer") else
                    " That folder has no <code>explorer.html</code>, so the Explorer and Timeline can't be shown.")
                 + "</p>" + items)
    status = ('<p role="status"><strong>No vulnerability data available; vulnerability status unknown.</strong> '
              'Network observations and IOC matches are leads for review.</p>' if telemetry_only else '')
    name, about = report.get("name") or "", report.get("description") or ""
    heading = f"<h1>{html.escape(name)}</h1>" if name else "<h1>Results</h1>"
    network = (f'<p class="report-network"><strong>Network:</strong> {html.escape(report["network"])}</p>'
               if report.get("network") else "")
    about_html = "".join(f'<p class="report-about">{html.escape(p).replace(chr(10), "<br>")}</p>'
                         for p in about.split("\n\n") if p.strip())
    saved_as = f'<p class="hint">Saved as <code>{html.escape(run_id)}</code></p>'
    body = (f"{chat_style}{heading}{network}{about_html}{saved_as}{status}{trigger}{items}{article_ui}{ai}"
            f"<p><a href=\"/\">New analysis</a> · <a href=\"/compare\">Compare with other reports</a></p>"
            f"{chat_script}{ARTICLE_PROGRESS_SCRIPT}")
    req.send(200, page(f"{name} · Results" if name else "Results", body))


def _article_briefs(result: dict, cfg, csrf: str, here: str) -> str:
    article_urls = {url for match in result.get("ioc_matches", []) for url in match.get("articles", [])}
    saved_urls = set(result.get("article_briefs", {}))
    if not article_urls:
        return ""
    remaining = len(article_urls - saved_urls)
    ui = (f"<h2>Article briefs</h2><p>{len(saved_urls & article_urls)} saved; "
          f"{remaining} matched article(s) without a saved brief.</p>")
    if remaining and cfg is not None and cfg.provider == "openai" and cfg.redact:
        ui += (f'<p><a href="/settings?next={here}">Turn off IP/hostname redaction</a>'
               ' to include exact source indicators in article briefs.</p>')
    elif remaining and cfg is not None and cfg.provider == "openai" and cfg.api_key:
        ui += (f'<form id="article-briefs-form" method="post" action="article-briefs">'
               f'<input type="hidden" name="csrf" value="{csrf}">'
               '<button type="submit">Generate article briefs with OpenAI</button>'
               ' <span class="hint">Sends matched article text to OpenAI using your configured key.</span>'
               ' <span class="article-brief-progress" role="status" aria-live="polite" hidden>'
               '<span class="article-brief-spinner" aria-hidden="true"></span>'
               'Generating briefs. This may take a few minutes…</span></form>')
    elif remaining and cfg is not None:
        ui += (f'<p><a href="/settings?next={here}">Choose OpenAI and enter an API key</a>'
               ' to generate these article briefs.</p>')
    return ui


def radar(req, run_id: str):
    """POST /runs/<id>/radar: Cloudflare Radar context for an IOC this run matched."""
    run_dir = req.app.run_out(run_id)
    if not os.path.isdir(run_dir):
        return req.send_json(404, {"error": "Analysis run not found."})
    body = req.read_json()
    if body is None:
        return req.send_json(403, {"error": "Forbidden."})
    kind, value = body.get("type"), body.get("value")
    if not isinstance(kind, str) or not isinstance(value, str) or len(value) > 253:
        return req.send_json(400, {"error": "Invalid indicator."})
    try:
        result = load_results(run_dir)
        if not any(row.get("type") == kind and row.get("value") == value
                   for row in result.get("ioc_matches", [])):
            return req.send_json(404, {"error": "Indicator was not matched in this run."})
        context = radar_lookup(kind, value, os.environ.get("CLOUDFLARE_RADAR_API_TOKEN", ""))
        return req.send_json(200, context, {"Cache-Control": "no-store"})
    except ValueError as exc:                  # radar's own checks of the indicator
        return req.send_json(400, {"error": str(exc)})
    except RadarError as exc:
        return req.send_json(502, {"error": str(exc)})
    except LLMError:
        return req.send_json(404, {"error": "Analysis results not found."})
    except OSError:
        return req.send_json(500, {"error": "Analysis results could not be read."})


def ai(req, run_id: str, action: str):
    """POST /runs/<id>/{brief,article-briefs,ask}: the Security Assistant."""
    run_dir = req.app.run_out(run_id)
    if not os.path.isdir(run_dir):
        return req.send_text(404, "Not found")
    cfg = req.app.llm_config()
    if cfg is None or not cfg.ready:
        return req.send_json(400, {"error": "No AI provider selected. Open AI settings to choose one."})
    try:
        res = load_results(run_dir)
        if action in ("brief", "article-briefs"):
            form = req.read_form(10000)
            if form is None or not req.app.csrf_ok(form.get("csrf", "")):
                return req.send_text(403, "Forbidden")
            if action == "article-briefs":
                return _write_article_briefs(req, res, cfg, run_dir, run_id)
            write_brief(res, run_dir, cfg)
            return req.redirect(f"/runs/{run_id}/ai_analyst_brief.html")
        if not req.app.csrf_ok(req.headers.get("X-CSRF-Token", "")):
            return req.send_json(403, {"error": "Forbidden. Reload the page and try again."})
        if "application/json" not in req.headers.get("Content-Type", ""):
            return req.send_json(415, {"error": "Send JSON."})
        length = req.length()
        if not 0 < length <= 1_000_000:
            req.close_connection = True
            return req.send_json(413, {"error": "Request too large."})
        ask = json.loads(req.rfile.read(length))
        if not isinstance(ask, dict):
            return req.send_json(400, {"error": "Malformed request."})
        question = str(ask.get("question", ""))
        history = ask.get("history") if isinstance(ask.get("history"), list) else []
        answer = Analyst(res, cfg).ask(question, history)
        log_qa(run_dir, cfg, question, answer)
        return req.send_json(200, {"answer": answer, "answer_html": md_body(answer)})
    except LLMError as exc:
        if action in ("brief", "article-briefs"):
            return req.send(502, page("AI brief failed", f"<h1>AI brief failed</h1><p>{html.escape(str(exc))}</p>"
                                                         f"<p><a href=\"/runs/{run_id}/\">Back</a></p>"))
        return req.send_json(502, {"error": str(exc)})
    except (OSError, ValueError) as exc:       # unreadable results, or a malformed question
        if action == "article-briefs":
            return req.send(500, page("Article briefs failed",
                                      f"<h1>Article briefs failed</h1><p>{html.escape(str(exc))}</p>"
                                      f'<p><a href="/runs/{run_id}/">Back</a></p>'))
        return req.send_json(400, {"error": "Malformed request."})


def _write_article_briefs(req, res: dict, cfg, run_dir: str, run_id: str):
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
    return req.send(200, page("Article briefs", notes))
