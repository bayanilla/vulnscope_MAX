"""Security Assistant settings: choose the AI provider and enter its API key (kept in memory only)."""
from __future__ import annotations

import html
import re

from ..llm import DEFAULT_BASE_URLS, PROVIDER_ALIASES, PROVIDER_NAMES, LLMConfig, LLMError
from ..runname import RUN_ID
from .pages import FORM_PAGE_CSS, error_html, page

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


def _next(nxt: str) -> str:
    """Only this server's own pages are valid places to go back to."""
    return nxt if re.fullmatch(rf"/(runs/{RUN_ID}/)?", nxt) else "/"


def view(req):
    """GET /settings[?next=/runs/<id>/]"""
    return _page(req, req.query.get("next", ["/"])[0])


def _page(req, nxt: str, error: str = "", code: int = 200):
    cfg = req.app.llm
    if cfg is None:
        return req.send_text(404, "The Security Assistant is turned off on this server.")
    nxt = _next(nxt)
    options = "".join(f'<option value="{p}"{" selected" if p == cfg.provider else ""}>{n}</option>'
                      for p, n in PROVIDER_NAMES.items())
    if not cfg.provider:
        options = '<option value="" selected>Choose a provider</option>' + options
    status = (f'<p><strong>Current:</strong> {html.escape(cfg.label())}, API key {cfg.masked_key()}.</p>'
              if cfg.ready else "<p><strong>Current:</strong> none selected.</p>")
    body = SETTINGS.format(
        css=FORM_PAGE_CSS, status=status, error=error_html(error), csrf=req.app.csrf, next=html.escape(nxt),
        options=options, model=html.escape(cfg.model), base_url=html.escape(cfg.base_url),
        key_hint="key is set; leave blank to keep it" if cfg.api_key else "paste key",
        redact=" checked" if cfg.redact else "")
    req.send(code, page("Security Assistant settings", body))


def save(req):
    """POST /settings"""
    app = req.app
    form = req.read_form()
    if form is None:
        return req.send_text(400, "Bad request")
    if not app.csrf_ok(form.get("csrf", "")):
        return req.send_text(403, "Forbidden")
    nxt = form.get("next", "/")
    if app.llm is None:
        return req.send_text(404, "Not found")
    if form.get("action") == "clear":
        app.llm = LLMConfig.offline()
        return req.redirect(_next(nxt))
    cur = app.llm
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
        return _page(req, nxt, str(exc), 400)
    app.llm = new
    req.redirect(_next(nxt))
