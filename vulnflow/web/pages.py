"""Pieces every page of the upload server shares: the page shell, error lines and static assets."""
from __future__ import annotations

import html
import json
import os

from ..branding import icon_data_uri, product_name
from ..report import CSS, HTML_OPEN, THEME_INIT, theme_control

STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

# Plain form pages (settings, branding).
FORM_PAGE_CSS = """form label{display:block;font-weight:600;margin:14px 0 4px} .hint{color:var(--muted);font-size:.9rem}
form input[type=text],form input[type=password],form select{width:100%;max-width:520px;padding:6px;font:inherit;box-sizing:border-box}
button{margin-top:18px;padding:8px 16px;cursor:pointer}
button.secondary{background:transparent;color:var(--fg);border:1px solid var(--line)}"""


def asset(name: str) -> str:
    """A file from vulnflow/static, inlined into a page (pages work offline and load nothing else)."""
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


def page(title: str, body: str, head: str = "") -> str:
    """A complete page in the report look: theme, branding icon and the light/dark switch."""
    return (f"{HTML_OPEN}<head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)} · {html.escape(product_name())}</title><link rel=\"icon\" href=\"{icon_data_uri()}\">"
            f"{THEME_INIT}<style>{CSS}</style>{head}</head>"
            f"<body>{theme_control()}{body}</body></html>")


def error_html(message: str) -> str:
    return f'<p style="color:#c0392b"><strong>{html.escape(message)}</strong></p>' if message else ""


def page_config(values: dict) -> str:
    """Values a page's scripts read (CSRF token, picker mode), as a JSON block safe inside HTML."""
    blob = json.dumps(values).replace("<", "\\u003c")
    return f'<script type="application/json" id="vs-page">{blob}</script>'


BUSY = """<div id="busy" role="alertdialog" aria-modal="true" aria-labelledby="busy-title" aria-describedby="busy-hint" hidden>
<div class="busy-card"><div class="busy-stage"><img class="busy-logo" src="{icon}" alt=""></div>
<p class="busy-title" role="status"><span id="busy-title">Working&hellip;</span> <span class="busy-time" id="busy-time">0:00</span></p>
<p class="hint" id="busy-hint"></p></div></div>"""


def busy_overlay() -> str:
    """The overlay static/busy.js shows while a long form post runs."""
    return BUSY.format(icon=icon_data_uri())
