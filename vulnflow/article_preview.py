"""Best-effort, short source previews for article links in IOC matches."""
from __future__ import annotations

import ipaddress
import json
import http.client
import socket
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .errors import UserError

MAX_BYTES = 800_000
MAX_PREVIEWS = 60
MAX_BRIEF_BYTES = 1_500_000


class _Article(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self.paragraphs = []
        self._tag = ""
        self._text = []
        self._ignore = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style", "noscript"):
            self._ignore += 1
        if tag == "meta":
            name = (attrs.get("name") or attrs.get("property") or "").lower()
            if name in ("description", "og:description") and not self.description:
                self.description = attrs.get("content", "")
        if tag in ("title", "p"):
            self._tag = tag
            self._text = []

    def handle_data(self, data):
        if self._tag and not self._ignore:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self._ignore:
            self._ignore -= 1
        if tag == self._tag:
            text = " ".join(" ".join(self._text).split())
            if tag == "title" and text:
                self.title = text
            if tag == "p" and len(text) >= 65 and len(self.paragraphs) < 6:
                self.paragraphs.append(text)
            self._tag = ""
            self._text = []


class _ArticleText(HTMLParser):
    """Extract article text for the model without keeping page markup or scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.parts: list[str] = []
        self._title = False
        self._ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "nav", "footer"):
            self._ignored += 1
        if tag == "title":
            self._title = True
        if tag in ("p", "li", "h1", "h2", "h3", "br", "tr", "pre"):
            self.parts.append("\n")

    def handle_data(self, data):
        if self._ignored:
            return
        text = " ".join(data.split())
        if not text:
            return
        if self._title and not self.title:
            self.title = text
        if not self._title:
            self.parts.append(text + " ")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "nav", "footer") and self._ignored:
            self._ignored -= 1
        if tag == "title":
            self._title = False
        if tag in ("p", "li", "h1", "h2", "h3", "tr", "pre"):
            self.parts.append("\n")


def fetch_article_text(url: str) -> dict:
    """Read a public article for an explicit AI-brief request; reject private targets."""
    current = url
    for _ in range(5):
        target = _public_address(current)
        if not target:
            break
        host, port, address, path = target
        conn_type = http.client.HTTPSConnection if urlsplit(current).scheme == "https" else http.client.HTTPConnection
        conn = conn_type(host, port, timeout=8)
        conn._create_connection = lambda _dest, timeout, source_address=None: socket.create_connection(
            (address, port), timeout, source_address)
        try:
            conn.request("GET", path, headers={"Host": host, "User-Agent": "Mucaro-VulnScope-ArticleBrief/1.0",
                                               "Accept-Encoding": "identity"})
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break
                current = urljoin(current, location)
                continue
            if response.status != 200:
                break
            content_type = response.headers.get_content_type()
            if content_type not in ("text/html", "text/plain", "application/xhtml+xml"):
                break
            raw = response.read(MAX_BRIEF_BYTES + 1)
            if len(raw) > MAX_BRIEF_BYTES:
                break
            page = raw.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            if content_type == "text/plain":
                return {"title": "", "text": page[:60_000]}
            parser = _ArticleText()
            parser.feed(page)
            text = "\n".join(" ".join(line.split()) for line in "".join(parser.parts).splitlines())
            return {"title": parser.title[:200], "text": text[:60_000]}
        except (OSError, UnicodeError, ValueError):
            break
        finally:
            conn.close()
    return {}


def _short(text: str, limit=320) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[: limit + 1].rsplit(" ", 1)[0]
    return cut.rstrip(".,;:") + "…"


def _public_address(url: str) -> tuple[str, int, str, str] | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            return None
        if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        if not addresses:
            return None
        for _, _, _, _, address in addresses:
            if not ipaddress.ip_address(address[0]).is_global:
                return None
        path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        return parsed.hostname, port, addresses[0][4][0], path
    except (ValueError, OSError):
        return None


def fetch_preview(url: str) -> dict:
    """Extract a title and short description without storing an article copy."""
    current = url
    for _ in range(4):
        target = _public_address(current)
        if not target:
            break
        host, port, address, path = target
        conn_type = http.client.HTTPSConnection if urlsplit(current).scheme == "https" else http.client.HTTPConnection
        conn = conn_type(host, port, timeout=5)
        # Connect to the checked public address; TLS still verifies the original hostname.
        conn._create_connection = lambda _dest, timeout, source_address=None: socket.create_connection(
            (address, port), timeout, source_address)
        try:
            conn.request("GET", path, headers={"Host": host, "User-Agent": "vulnScope-SourcePreview/1.0",
                                               "Accept-Encoding": "identity"})
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break
                current = urljoin(current, location)
                continue
            if response.status != 200:
                break
            if response.headers.get_content_type() not in ("text/html", "application/xhtml+xml"):
                break
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                break
            text = raw.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
            parser = _Article()
            parser.feed(text)
            overview = _short(parser.description or " ".join(parser.paragraphs[:2]))
            return {"title": _short(parser.title, 140), "overview": overview} if overview else {}
        except (OSError, UnicodeError, ValueError):
            break
        finally:
            conn.close()
    return {}


def read_preview_cache(path: str) -> dict[str, dict]:
    """Read short, saved source overviews for an offline or repeatable run."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UserError(f"Cannot read article preview cache: {exc}") from exc
    if not isinstance(data, dict):
        raise UserError("Article preview cache must be a JSON object keyed by article URL")
    return {url: {"title": _short(value.get("title", ""), 140),
                  "overview": _short(value.get("overview", ""))}
            for url, value in data.items()
            if isinstance(url, str) and isinstance(value, dict)
            and isinstance(value.get("title", ""), str)
            and isinstance(value.get("overview", ""), str)
            and value.get("overview")}


def add_previews(matches: list[dict], cached: dict[str, dict] | None = None) -> None:
    """Prioritize one source per matched IP, then other article links."""
    preferred = [row["articles"][0] for row in matches if row["type"] == "ip" and row["articles"]]
    remaining = [url for row in matches for url in row["articles"]]
    urls = list(dict.fromkeys(preferred + remaining))[:MAX_PREVIEWS]
    if not urls:
        return
    previews = {url: cached[url] for url in urls if cached and url in cached}
    missing = [url for url in urls if url not in previews]
    if missing:
        with ThreadPoolExecutor(max_workers=6) as pool:
            previews.update(zip(missing, pool.map(fetch_preview, missing)))
    for row in matches:
        row["article_previews"] = {url: previews[url] for url in row["articles"]
                                   if previews.get(url)}
