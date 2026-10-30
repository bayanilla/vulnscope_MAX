"""Múcaro-style article briefs for exact IOC archive matches.

The prompt and output schema are bundled from Múcaro Threat Monitor so a
VulnScope user's OpenAI key can generate briefs without calling Múcaro's app.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

from .article_preview import fetch_article_text
from .llm import LLMConfig, LLMError

ASSETS = Path(__file__).parent
MAX_ARTICLES = 20
MAX_ARTICLE_CHARS = 18_000


def _assets() -> tuple[str, dict]:
    prompt = (ASSETS / "mucaro_article_prompt.txt").read_text(encoding="utf-8").strip()
    schema = json.loads((ASSETS / "mucaro_article_schema.json").read_text(encoding="utf-8"))
    return prompt, schema


def _article_excerpt(text: str, indicators: list[str]) -> str:
    """Keep the lead and later IOC context within the Múcaro input budget."""
    text = text.strip()
    if len(text) <= MAX_ARTICLE_CHARS:
        return text
    lead = text[:9_000]
    windows = []
    for indicator in indicators:
        for match in list(re.finditer(re.escape(indicator), text, re.I))[:4]:
            if match.start() > len(lead):
                windows.append((max(len(lead), match.start() - 450), min(len(text), match.end() + 450)))
    for match in list(re.finditer(r"\b(?:indicators? of compromise|IOCs?|C2|command.and.control|exfiltration)\b",
                                  text, re.I))[:12]:
        if match.start() > len(lead):
            windows.append((max(len(lead), match.start() - 350), min(len(text), match.end() + 350)))
    excerpts = []
    remaining = MAX_ARTICLE_CHARS - len(lead) - 100
    for start, end in sorted(set(windows)):
        if remaining <= 0:
            break
        chunk = text[start:end].strip()[:remaining]
        if chunk:
            excerpts.append(chunk)
            remaining -= len(chunk)
    return (lead + "\n\n[IOC-focused excerpts from later in the article]\n" +
            "\n\n".join(excerpts))[:MAX_ARTICLE_CHARS] if excerpts else text[:MAX_ARTICLE_CHARS]


def _validate(value, schema: dict, path="brief") -> None:
    """Validate the constrained JSON types and required fields we send OpenAI."""
    kind = schema.get("type")
    valid = {"object": lambda x: isinstance(x, dict),
             "array": lambda x: isinstance(x, list),
             "string": lambda x: isinstance(x, str),
             "number": lambda x: isinstance(x, (int, float)) and not isinstance(x, bool),
             "boolean": lambda x: isinstance(x, bool)}
    if kind in valid and not valid[kind](value):
        raise LLMError(f"Article brief has an invalid {path} field.")
    if "enum" in schema and value not in schema["enum"]:
        raise LLMError(f"Article brief has an invalid {path} value.")
    if kind == "object":
        for field in schema.get("required", []):
            if field not in value:
                raise LLMError(f"Article brief is missing {path}.{field}.")
        for field, item in value.items():
            field_schema = schema.get("properties", {}).get(field)
            if field_schema:
                _validate(item, field_schema, f"{path}.{field}")
            elif schema.get("additionalProperties") is False:
                raise LLMError(f"Article brief contains an unexpected {path}.{field} field.")
    elif kind == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1_000_000):
            raise LLMError(f"Article brief has an invalid number of {path} items.")
        for item in value:
            _validate(item, schema["items"], path)


def _response_text(response: dict) -> str:
    if not isinstance(response, dict):
        raise LLMError("OpenAI returned an unreadable article brief.")
    if isinstance(response.get("output_text"), str):
        return response["output_text"]
    output = response.get("output")
    for item in (output if isinstance(output, list) else []):
        if isinstance(item, dict) and item.get("type") == "message":
            for part in item.get("content", []):
                if isinstance(part, dict) and part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    return part["text"]
    raise LLMError("OpenAI did not return article brief text.")


def _generate(url: str, article: dict, indicators: list[str], cfg: LLMConfig) -> dict:
    prompt, schema = _assets()
    title = article.get("title", "")
    text = _article_excerpt(article["text"], indicators)
    user_prompt = ("Analyze the following cybersecurity article and return strict JSON.\n\n"
                   f"source.url: {url}\nsource.title: {title}\n"
                   f"source.publisher: {urlsplit(url).hostname or ''}\nsource.published_at: \n\n"
                   f"article_text:\n{text}")
    request_body = {
        "model": cfg.model,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": prompt}]},
            {"role": "user", "content": [{"type": "input_text", "text": user_prompt}]},
        ],
        "text": {"format": {"type": "json_schema", **schema}},
        "max_output_tokens": 5000,
    }
    req = urllib.request.Request(cfg.base_url.rstrip("/") + "/responses",
                                 data=json.dumps(request_body).encode("utf-8"),
                                 headers={"Authorization": f"Bearer {cfg.api_key}",
                                          "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            raw = response.read(1_500_001)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise LLMError("OpenAI rejected the API key in AI settings.") from exc
        if exc.code == 429:
            raise LLMError("OpenAI rate limit reached; retry later.") from exc
        raise LLMError(f"OpenAI could not generate the article brief (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise LLMError("Could not reach OpenAI to generate the article brief.") from exc
    if len(raw) > 1_500_000:
        raise LLMError("OpenAI returned an oversized article brief.")
    try:
        payload = json.loads(_response_text(json.loads(raw)))
    except (ValueError, TypeError, KeyError) as exc:
        raise LLMError("OpenAI returned an unreadable article brief.") from exc
    _validate(payload, schema["schema"])
    payload["source"]["url"] = url
    payload["source"]["title"] = payload["source"]["title"] or title
    payload["analysis_metadata"] = {"model": cfg.model}
    version = sha256((prompt + json.dumps(schema, sort_keys=True)).encode("utf-8")).hexdigest()[:12]
    return {"brief": payload, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "model": cfg.model, "prompt_version": version}


def generate_article_briefs(res: dict, cfg: LLMConfig) -> dict:
    """Add one saved brief per unique matched article, never per IOC occurrence."""
    cfg = cfg.resolved()
    if cfg.provider != "openai":
        raise LLMError("Múcaro article briefs require OpenAI in AI settings.")
    if not cfg.api_key:
        raise LLMError("Enter an OpenAI API key in AI settings first.")
    if cfg.redact:
        raise LLMError("Turn off IP/hostname redaction to include exact article indicators in AI briefs.")
    by_url: dict[str, list[str]] = {}
    for match in res.get("ioc_matches", []):
        for url in match.get("articles", []):
            by_url.setdefault(url, [])
            if match["value"] not in by_url[url]:
                by_url[url].append(match["value"])
    if not by_url:
        raise LLMError("No matched Múcaro source articles are available for AI briefs.")
    saved = res.setdefault("article_briefs", {})
    generated, unavailable, errors = 0, 0, []
    for url, indicators in by_url.items():
        if url in saved:
            continue
        if generated + unavailable + len(errors) >= MAX_ARTICLES:
            break
        article = fetch_article_text(url)
        if len(article.get("text", "").strip()) < 100:
            unavailable += 1
            continue
        try:
            saved[url] = _generate(url, article, indicators, cfg)
            generated += 1
        except LLMError as exc:
            errors.append(f"{urlsplit(url).hostname or 'article'}: {exc}")
    remaining = len(set(by_url) - set(saved))
    return {"generated": generated, "saved": len(saved), "unavailable": unavailable,
            "remaining": remaining, "errors": errors}
