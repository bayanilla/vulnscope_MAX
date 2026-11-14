"""Reopen a completed report from its output folder, without reanalyzing.

The folder is a previous run's output folder (results.json, explorer.html, the reports and
normalized/). results.json holds everything the summaries and the technical report are built
from, so those are rebuilt with this version's code. The Explorer and Timeline are built from
the raw flows, which results.json does not keep; their data is embedded in explorer.html, so it
is lifted out and drawn again with this version's Explorer. The other files (normalized data,
CSVs, an earlier Security Assistant brief) are served read-only from the folder itself, from a
fixed list of names; nothing in the folder is changed.

Its files are treated as untrusted: size capped, parsed as data only (the old HTML is never
served, only the JSON inside explorer.html), checked for the fields the pages read, and the
pages of a reopened run are served in a CSP sandbox (see ``web.py``) so that crafted content
cannot act as the VulnScope page.
"""
from __future__ import annotations

import json
import os
import re

from .correlate import RESULTS_SCHEMA_VERSION
from .errors import UserError

MAX_SAVED_FILE = 256 * 1024 * 1024       # results.json is parsed in memory (~10x its size)
MARKER = "REOPENED.json"                  # in the run folder (next to out/): how the run was made

_VF_DATA = re.compile(r'<script id="vf-data" type="application/json">(.*?)</script>', re.S)


class SavedRunError(UserError):
    """The upload is not a usable saved run; the message is shown to the user."""


def _load_json(text: str, what: str):
    try:
        return json.loads(text)
    except RecursionError:
        raise SavedRunError(f"{what} is nested too deeply to be a VulnScope file.") from None
    except ValueError as exc:
        raise SavedRunError(f"{what} is not valid JSON ({exc}).") from None


def _need(obj, key, kind, where="results.json"):
    if not isinstance(obj.get(key), kind):
        name = {dict: "an object", list: "a list", str: "text"}.get(kind, kind.__name__)
        raise SavedRunError(f"This doesn't look like a VulnScope {where}: "
                            f"\"{key}\" is missing or is not {name}.")
    return obj[key]


def check_results(res) -> dict:
    """Structural check of a parsed results.json. Raises SavedRunError with a readable reason."""
    if not isinstance(res, dict):
        raise SavedRunError("This doesn't look like a VulnScope results.json: the top level is not an object.")
    version = res.get("schema_version", 1)        # files written before the field existed are version 1
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SavedRunError("results.json has an unreadable \"schema_version\".")
    if version > RESULTS_SCHEMA_VERSION:
        raise SavedRunError(f"This results.json was written by a newer VulnScope (results format {version}; "
                            f"this copy reads up to {RESULTS_SCHEMA_VERSION}). Update VulnScope and try again.")
    _need(res, "generated", str)
    cfg = _need(res, "config", dict)
    nets = _need(cfg, "internal_nets", list, "results.json config")
    if not all(isinstance(n, str) for n in nets):
        raise SavedRunError("results.json config.internal_nets must be a list of networks.")
    _need(res, "summary", dict)
    for key in ("hosts", "findings"):
        rows = _need(res, key, list)
        if not all(isinstance(r, dict) and isinstance(r.get("host"), str) for r in rows):
            raise SavedRunError(f"This doesn't look like a VulnScope results.json: an entry in \"{key}\" has no host.")
    for key in ("ioc_matches",):
        if key in res and not isinstance(res[key], list):
            raise SavedRunError(f"results.json \"{key}\" must be a list.")
    if "article_briefs" in res and not isinstance(res["article_briefs"], dict):
        raise SavedRunError("results.json \"article_briefs\" must be an object.")
    return res


def explorer_blob(text: str, generated: str) -> dict:
    """The Explorer data embedded in a saved explorer.html, checked to be from the analysis made
    at ``generated`` (results.json's "generated")."""
    m = _VF_DATA.search(text)
    if not m:
        raise SavedRunError("explorer.html in that folder is not a VulnScope Explorer page (no Explorer data inside).")
    data = _load_json(m.group(1), "The Explorer data in explorer.html")
    if not isinstance(data, dict):
        raise SavedRunError("The Explorer data in explorer.html is not an object.")
    for key, kind in (("generated", str), ("nodes", list), ("links", list), ("focus", dict)):
        _need(data, key, kind, "explorer.html")
    if data["generated"] != generated:
        raise SavedRunError(f"explorer.html is from a different analysis than results.json "
                            f"(made {data['generated']} vs {generated}). The folder mixes files from two runs.")
    return data


def explorer_data(text: str, res: dict) -> dict:
    """The Explorer data embedded in a saved explorer.html, checked against its results.json."""
    data = explorer_blob(text, res["generated"])
    # The Explorer shows the IOC matches and article briefs saved with the results (as after
    # generating briefs), so the two files can't disagree.
    data["ioc_matches"] = res.get("ioc_matches", [])
    data["article_briefs"] = res.get("article_briefs", {})
    return data


# Files served from the original folder when the rebuilt run doesn't have its own copy.
SOURCE_FILES = ("correlated_findings.csv", "hostile_activity.svg", "ai_analyst_brief.html", "ai_chat_log.md",
                "normalized/flows.csv", "normalized/findings.csv", "normalized/threats.csv",
                "normalized/probed_addresses.csv",
                "normalized/zeek_events.jsonl", "normalized/ot_events.jsonl")


def is_report_folder(folder: str) -> bool:
    """A previous run's output folder: results.json next to the pages it produced."""
    return os.path.isfile(os.path.join(folder, "results.json")) and any(
        os.path.isfile(os.path.join(folder, n)) for n in ("explorer.html", "executive_summary.md", "technical_report.md"))


def read_text(path: str, what: str) -> str:
    """A saved file's text, refused (SavedRunError) when it is larger than MAX_SAVED_FILE."""
    if os.path.getsize(path) > MAX_SAVED_FILE:
        raise SavedRunError(f"{what} is larger than {MAX_SAVED_FILE // 1048576} MB, too large to reopen.")
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_results(folder: str) -> dict:
    """A report folder's results.json, size capped and checked (SavedRunError otherwise)."""
    path = os.path.join(folder, "results.json")
    if not os.path.isfile(path):
        raise SavedRunError("There's no results.json in that folder. Choose a completed report's output folder "
                            "(the one with results.json, explorer.html and the reports).")
    return check_results(_load_json(read_text(path, "results.json"), "results.json"))


def load_folder(folder: str) -> tuple[dict, dict | None]:
    """results.json (required) and the Explorer data in explorer.html (if present) of a report folder."""
    res = load_results(folder)
    path = os.path.join(folder, "explorer.html")
    data = explorer_data(read_text(path, "explorer.html"), res) if os.path.isfile(path) else None
    return res, data


def source_file(marker: dict | None, name: str) -> str | None:
    """Path of an allow-listed file in a reopened run's original folder, if it is still there."""
    folder = (marker or {}).get("source")
    if not folder or name not in SOURCE_FILES:
        return None
    root = os.path.realpath(folder)
    path = os.path.realpath(os.path.join(root, name))
    return path if path.startswith(root + os.sep) and os.path.isfile(path) else None


def read_marker(run_root: str) -> dict | None:
    try:
        with open(os.path.join(run_root, MARKER), encoding="utf-8") as fh:
            marker = json.load(fh)
        return marker if isinstance(marker, dict) else None
    except (OSError, ValueError):
        return None


def write(res: dict, data: dict | None, outdir: str, source: str, shown: str = "") -> None:
    """Rebuild the run's pages. Missing or mistyped fields become a SavedRunError."""
    from . import explore
    from .report import write_reports
    try:
        write_reports(res, outdir)
        if data is not None:
            page = explore.html(data)
            with open(os.path.join(outdir, "explorer.html"), "w", encoding="utf-8") as fh:
                fh.write(page)
    except SavedRunError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        detail = f"missing field {exc}" if isinstance(exc, KeyError) else str(exc)[:200]
        raise SavedRunError("This results.json can't be drawn by this version of VulnScope "
                            f"({detail}). It may be from a much older version, or edited.") from None
    with open(os.path.join(os.path.dirname(outdir), MARKER), "w", encoding="utf-8") as fh:
        json.dump({"generated": res["generated"], "schema_version": res.get("schema_version", 1),
                   "explorer": data is not None, "source": source, "shown": shown or source}, fh)
