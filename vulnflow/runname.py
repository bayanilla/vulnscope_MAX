"""Report name, description and the timestamped folder a run is saved in."""
from __future__ import annotations

import os
import re
import secrets
import unicodedata
from datetime import datetime

NAME_MAX = 100          # characters kept from the report name
NETWORK_MAX = 60        # characters kept from the network name
DESCRIPTION_MAX = 2000  # characters kept from the description
SLUG_MAX = 60           # characters of the name used in the folder name
# A run's folder name, as it appears in /runs/<id>/ URLs: old runs are 16 hex characters,
# new ones "<name or 16 hex>_YYYY-MM-DD_HH-MM-SS" (plus "-2", "-3"... on a clash). No dots or
# slashes, so it can never leave the results folder.
RUN_ID = r"[A-Za-z0-9][A-Za-z0-9_-]{0,120}"


def clean(name: str | None, description: str | None, network: str | None = None) -> dict:
    """The ``report`` block stored in results.json: one-line name, multi-line description and the
    network (or site) the data came from, which Compare reports uses to count networks."""
    name = " ".join((name or "").split())[:NAME_MAX]
    lines = [" ".join(ln.split()) for ln in (description or "").replace("\r\n", "\n").split("\n")]
    text = "\n".join(lines).strip()
    text = re.sub(r"\n{3,}", "\n\n", text)[:DESCRIPTION_MAX].strip()
    return {"name": name, "description": text, "network": " ".join((network or "").split())[:NETWORK_MAX]}


def slug(name: str) -> str:
    """Folder-safe form of a report name: ASCII letters, digits, '-' and '_' only."""
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", ascii_name).strip("-_")
    return re.sub(r"-{2,}", "-", s)[:SLUG_MAX].strip("-_")


def stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y-%m-%d_%H-%M-%S")


def new_run(data_dir: str, name: str = "", now: datetime | None = None) -> str:
    """Create and return a new run folder under ``data_dir``.

    Named: "<name>_<timestamp>". Unnamed: the usual random id plus the timestamp."""
    base = f"{slug(name) or secrets.token_hex(8)}_{stamp(now)}"
    for n in range(1, 1000):
        run_id = base if n == 1 else f"{base}-{n}"
        try:
            os.makedirs(os.path.join(data_dir, run_id))
            return run_id
        except FileExistsError:
            continue
    raise RuntimeError("Could not create a run folder")
