"""Format detection and dispatch."""
from __future__ import annotations

import gzip
import os

from . import filebeat, generic, nessus, paloalto, suricata, zeek

FORMATS = {
    "zeek": ("flows", zeek.parse),
    "filebeat_zeek": ("flows", filebeat.parse),
    "paloalto": ("flows", paloalto.parse),
    "suricata": ("flows", suricata.parse),
    "generic": ("flows", generic.parse),
    "nessus": ("findings", nessus.parse_xml),
    "nessus_csv": ("findings", nessus.parse_csv),
}


def detect(path: str) -> str:
    """Guess a file's format from its first few KB."""
    opener = gzip.open if path.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8-sig", errors="replace") as fh:
        head = fh.read(16384)
    first = next((l for l in head.splitlines() if l.strip()), "")
    low = first.lower()
    if "NessusClientData" in head:
        return "nessus"
    if filebeat.looks_like(head, first):
        return "filebeat_zeek"
    if head.startswith("#separator") or "\n#fields" in head or first.startswith("#fields"):
        return "zeek"
    if first.lstrip().startswith("{") and '"event_type"' in first:
        return "suricata"
    if first.lstrip().startswith("{") and ('"id.orig_h"' in first or '"note"' in first):
        return "zeek"
    if first.lstrip().startswith("{") and (
        ('"ts"' in first and '"uid"' in first)
        or ((os.path.basename(path).lower().endswith((".log", ".log.gz"))
             or '"_path"' in first) and ('"ts"' in first or '"uid"' in first))
    ):
        return "zeek"
    if "plugin id" in low and ("host" in low or "ip address" in low):
        return "nessus_csv"
    if ",TRAFFIC," in head or ",THREAT," in head or ("source address" in low and "destination address" in low):
        return "paloalto"
    return "generic"
