"""Network map: name address ranges (for example the AWS VPCs) so reports and the Explorer can tell
cloud hosts from on-prem ones.

The map is a small CSV with a header row:

    cidr,name,type
    10.40.0.0/16,HQ,on-prem
    10.60.0.0/16,AWS prod (us-east-2),aws

``type`` is free text; ``aws``, ``azure``, ``gcp`` and ``cloud`` are drawn as cloud networks. When
ranges overlap, the most specific one wins. A file named ``network_map.csv`` in an input folder is
used automatically (it is not read as telemetry), or pass one with ``--network-map``.
"""
from __future__ import annotations

import csv
import ipaddress
import os

from .errors import UserError

FILENAME = "network_map.csv"
CLOUD_TYPES = {"aws", "azure", "gcp", "cloud", "oci"}
_HEADERS = {"cidr": ("cidr", "range", "network", "subnet", "prefix"),
            "name": ("name", "label", "network_name", "site"),
            "type": ("type", "kind", "location", "environment")}


def is_map_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def read(path: str) -> list[dict]:
    """Return [{cidr, name, type, cloud}] in file order. Raises UserError with the line number."""
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        raise UserError(f"{os.path.basename(path)} is empty; expected a header row: cidr,name,type")
    head = [h.strip().lower() for h in rows[0]]
    idx = {k: next((head.index(a) for a in aliases if a in head), None) for k, aliases in _HEADERS.items()}
    if idx["cidr"] is None or idx["name"] is None:
        raise UserError(f"{os.path.basename(path)} needs 'cidr' and 'name' columns; header was: {', '.join(head)}")
    out = []
    for line, row in enumerate(rows[1:], 2):
        if not any(c.strip() for c in row) or row[0].lstrip().startswith("#"):
            continue
        get = lambda k: row[idx[k]].strip() if idx[k] is not None and idx[k] < len(row) else ""
        try:
            net = ipaddress.ip_network(get("cidr"), strict=False)
        except ValueError:
            raise UserError(f"{os.path.basename(path)} line {line}: '{get('cidr')}' is not an address range") from None
        name = get("name") or str(net)
        kind = get("type").lower() or "on-prem"
        out.append({"cidr": str(net), "name": name[:60], "type": kind[:20], "cloud": kind in CLOUD_TYPES})
    return out


class NetMap:
    def __init__(self, entries: list[dict]):
        self.entries = entries
        self._nets = sorted(((ipaddress.ip_network(e["cidr"]), i) for i, e in enumerate(entries)),
                            key=lambda x: -x[0].prefixlen)
        self._cache: dict[str, int | None] = {}

    def __bool__(self):
        return bool(self.entries)

    def index(self, ip: str) -> int | None:
        """Index of the most specific range containing ip, or None."""
        if ip not in self._cache:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                self._cache[ip] = None
                return None
            self._cache[ip] = next((i for n, i in self._nets if addr.version == n.version and addr in n), None)
        return self._cache[ip]

    def name(self, ip: str) -> str:
        i = self.index(ip)
        return self.entries[i]["name"] if i is not None else ""


def summarize(entries: list[dict], res: dict, scanned: list[str]) -> list[dict]:
    """Per-network host counts for the reports, in map order, plus an 'Unmapped' row if needed."""
    nm = NetMap(entries)
    rows = [{"name": e["name"], "type": e["type"], "cloud": e["cloud"], "ranges": [], "scanned": 0,
             "with_findings": 0, "p1": 0} for e in entries]
    by_name: dict[str, dict] = {}
    for e, r in zip(entries, rows):
        by_name.setdefault(e["name"], r)["ranges"].append(e["cidr"])
    other = {"name": "Unmapped", "type": "", "cloud": False, "ranges": [], "scanned": 0, "with_findings": 0, "p1": 0}
    pick = lambda ip: by_name.get(nm.name(ip)) or other
    for ip in scanned:
        pick(ip)["scanned"] += 1
    for h in res["hosts"]:
        row = pick(h["host"])
        row["with_findings"] += h.get("findings", 0) > 0
        row["p1"] += h.get("priority") == "P1"
    out = list(by_name.values()) + ([other] if other["scanned"] or other["with_findings"] else [])
    return out
