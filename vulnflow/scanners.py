"""Scanner detection from traffic, and the optional list of scanners you expect.

A host is called a scanner when the sessions it starts look like probing rather than use:

* it tried at least ``MIN_TARGETS`` different (address, port) pairs, and
* at least ``MIN_FAILED`` of its sessions never completed (no answer, refused or blocked),

or when a Zeek ``Scan::`` notice names it. Every detected scanner is reported. Scanners you run
yourself (vulnerability scanners, monitoring, asset discovery) can be listed in a small file so
they are labelled "expected" instead of being left for review:

    address,name
    10.20.0.15,Nessus
    10.30.0.0/28,Monitoring probes

The header row and the name are optional; ``#`` starts a comment. A file named
``known_scanners.csv`` in an input folder is used automatically (it is not read as telemetry), or
pass one with ``--known-scanners``. The Nessus scanner address found in a scan is always expected.
"""
from __future__ import annotations

import csv
import ipaddress
import os

from .errors import UserError

FILENAME = "known_scanners.csv"
MIN_TARGETS, MIN_FAILED, MAX_LISTED = 100, 0.7, 200
_HEAD = {"address", "ip", "cidr", "range", "scanner", "host"}


def is_list_file(path: str) -> bool:
    return os.path.basename(path).lower() == FILENAME


def read(path: str) -> list[dict]:
    """Return [{cidr, name}] in file order. Raises UserError with the line number."""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for line, row in enumerate(csv.reader(fh), 1):
            cells = [c.strip() for c in row]
            if not any(cells) or cells[0].startswith("#"):
                continue
            if line == 1 and cells[0].lower() in _HEAD:
                continue
            try:
                net = ipaddress.ip_network(cells[0], strict=False)
            except ValueError:
                raise UserError(f"{os.path.basename(path)} line {line}: '{cells[0]}' is not an address "
                                "or address range") from None
            out.append({"cidr": str(net), "name": (cells[1] if len(cells) > 1 else "")[:60]})
    return out


class Known:
    def __init__(self, entries: list[dict] | None = None, nessus: tuple = ()):
        self.nets = [(ipaddress.ip_network(e["cidr"]), e["name"]) for e in entries or ()]
        self.nessus = set(nessus)

    def label(self, ip: str) -> str | None:
        """The name of the expected scanner at this address, '' if listed without one, else None."""
        if ip in self.nessus:
            return "Vulnerability scanner"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        hits = [(net.prefixlen, name) for net, name in self.nets if net.version == addr.version and addr in net]
        return max(hits)[1] if hits else None


def _kind(hosts: int, ports: int) -> str:
    if hosts >= 20 and ports >= 20:
        return "address sweep and port scan"
    return "address sweep" if hosts >= ports else "port scan"


def detect(con, threats, internal, known: Known | None = None) -> list[dict]:
    """Scanners seen in ``flows`` (DuckDB connection) and in Zeek Scan:: notices, busiest first.

    ``internal`` is a callable(ip) -> bool. Each entry: ip, internal, sessions, hosts, ports,
    targets, failed_pct, kind, evidence ("traffic" and/or "notice"), expected, name."""
    known = known or Known()
    found: dict[str, dict] = {}
    for ip, n, hosts, ports, targets, failed in con.execute(f"""
            SELECT src_ip, count(*), count(DISTINCT dst_ip), count(DISTINCT dst_port),
                   count(DISTINCT (dst_ip, dst_port)),
                   count(*) FILTER (NOT (established AND action = 'allow'))
            FROM flows WHERE src_ip <> dst_ip GROUP BY src_ip
            HAVING count(DISTINCT (dst_ip, dst_port)) >= {MIN_TARGETS}
               AND count(*) FILTER (NOT (established AND action = 'allow')) >= {MIN_FAILED} * count(*)
            """).fetchall():
        found[ip] = {"ip": ip, "sessions": int(n), "hosts": int(hosts), "ports": int(ports),
                     "targets": int(targets), "failed_pct": round(100 * failed / n),
                     "kind": _kind(hosts, ports), "evidence": ["traffic"]}
    for t in threats:
        if (t.name or "").startswith("Scan::"):
            e = found.setdefault(t.src_ip, {"ip": t.src_ip, "sessions": 0, "hosts": 0, "ports": 0,
                                            "targets": 0, "failed_pct": None,
                                            "kind": "address sweep" if "Address" in t.name else "port scan",
                                            "evidence": []})
            if "notice" not in e["evidence"]:
                e["evidence"].append("notice")
    for ip, e in found.items():
        name = known.label(ip)
        e.update(internal=bool(internal(ip)), expected=name is not None, name=name or "")
    return sorted(found.values(), key=lambda e: (e["expected"], -e["sessions"], e["ip"]))
