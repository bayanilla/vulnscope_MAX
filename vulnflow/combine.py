"""All networks on one Explorer map, built from a comparison of saved reports (compare.py).

Every compared report that has an Explorer page becomes an island on one map: its subnets, hosts
and the traffic between them, as its own Explorer drew them. Outside addresses are the same in
every network, so they are merged onto the one arc overhead, with beams down to every network they
reached. Hosts with an IOC match or a vulnerability are highlighted, and hosts with an IOC or
vulnerability that the comparison found in more than one report are highlighted more strongly;
the page lists those items, and picking one lights up every host that has it, in every network.

Internal addresses repeat between networks, so each report's hosts, subnets and links are kept
apart: their ids get "@<island>" (the page shows the address without it). The data is each
report's own saved Explorer data (the JSON inside its explorer.html), so nothing is reanalyzed. To
keep one page for many networks quick it is trimmed: the hosts with shared items first, then the
other IOC and vulnerability hosts, then the rest, taken in turn from each report and each in its
report's own risk order, up to ``MAX_NODES``; and the longest lists in a host's card are cut short
(``KEEP``). Each card links to the report's own Explorer for everything.
"""
from __future__ import annotations

import heapq
import json
import os
from collections import defaultdict

from . import saved
from .compare import network_key
from .explore import KIND_RANK, _interleave

MAX_NODES = 3000                 # hosts drawn on the map, over all networks
MAX_LINKS, MAX_SUBNET_LINKS, MAX_RISKY_LINKS = 3000, 800, 300
MAX_INTERNET, MAX_TARGETS = 80, 12
# longest lists kept in a host's card (the report's own Explorer has them all)
KEEP = {"attackers": 24, "peers": 24, "hop2": 6, "ot_events": 3}
KEEP_EXAMPLES, KEEP_WHY, KEEP_EVIDENCE = 1, 2, 3
DRAWER_HOSTS = 60                # related hosts named in an indicator's details


def _sid(value, k: int) -> str:
    return f"{value}@{k}"


def explorer_href(href: str) -> str:
    """Where a report's own Explorer is, from the link the comparison has for the report: the
    upload server's run page (/runs/<id>/) or the page the command line linked to."""
    if href.endswith("/"):
        return href + "explorer.html"
    return href if href.split("#")[0].endswith("explorer.html") else ""


def shared_items(result: dict) -> tuple[list[dict], dict[int, dict[str, list[int]]]]:
    """The IOCs and vulnerabilities seen in more than one report, and for each report (by its
    index in the comparison) which of them each of its hosts has."""
    items: list[dict] = []
    by_host: dict[int, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for kind, rows in (("ioc", result["iocs"]), ("vuln", result["vulns"])):
        for row in rows:
            if row["reports"] < 2:
                continue
            j = len(items)
            if kind == "ioc":
                item = {"k": "ioc", "type": row["type"], "label": row["value"], "key": f"{row['type']}:{row['value']}"}
            else:
                item = {"k": "vuln", "label": row["name"], "key": row["plugin_id"], "sev": row["severity_name"],
                        "cvss": row["cvss"], "cves": row["cves"][:6], "exploit": row["exploit"]}
            item.update(reports=row["reports"], networks=row["networks"], hosts=row["hosts"],
                        seen=[[s["r"], s["hosts"]] for s in row["seen"]])
            items.append(item)
            for s in row["seen"]:
                for host in s["related"]:
                    by_host[s["r"]][host].append(j)
    return items, by_host


def _trim_focus(f: dict, k: int) -> dict:
    """A host's card, its longest lists cut short and its internal addresses kept to its island."""
    def examples(rows):
        return rows[:KEEP_EXAMPLES] if isinstance(rows, list) else []
    atk = [{**a, "connection_examples": examples(a.get("connection_examples")),
            "alert_examples": examples(a.get("alert_examples"))} for a in f.get("attackers", [])[:KEEP["attackers"]]]
    peers = [{**p, "ip": _sid(p["ip"], k), "connection_examples": examples(p.get("connection_examples")),
              "why": p.get("why", [])[:KEEP_WHY]} for p in f.get("peers", [])[:KEEP["peers"]]]
    hop2 = [{**p, "ip": _sid(p["ip"], k), "via": _sid(p["via"], k), "why": p.get("why", [])[:KEEP_WHY]}
            for p in f.get("hop2", [])[:KEEP["hop2"]]]
    findings = [{**x, "evidence": x.get("evidence", [])[:KEEP_EVIDENCE]} for x in f.get("findings", [])]
    return {**f, "attackers": atk, "peers": peers, "hop2": hop2, "findings": findings,
            "attackers_total": f.get("attackers_total", len(f.get("attackers", []))),
            "peers_total": f.get("peers_total", len(f.get("peers", []))),
            "ot_events": f.get("ot_events", [])[:KEEP["ot_events"]]}


class _Inet:
    """One outside address, merged over every network it touched."""
    __slots__ = ("ip", "kind", "sessions", "alerts", "in_sessions", "out_sessions", "out_hosts", "targets", "islands")

    def __init__(self, ip):
        self.ip, self.kind = ip, "blocked"
        self.sessions = self.alerts = self.in_sessions = self.out_sessions = self.out_hosts = 0
        self.targets: list = []
        self.islands: set = set()


def _read_report(row: dict) -> dict:
    """A report's saved Explorer data (SavedRunError when it can't be used)."""
    path = os.path.join(row["folder"], "explorer.html")
    if not os.path.isfile(path):
        raise saved.SavedRunError("it has no Explorer page (explorer.html)")
    return saved.explorer_blob(saved.read_text(path, "explorer.html"), row["generated"])


def _island(data: dict, k: int, shared: dict, iocs: dict) -> dict:
    """One report's Explorer data, kept to island ``k``: its hosts (each with its highlight level and
    trimmed card), links, subnets and the outside addresses its hosts exchanged traffic with."""
    rank = defaultdict(int)
    levels = [0, 0, 0]
    hosts = []
    focus = data["focus"]
    for n in data["nodes"]:
        ip = n["id"]
        sh = sorted(set(shared.get(ip, ())))
        level = 2 if sh else 1 if (n.get("sev") or iocs.get(ip)) else 0
        node = {**n, "id": _sid(ip, k), "subnet": _sid(n.get("subnet") or "other", k), "net": k}
        if sh:
            node["sh"] = sh
        card = _trim_focus(focus[ip], k) if isinstance(focus.get(ip), dict) else None
        hosts.append((level, -rank[level], -k, node, card))   # the report's own risk order within each level
        rank[level] += 1
        levels[level] += 1
    inet: dict[str, _Inet] = {}
    for ip, f in focus.items():           # every host's outside addresses (complete, unlike the top list)
        for a in f.get("attackers", []):
            e = inet.get(a["ip"]) or inet.setdefault(a["ip"], _Inet(a["ip"]))
            if KIND_RANK.get(a["kind"], 9) < KIND_RANK.get(e.kind, 9):
                e.kind = a["kind"]
            e.sessions += a["sessions"] + a["out_sessions"]
            e.in_sessions += a["sessions"]
            e.out_sessions += a["out_sessions"]
            e.out_hosts += a["out_sessions"] > 0
            e.alerts += a["alerts"]
            d = "both" if a["sessions"] and a["out_sessions"] else "out" if a["out_sessions"] else "in"
            e.targets.append([_sid(ip, k), a["kind"], a["sessions"] + a["out_sessions"], d])
            e.islands.add(k)
    return {"hosts": hosts, "levels": levels, "inet": inet,
            "links": [[_sid(a, k), _sid(b, k), w] for a, b, w in data["links"]],
            "risky": [[_sid(a, k), _sid(b, k), w, why, lvl] for a, b, w, why, lvl in data.get("risky_links") or []],
            "sublinks": [[_sid(a, k), _sid(b, k), w, lw] for a, b, w, lw in data.get("subnet_links") or []],
            "subnets": [{**s, "id": _sid(s["id"], k), "net": k} for s in data.get("subnets") or []]}


def build(result: dict, log=None) -> tuple[dict | None, list[dict], list[str]]:
    """The all-networks Explorer data for a comparison, the IOC list for its details drawer, and
    notes on reports that couldn't be drawn. The data is None when no report has an Explorer page."""
    log = log or (lambda _msg: None)
    items, shared_by = shared_items(result)
    ioc_by: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in result["iocs"]:
        for s in row["seen"]:
            for host in s["related"]:
                ioc_by[s["r"]][host] += 1
    notes: list[str] = []
    islands: list[dict] = []           # one per report on the map
    island_of: dict[int, int] = {}     # report index in the comparison -> island
    heap: list = []                    # the MAX_NODES hosts drawn so far, worst on top
    seq = 0
    links, risky, sublinks, subnets = [], [], [], []
    inet: dict[str, _Inet] = {}
    briefs: dict = {}
    counts = {"hosts": 0, "flows": 0, "p1": 0, "alerts": 0}
    window: list = [None, None]
    vuln_data = False
    for r, row in enumerate(result["reports"]):
        log(f"Adding {row['name']} to the all-networks map ...")
        k = len(islands)
        try:
            data = _read_report(row)
            part = _island(data, k, shared_by.get(r, {}), ioc_by.get(r, {}))
            c, w = data.get("counts") or {}, data.get("window") or [None, None]
            report_counts = {key: int(c.get(key) or 0) for key in counts}
        except saved.SavedRunError as exc:
            notes.append(f"{row['name']} isn't on the all-networks map: {str(exc).rstrip('.')}.")
            continue
        except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
            detail = f"missing field {exc}" if isinstance(exc, KeyError) else str(exc)[:200]
            notes.append(f"{row['name']} isn't on the all-networks map: its Explorer data can't be read ({detail}).")
            continue
        for level, neg_rank, neg_k, node, card in part["hosts"]:
            entry = (level, neg_rank, neg_k, seq, node, card)
            seq += 1
            if len(heap) < MAX_NODES:
                heapq.heappush(heap, entry)
            elif entry[:4] > heap[0][:4]:
                heapq.heapreplace(heap, entry)
        links += part["links"]
        risky += part["risky"]
        sublinks += part["sublinks"]
        subnets += part["subnets"]
        for ip, e in part["inet"].items():
            have = inet.get(ip)
            if have is None:
                inet[ip] = e
                continue
            if KIND_RANK.get(e.kind, 9) < KIND_RANK.get(have.kind, 9):
                have.kind = e.kind
            for key in ("sessions", "alerts", "in_sessions", "out_sessions", "out_hosts"):
                setattr(have, key, getattr(have, key) + getattr(e, key))
            have.targets += e.targets
            have.islands |= e.islands
        for key in counts:
            counts[key] += report_counts[key]
        if w[0] and (window[0] is None or w[0] < window[0]):
            window[0] = w[0]
        if len(w) > 1 and w[1] and (window[1] is None or w[1] > window[1]):
            window[1] = w[1]
        vuln_data = vuln_data or data.get("vulnerability_data_available", True) is not False
        if isinstance(data.get("article_briefs"), dict):
            briefs.update(data["article_briefs"])
        island_of[r] = k
        islands.append({"r": r, "name": row["name"], "network": row["network"], "generated": row["generated"],
                        "href": explorer_href(row.get("href") or ""), "hosts": report_counts["hosts"],
                        "nodes": len(part["hosts"]), "drawn": 0, "telemetry_only": bool(row.get("telemetry_only")),
                        "levels": part["levels"]})
        del data, part
    if not islands:
        return None, [], notes

    kept = {}
    for level, _r, _k, _seq, node, card in heap:
        kept[node["id"]] = (node, card)
    order = sorted(heap, key=lambda e: (-e[2], e[3]))      # each island's hosts in their report's order
    nodes = [e[4] for e in order]
    focus = {e[4]["id"]: e[5] for e in order if e[5] is not None}
    for node in nodes:
        islands[node["net"]]["drawn"] += 1
    drawn_in = defaultdict(int)
    for node in nodes:
        drawn_in[node["subnet"]] += 1
    for s in subnets:
        s["drawn"] = drawn_in.get(s["id"], 0)

    # items: which islands each one is on, and how many of its hosts are drawn
    for item in items:
        item["islands"] = sorted({island_of[r] for r, _ in item["seen"] if r in island_of})
        item["drawn"] = 0
    for node in nodes:
        for j in node.get("sh", ()):
            items[j]["drawn"] += 1

    # IOCs: the comparison's (the analyses' own matches and the re-hunt's), on the drawn hosts
    matches, drawer = [], []
    ioc_counts: dict[str, int] = defaultdict(int)
    reports = result["reports"]
    for row in result["iocs"]:
        hosts, named, observed = [], {}, defaultdict(int)
        for s in row["seen"]:
            k = island_of.get(s["r"])
            for label, n in s["observed"].items():
                observed[label] += n
            for host in s["related"]:
                hid = _sid(host, k) if k is not None else None
                if hid in kept:
                    hosts.append(hid)
                    ioc_counts[hid] += 1
                named[f"{host} ({reports[s['r']]['network']})"] = None   # a network's two reports: named once
        named = list(named)
        base = {"id": f"{row['type']}:{row['value']}", "type": row["type"], "value": row["value"],
                "disposition": row.get("disposition") or "", "sources": row.get("sources") or [],
                "articles": row.get("articles") or [], "first_seen": row.get("first_seen") or "",
                "last_seen": row.get("last_seen") or "", "observed": dict(observed), "reports": row["reports"],
                "networks": row["networks"]}
        matches.append({**base, "hosts": hosts})
        more = len(named) - DRAWER_HOSTS
        drawer.append({**base, "hosts": named[:DRAWER_HOSTS] + ([f"and {more:,} more (see comparison.json)"] if more > 0 else [])})

    ioc_ips = {m["value"] for m in matches if m["type"] == "ip"}
    entries = list(inet.values())
    for e in entries:
        e.targets = [t for t in e.targets if t[0] in kept]
    first = sorted((e for e in entries if e.ip in ioc_ips or len(e.islands) > 1),
                   key=lambda e: (e.ip not in ioc_ips, -len(e.islands), KIND_RANK.get(e.kind, 9), -len(e.targets), e.ip))
    picked = {e.ip for e in first}
    rest = [e for e in entries if e.ip not in picked]
    as_row = lambda e: {"ip": e.ip, "dir": _direction(e), "kind": e.kind, "sessions": e.sessions,
                        "out_sessions": e.out_sessions, "out_hosts": e.out_hosts, "targets": e.targets, "e": e}
    by_in = sorted((as_row(e) for e in rest if _direction(e) != "out"),
                   key=lambda x: (KIND_RANK.get(x["kind"], 9), -len(x["targets"]), -x["sessions"], x["ip"]))
    by_out = sorted((as_row(e) for e in rest if e.out_sessions),
                    key=lambda x: (x["kind"] != "alert", -x["out_hosts"], -x["out_sessions"], x["ip"]))
    top = first[:MAX_INTERNET] + [x["e"] for x in _interleave(by_in, by_out, MAX_INTERNET - min(len(first), MAX_INTERNET))]
    internet = []
    for e in top:
        internet.append({"ip": e.ip, "kind": e.kind, "sessions": e.sessions, "alerts": e.alerts,
                         "in_sessions": e.in_sessions, "out_sessions": e.out_sessions, "out_hosts": e.out_hosts,
                         "dir": _direction(e), "hosts_total": len(e.targets), "islands": sorted(e.islands),
                         "targets": _spread(e.targets)})

    names = {network_key(i["network"]) for i in islands}
    when = result["generated"][:10]
    data = {
        "vulnerability_data_available": vuln_data,
        "generated": result["generated"],
        "report": {"name": "All networks",
                   "description": f"{len(islands)} report{'s' if len(islands) != 1 else ''} from {len(names)} "
                                  f"network{'s' if len(names) != 1 else ''}, compared {when}"},
        "window": window, "counts": counts,
        "nodes": nodes,
        "links": sorted((l for l in links if l[0] in kept and l[1] in kept), key=lambda l: -l[2])[:MAX_LINKS],
        "networks": [{"name": i["network"], "type": "report", "cloud": False, "cidr": "", "report": i["name"]}
                     for i in islands],
        "focus": focus,
        "ioc_matches": matches,
        "subnets": sorted(subnets, key=lambda s: s["id"]),
        "subnet_links": sorted(sublinks, key=lambda l: (-l[3], -l[2]))[:MAX_SUBNET_LINKS],
        "risky_links": sorted((l for l in risky if l[0] in kept and l[1] in kept),
                              key=lambda l: (-l[4], -l[2], l[0], l[1]))[:MAX_RISKY_LINKS],
        "internet": internet, "internet_total": len(entries),
        "internet_in_total": sum(_direction(e) != "out" for e in entries),
        "internet_out_total": sum(e.out_sessions > 0 for e in entries),
        "ioc_counts": dict(ioc_counts),
        "article_briefs": briefs,
        "start": None,
        "timeline": None,
        "combined": {"reports": islands, "items": items, "networks": len(names), "notes": notes,
                     # every compared report, by its index in the comparison (items' "seen")
                     "compared": [{"name": rep["name"], "network": rep["network"], "island": island_of.get(i)}
                                  for i, rep in enumerate(result["reports"])],
                     "hosts": sum(i["nodes"] for i in islands), "drawn": len(nodes), "max_nodes": MAX_NODES,
                     "keep": KEEP},
    }
    return data, drawer, notes


def _spread(targets: list) -> list:
    """An outside address's MAX_TARGETS hosts with beams: the worst of each network in turn, so the
    beams reach every network it touched (best first, as the Explorer lists them)."""
    key = lambda t: (KIND_RANK.get(t[1], 9), -t[2], t[0])
    turn: dict[str, int] = defaultdict(int)
    ranked = []
    for i, t in enumerate(sorted(targets, key=key)):
        island = t[0].rsplit("@", 1)[1]
        ranked.append((turn[island], i, t))
        turn[island] += 1
    return [t for _turn, _i, t in sorted(sorted(ranked)[:MAX_TARGETS], key=lambda x: x[1])]


def _direction(e: _Inet) -> str:
    return "both" if e.out_sessions and (e.in_sessions or e.alerts) else "out" if e.out_sessions else "in"


def write(result: dict, outdir: str, log=None) -> dict | None:
    """explorer.html (all networks on one map) and explorer.json (its data) in ``outdir``.
    Returns what the comparison page says about it, or None when no report could be drawn."""
    from . import explore
    data, drawer, notes = build(result, log)
    if data is None:
        for name in ("explorer.html", "explorer.json"):          # an earlier comparison's, in a reused folder
            try:
                os.remove(os.path.join(outdir, name))
            except OSError:
                pass
        return {"file": None, "notes": notes} if notes else None
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "explorer.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    with open(os.path.join(outdir, "explorer.html"), "w", encoding="utf-8") as fh:
        fh.write(explore.html(data, ioc_drawer=drawer))
    c = data["combined"]
    return {"file": "explorer.html", "data": "explorer.json", "reports": len(c["reports"]),
            "networks": c["networks"], "hosts": c["hosts"], "drawn": c["drawn"], "notes": notes}
