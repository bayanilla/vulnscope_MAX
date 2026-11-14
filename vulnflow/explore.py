"""Data and page for the host explorer: a logical graph of scanned or observed hosts.

Click a host and the view flies in on it. On the left is all of its north/south traffic: every outside
address that reached, tried to reach, or was contacted by it (with firewall and IPS outcome). On the
right is all of its east/west traffic: every internal host it exchanged traffic with in either direction,
including failed attempts, with an estimate of how likely each one is to be compromised next if this
host is exploited.

The estimate is a heuristic built only from observed traffic and scan results (see `_reach`). It ranks
where to look; it is not a probability of compromise and it never confirms one.
"""
from __future__ import annotations

import ipaddress
import json
import os
from collections import defaultdict
from datetime import datetime

from .correlate import LATERAL_PORTS, Config, _Net
from .store import naive, utc

STATIC = os.path.join(os.path.dirname(__file__), "static")
MAX_HOP2, MAX_NODES = 30, 2000
MAX_SUBNET_LINKS, MAX_RISKY_LINKS, MAX_INTERNET, MAX_INTERNET_TARGETS = 600, 200, 80, 12
MAX_CONNECTION_EXAMPLES, MAX_OT_EVENTS_PER_HOST = 6, 40
# Timeline view: individual flows drawn at their timestamps. Large runs keep flagged flows (to/from an
# alert or IOC address, then blocked) up to half the cap, sampled over the whole run, and fill the rest
# with a fixed random sample (see _timeline).
MAX_TIMELINE_FLOWS, MAX_TIMELINE_ALERTS, MAX_TIMELINE_IOC_LOOKUPS = 20_000, 200, 400
SEV_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEV = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _band(p: float) -> str:
    return "High" if p >= 0.6 else "Medium" if p >= 0.35 else "Low"


def _subnet(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 64}", strict=False))


class _Pair:
    __slots__ = ("sessions", "established", "blocked", "ports", "tried", "bytes", "first", "last",
                 "first_est", "last_est", "examples")

    def __init__(self):
        self.sessions = self.established = self.blocked = self.bytes = 0
        self.ports: set = set()       # ports with completed sessions
        self.tried: set = set()       # every port seen, including blocked attempts
        self.first = self.last = None
        self.first_est = self.last_est = None     # completed sessions only
        self.examples: list[dict] = []


def _pairs(ds) -> dict[tuple, _Pair]:
    """Per (source, destination) connection rollup, aggregated in DuckDB."""
    con = ds.flow_store().con
    pairs: dict[tuple, _Pair] = {}
    cur = con.cursor()
    cur.execute("""
        SELECT src_ip, dst_ip, count(*), count(*) FILTER (action = 'allow' AND established),
               count(*) FILTER (action <> 'allow'),
               list(DISTINCT dst_port) FILTER (dst_port IS NOT NULL),
               list(DISTINCT dst_port) FILTER (dst_port IS NOT NULL AND action = 'allow' AND established),
               coalesce(sum(bytes_out + bytes_in), 0), min(ts), max(ts),
               min(ts) FILTER (action = 'allow' AND established), max(ts) FILTER (action = 'allow' AND established)
        FROM flows WHERE src_ip <> dst_ip GROUP BY src_ip, dst_ip ORDER BY min(seq)""")
    while rows := cur.fetchmany(10_000):
        for src, dst, n, est, blocked, tried, ports, nbytes, first, last, first_est, last_est in rows:
            p = _Pair()
            p.sessions, p.established, p.blocked, p.bytes = int(n), int(est), int(blocked), int(nbytes)
            p.tried, p.ports = set(tried or ()), set(ports or ())
            p.first, p.last = utc(first), utc(last)
            p.first_est, p.last_est = utc(first_est), utc(last_est)
            pairs[(src, dst)] = p
    # Examples: the first distinct connections of each pair, in time order. A sorted scan
    # (which DuckDB spills to disk) keeps memory flat; a window function per pair does not.
    cur.execute("""
        SELECT src_ip, dst_ip, src_port, dst_port, proto, app, action, established, source
        FROM flows WHERE src_ip <> dst_ip ORDER BY src_ip, dst_ip, seq""")
    p = None
    while rows := cur.fetchmany(10_000):
        for src, dst, sport, dport, proto, app, action, est, source in rows:
            if p is None or p_key != (src, dst):
                p_key = (src, dst)
                p = pairs[p_key]
            if len(p.examples) >= MAX_CONNECTION_EXAMPLES:
                continue
            ex = {"src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "proto": proto,
                  "app": app, "action": action, "established": est, "source": source}
            if ex not in p.examples:
                p.examples.append(ex)
    cur.close()
    return pairs


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def _parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _vuln_services(res: dict) -> dict[str, list[tuple]]:
    """host -> [(port, proto, window start, window end)] for each port-level finding.

    The window is the scan window the correlator used for that finding (None = all telemetry), so
    the explorer marks the same traffic as "reached a vulnerable service" that the report counts."""
    out = defaultdict(list)
    for r in res["findings"]:
        if not r.get("port"):
            continue
        exp = r.get("exposure") or {}
        for w in exp.get("windows") or [exp.get("window") or {}]:
            out[r["host"]].append((r["port"], r.get("proto") or "tcp", _parse_iso(w.get("start")), _parse_iso(w.get("end"))))
    return out


def _hits_service(services, port, proto, ts) -> bool:
    return any(port == p and proto == pr and (lo is None or ts is None or lo <= ts <= hi)
               for p, pr, lo, hi in services)


def _returned(inbound, outbound) -> bool:
    """The host connected back out to an outside address after that address reached it, the same
    ordering the report uses for return-connection leads (untimed sessions are not ruled out)."""
    if not (inbound and inbound.established and outbound and outbound.established):
        return False
    return inbound.first_est is None or outbound.last_est is None or outbound.last_est >= inbound.first_est


def _vuln_hits(ds, services: dict, scanners=()) -> dict[tuple, set]:
    """(source, host) -> {(port, proto)}: completed sessions onto a vulnerable service, matched on
    port, protocol and the finding's scan window exactly as the report does. Probes from the
    vulnerability scanner itself are not counted, as in the report."""
    rows = [(h, p, pr, naive(lo), naive(hi)) for h, svcs in services.items() for p, pr, lo, hi in svcs]
    if not rows:
        return {}
    store = ds.flow_store()
    store.insert_rows("explore_vkeys", {"host": "VARCHAR", "port": "INTEGER", "proto": "VARCHAR",
                                        "lo": "TIMESTAMP", "hi": "TIMESTAMP"}, set(rows))
    hits = defaultdict(set)
    for src, dst, port, proto in store.con.execute("""
            SELECT DISTINCT f.src_ip, f.dst_ip, f.dst_port, f.proto FROM flows f JOIN explore_vkeys k
              ON f.dst_ip = k.host AND f.dst_port = k.port AND f.proto = k.proto
             AND (k.lo IS NULL OR f.ts IS NULL OR f.ts BETWEEN k.lo AND k.hi)
            WHERE f.action = 'allow' AND f.established AND f.src_ip <> f.dst_ip
              AND NOT list_contains(?, f.src_ip)""", [list(scanners)]).fetchall():
        hits[(src, dst)].add((port, proto))
    store.con.execute("DROP TABLE explore_vkeys")
    return hits


def build(res: dict, ds, cfg: Config | None = None) -> dict:
    cfg = cfg or Config(internal_nets=res["config"]["internal_nets"])
    net = _Net(cfg.internal_nets)
    telemetry_only = not res["summary"].get("vulnerability_data_available", True)
    pairs = _pairs(ds)
    out_of, in_to = defaultdict(set), defaultdict(set)
    for s, d in pairs:
        out_of[s].add(d)
        in_to[d].add(s)

    findings = defaultdict(list)
    for r in res["findings"]:
        findings[r["host"]].append(r)
    services = _vuln_services(res)
    scanners = set(res["summary"].get("scanner_ips") or ())
    vhits = _vuln_hits(ds, services, scanners)
    hostinfo = {h["host"]: h for h in res["hosts"]}
    alerts = defaultdict(lambda: defaultdict(list))
    for t in ds.threats:
        alerts[t.dst_ip][t.src_ip].append(t)
        if net.internal(t.src_ip) and not net.internal(t.dst_ip):
            alerts[t.src_ip][t.dst_ip].append(t)     # internal host set off an alert going out (e.g. a beacon)
    ot_by_host = defaultdict(list)
    ot_counts = defaultdict(int)
    for event in ds.ot_events:
        row = {"ts": _iso(event.ts), "src_ip": event.src_ip, "dst_ip": event.dst_ip,
               "originator": event.fields.get("id.orig_h"), "responder": event.fields.get("id.resp_h"),
               "protocol": event.protocol, "operation": event.operation,
               "message_side": event.direction, "source": event.source}
        for host in {event.src_ip, event.dst_ip, row["originator"], row["responder"]} - {None, ""}:
            ot_counts[host] += 1
            if len(ot_by_host[host]) < MAX_OT_EVENTS_PER_HOST:
                ot_by_host[host].append(row)

    def ext(ip):
        try:
            return not net.internal(ip)
        except ValueError:
            return False

    def reach(a: str, b: str) -> dict:
        """How easily someone in control of `a` could compromise `b`, from what was observed."""
        fwd, back = pairs.get((a, b)), pairs.get((b, a))
        if telemetry_only:
            return {"p": 0.0, "why": ["Vulnerability status unknown; observed connections do not establish compromise likelihood."]}
        why = []
        if fwd and fwd.established:
            r = 1.0
            why.append(f"{a} opened {fwd.established} session(s) to it on "
                       + ", ".join(str(p) for p in sorted(fwd.ports)[:6]))
        elif back and back.established:
            r = 0.35
            why.append(f"only {b} connects to {a}; an attacker would have to wait for or ride those sessions")
        else:
            return {"p": 0.0, "why": ["no completed sessions between them"]}
        used = fwd.ports if fwd else set()
        hit = vhits.get((a, b), set())        # port, protocol and scan window all match
        best, v = None, 0.1
        for fd in findings.get(b, []):
            cv = (fd["cvss"] or 0) / 10
            if fd["port"] and (fd["port"], fd["proto"]) in hit:
                s = cv * (1.0 if fd["exploit_available"] else 0.55)
                tag = f"vulnerable service {fd['port']}/{fd['proto']} is the one {a} already reaches"
            elif fd["severity"] >= 3:
                s = cv * (0.45 if fd["exploit_available"] else 0.25)
                tag = f"{fd['severity_name']} finding on another service ({fd['plugin_name'][:60]})"
            else:
                continue
            if s > v:
                v, best = s, (tag, fd)
        if best:
            why.append(best[0] + (", public exploit" if best[1]["exploit_available"] else ""))
        admin = sorted({LATERAL_PORTS[p] for p in used if p in LATERAL_PORTS})
        if admin and 0.5 > v:
            v = 0.5
            why.append(f"admin/lateral protocol in use ({', '.join(admin)}): stolen credentials would carry over")
        elif admin:
            why.append(f"admin/lateral protocol in use ({', '.join(admin)})")
        if b not in hostinfo:
            v = max(v, 0.3)
            why.append("not in the vulnerability scan, so its weaknesses are unknown")
        return {"p": round(min(1.0, r * v), 2), "why": why}

    scanned = [h["host"] for h in res["hosts"]]
    nodes: dict[str, dict] = {}
    from .netmap import NetMap
    netmap = NetMap(res.get("network_map", []))

    def node(ip):
        if ip in nodes:
            return nodes[ip]
        h = hostinfo.get(ip)
        fl = findings.get(ip, [])
        worst = max((r["severity"] for r in fl), default=-1)
        ev = ("likely" if any(i["confidence"] == "corroborated" for r in fl for i in r["indicators"])
              else "lead" if any(r["indicators"] for r in fl) else "")
        name = (h or {}).get("hostname", "") or ("Vulnerability scanner" if ip in scanners else "")
        nodes[ip] = {"id": ip, "name": name, "scanned": ip in ds.scanned_hosts,
                     "observed": h is not None,
                     "subnet": _subnet(ip), "sev": SEV.get(worst, ""), "pri": (h or {}).get("priority", ""),
                     "score": (h or {}).get("max_score", 0), "ev": ev, "os": (h or {}).get("os", "") or ""}
        if netmap and netmap.index(ip) is not None:
            nodes[ip]["net"] = netmap.index(ip)
        return nodes[ip]

    focus = {}
    for ip in scanned:
        node(ip)
        # north/south: every outside address this host exchanged traffic with, in either direction
        atk = []
        for src in in_to.get(ip, set()) | out_of.get(ip, set()):
            if not ext(src):
                continue
            p, back = pairs.get((src, ip)), pairs.get((ip, src))
            al = alerts[ip].get(src, [])
            open_al = [t for t in al if not t.blocked]
            hit = sorted({port for port, _ in vhits.get((src, ip), ())}) if p else []
            if p:
                kind = ("alert" if open_al else "vuln" if hit else "reached" if p.established
                        else "blocked" if p.blocked else "attempt")
            else:
                kind = "alert" if open_al else "outbound"
            span = [x for x in (p, back) if x]
            first = min((x.first for x in span if x.first), default=None)
            last = max((x.last for x in span if x.last), default=None)
            atk.append({"ip": src, "kind": kind, "dir": "both" if p and back else "in" if p else "out",
                        "sessions": p.sessions if p else 0, "established": p.established if p else 0,
                        "blocked": p.blocked if p else 0, "ports": sorted(p.tried)[:8] if p else [],
                        "vuln_ports": hit,
                        "out_sessions": back.sessions if back else 0,
                        "out_established": back.established if back else 0,
                        "out_ports": sorted(back.tried)[:8] if back else [],
                        "connection_examples": (p.examples if p else []) + (back.examples if back else []),
                        "alerts": len(open_al), "alerts_blocked": len(al) - len(open_al),
                        "alerts_in": sum(t.src_ip == src for t in al),
                        "alert_examples": [{"src_ip": t.src_ip, "dst_ip": t.dst_ip,
                                            "dst_port": t.dst_port, "name": t.name,
                                            "blocked": t.blocked} for t in al[:MAX_CONNECTION_EXAMPLES]],
                        "signatures": sorted({t.name for t in al})[:3],
                        "returned": _returned(p, back),
                        "first": _iso(first), "last": _iso(last)})
        known_outside = {a["ip"] for a in atk}
        for src, al in alerts[ip].items():           # IPS-only sources with no flow in either direction
            if ext(src) and src not in known_outside:
                open_al = [t for t in al if not t.blocked]
                atk.append({"ip": src, "kind": "alert" if open_al else "blocked",
                            "dir": "out" if all(t.src_ip == ip for t in al) else "in", "sessions": 0,
                            "established": 0, "blocked": 0, "ports": sorted({t.dst_port for t in al if t.dst_port})[:8],
                            "vuln_ports": [], "out_sessions": 0, "out_established": 0, "out_ports": [],
                            "connection_examples": [],
                            "alerts": len(open_al), "alerts_blocked": len(al) - len(open_al),
                            "alerts_in": sum(t.src_ip == src for t in al),
                            "alert_examples": [{"src_ip": t.src_ip, "dst_ip": t.dst_ip,
                                                "dst_port": t.dst_port, "name": t.name,
                                                "blocked": t.blocked} for t in al[:MAX_CONNECTION_EXAMPLES]],
                            "signatures": sorted({t.name for t in al})[:3], "returned": False,
                            "first": None, "last": None})
        rank = {"alert": 0, "vuln": 1, "reached": 2, "outbound": 3, "attempt": 4, "blocked": 5}
        atk.sort(key=lambda a: (rank[a["kind"]], -a["alerts"], -a["alerts_blocked"], -a["established"],
                                -a["sessions"] - a["out_sessions"], a["ip"]))
        n_ext = len(atk)

        # east/west: every internal peer in either direction (failed attempts too), then onward peers
        peers = []
        for other in (out_of.get(ip, set()) | in_to.get(ip, set())):
            if ext(other):
                continue
            o, i = pairs.get((ip, other)), pairs.get((other, ip))
            ok = bool((o and o.established) or (i and i.established))
            if ok:
                est = reach(ip, other)
            else:
                tries = (o.sessions if o else 0) + (i.sessions if i else 0)
                est = {"p": 0.0, "why": [f"{tries} attempt(s), none completed: no working path seen"]}
            node(other)
            peers.append({"ip": other, "out": o.established if o else 0, "in": i.established if i else 0,
                          "out_tries": o.sessions if o else 0, "in_tries": i.sessions if i else 0,
                          "ports_out": sorted(o.ports if ok else o.tried)[:8] if o else [],
                          "ports_in": sorted(i.ports if ok else i.tried)[:8] if i else [],
                          "connection_examples": (o.examples if o else []) + (i.examples if i else []),
                          "p": est["p"], "band": ("Unknown" if telemetry_only else _band(est["p"])) if ok else "None", "why": est["why"]})
        peers.sort(key=lambda p: (-p["p"], p["band"] == "None", -(p["out"] + p["in"]),
                                  -(p["out_tries"] + p["in_tries"]), p["ip"]))
        n_peers = len(peers)
        hop1 = {p["ip"]: p["p"] for p in peers}
        hop2 = {}
        for mid, p1 in hop1.items():
            if p1 <= 0:
                continue
            for nxt in out_of.get(mid, ()):
                if nxt == ip or nxt in hop1 or ext(nxt) or not pairs.get((mid, nxt)).established:
                    continue
                est = reach(mid, nxt)
                p2 = round(p1 * est["p"], 2)
                if p2 > hop2.get(nxt, {}).get("p", -1):
                    hop2[nxt] = {"ip": nxt, "via": mid, "p": p2, "band": _band(p2),
                                 "why": [f"via {mid} ({p1:.2f})"] + est["why"]}
        h2 = sorted((p for p in hop2.values() if p["p"] >= 0.05), key=lambda p: (-p["p"], p["ip"]))[:MAX_HOP2]
        for p in h2:
            node(p["ip"])
        focus[ip] = {
            "attackers": atk, "attackers_total": n_ext, "peers": peers, "peers_total": n_peers, "hop2": h2,
            "ot_events": ot_by_host.get(ip, []), "ot_events_total": ot_counts[ip],
            "findings": [{"pri": r["priority"], "score": r["score"], "name": r["plugin_name"],
                          "port": r["port"], "proto": r["proto"], "sev": r["severity_name"], "cvss": r["cvss"],
                          "cves": r["cves"][:4], "exploit": r["exploit_available"],
                          "exposure": r["exposure"]["label"],
                          "evidence": [{"c": i["confidence"], "t": i["text"]} for i in r["indicators"]]}
                         for r in findings.get(ip, [])],
            "blast": {"high": sum(p["band"] == "High" for p in peers),
                      "medium": sum(p["band"] == "Medium" for p in peers),
                      "low": sum(p["band"] == "Low" for p in peers)},
        }

    # overview edges: internal pairs touching at least one node we keep
    # Past MAX_NODES, draw the riskiest hosts: evidence first, then priority and score. Sorting by
    # address alone would drop whole ranges (for example cloud subnets that sort after on-prem).
    # Then hosts in IPS/IDS alerts, OT devices and the busiest hosts, so telemetry-only runs (no
    # priorities or scores) do not fall back to address order and drop alerted hosts and PLCs.
    ev_rank = {"likely": 0, "lead": 1}
    alerted = {ip for t in ds.threats for ip in (t.src_ip, t.dst_ip)}
    ot_hosts = {ip for ip, c in ot_counts.items() if c}

    def activity(n):
        h = hostinfo.get(n) or {}
        return (h.get("inbound_flows") or 0) + (h.get("outbound_flows") or 0)
    keep = sorted(nodes, key=lambda n: (not nodes[n]["observed"], ev_rank.get(nodes[n]["ev"], 2),
                                        nodes[n]["pri"] or "P9", -(nodes[n]["score"] or 0),
                                        n not in alerted, n not in ot_hosts, -activity(n), n))[:MAX_NODES]
    kept = set(keep)
    links = {}
    for (s, d), p in pairs.items():
        if p.established and s in kept and d in kept:
            k = tuple(sorted((s, d)))
            links[k] = links.get(k, 0) + p.established
    ext_count = {ip: focus[ip]["attackers_total"] for ip in focus}
    ext_alert = {ip: any(a["kind"] == "alert" for a in focus[ip]["attackers"]) for ip in focus}
    for n in keep:
        nodes[n]["ext"] = ext_count.get(n, 0)
        nodes[n]["alert"] = ext_alert.get(n, False)
    overview = _overview_summary(pairs, nodes, focus, kept, ext)
    ioc_by_host = defaultdict(set)
    for match in res.get("ioc_matches", []):
        for host in match.get("hosts", []):
            if host in focus:
                ioc_by_host[host].add(match["id"])
    timeline = _timeline(ds, res, keep, ext, services, pairs, scanners)
    s = res["summary"]
    return {
        "vulnerability_data_available": not telemetry_only,
        "generated": res["generated"], "report": res.get("report") or {"name": "", "description": ""},
        "window": [s.get("window_start"), s.get("window_end")],
        "counts": {"hosts": len(scanned) if telemetry_only else res["coverage"]["scanned_hosts"], "flows": s["flows"], "p1": s["priority_counts"]["P1"],
                   "alerts": s.get("threat_alerts", 0)},
        "nodes": [nodes[n] for n in keep],
        "links": [[a, b, w] for (a, b), w in sorted(links.items(), key=lambda kv: -kv[1])[:3000]],
        # the page expects every focusable host to be drawn
        "networks": [{"name": e["name"], "type": e["type"], "cloud": e["cloud"], "cidr": e["cidr"]}
                     for e in res.get("network_map", [])],
        "focus": {ip: f for ip, f in focus.items() if ip in kept}, "ioc_matches": res.get("ioc_matches", []), **overview,
        "ioc_counts": {host: len(ids) for host, ids in ioc_by_host.items()},
        "article_briefs": res.get("article_briefs", {}),
        "start": (keep[0] if telemetry_only and keep else res["hosts"][0]["host"] if res["hosts"] else None),
        "timeline": timeline,
    }


def _hours(ts, t0) -> float:
    return round((ts - t0).total_seconds() / 3600, 4)


def _even(items: list, n: int) -> list:
    """`n` items picked at even steps through `items`, so a time-sorted list keeps its whole span."""
    if len(items) <= n:
        return list(items)
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def _spread(items: list, cap: int, favour=None, key=lambda x: x[0]) -> list:
    """At most `cap` of the time-sorted `items`, spread over the whole run instead of the earliest ones.
    Items for which `favour` is true are kept first (themselves spread if there are more than `cap`)."""
    if len(items) <= cap:
        return list(items)
    fav = [x for x in items if favour(x)] if favour else []
    if len(fav) >= cap:
        return _even(fav, cap)
    rest = [x for x in items if not favour(x)] if favour else items
    return sorted(fav + _even(rest, cap - len(fav)), key=key)


def _timeline(ds, res: dict, keep: list, ext, services: dict, pairs: dict, scanners=frozenset()) -> dict | None:
    """Flows, IPS alerts and IOC lookups in time order for the Timeline view.

    Hosts are referenced by their index in ``nodes`` (>= 0), as len(nodes) + i into ``more`` for internal
    hosts the network view leaves out (so their traffic is still drawn), or as -(index + 1) into ``ext``
    for outside addresses. Flow flags: 1 blocked or failed, 2 to/from an IPS-alert or IOC address, 4 onto
    a port with a known vulnerability on the destination host.

    Large runs are sampled: flows to/from an alert or IOC address first, then blocked flows, up to half
    the budget, each tier sampled at random over the whole run (never just the earliest); the rest is a
    random sample of everything else. ``hist`` then counts every flow per time bucket so the page can say
    how many flows a stretch of time really had. Alerts and IOC lookups beyond their caps are thinned
    evenly over the run, keeping alerts that were not blocked first. Alerts with no timestamp of their
    own are listed apart (``untimed``) rather than placed at a guessed time."""
    con = ds.flow_store().con
    row = con.execute("SELECT count(*), min(ts), max(ts) FROM flows WHERE ts IS NOT NULL AND src_ip <> dst_ip").fetchone()
    total, t0, t1 = int(row[0] or 0), utc(row[1]), utc(row[2])
    if not total or t0 is None:
        return None
    t0 = t0.replace(microsecond=0)          # t0 is sent to the page to the second; hours are counted from it
    idx = {ip: i for i, ip in enumerate(keep)}
    ext_idx: dict[str, int] = {}
    more_idx: dict[str, int] = {}

    def ref(ip):
        if ip in idx:
            return idx[ip]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if ext(ip):
            if ip not in ext_idx:
                ext_idx[ip] = len(ext_idx)
            return -(ext_idx[ip] + 1)
        if ip not in more_idx:
            more_idx[ip] = len(more_idx)
        return len(keep) + more_idx[ip]

    flagged = {t.src_ip for t in ds.threats if ext(t.src_ip)}
    flagged |= {m["value"] for m in res.get("ioc_matches", []) if m.get("type") == "ip"}
    cols = "ts, src_ip, dst_ip, dst_port, action, established, proto"
    base = "FROM flows WHERE ts IS NOT NULL AND src_ip <> dst_ip"
    hot = "(list_contains(?, src_ip) OR list_contains(?, dst_ip))"
    fl = sorted(flagged)
    cur = con.cursor()
    sampled = total > MAX_TIMELINE_FLOWS
    hist = None
    if not sampled:
        cur.execute(f"SELECT {cols} {base} ORDER BY seq")
    else:
        half = MAX_TIMELINE_FLOWS // 2
        tiers = [(f"{hot}", [fl, fl]), (f"action <> 'allow' AND NOT {hot}", [fl, fl]),
                 (f"action = 'allow' AND NOT {hot}", [fl, fl])]
        counts = [int(con.execute(f"SELECT count(*) {base} AND {w}", a).fetchone()[0]) for w, a in tiers]
        take = [min(counts[0], half)]
        take.append(min(counts[1], half - take[0]))
        take.append(min(counts[2], MAX_TIMELINE_FLOWS - take[0] - take[1]))
        parts, args = [], []
        for (w, a), n, k in zip(tiers, counts, take):
            if not k:
                continue
            sample = "" if k >= n else f" USING SAMPLE reservoir({k} ROWS) REPEATABLE (7)"
            parts.append(f"SELECT * FROM (SELECT {cols}, seq {base} AND {w}){sample}")
            args += a
        cur.execute(" UNION ALL ".join(parts) + " ORDER BY seq", args)
        # every flow, counted per bucket of time, so a window's real total can be shown next to the sample
        hours = (t1 - t0).total_seconds() / 3600
        bw = max(0.25, hours / 2000)
        rows = con.execute(f"SELECT CAST(floor((epoch(ts) - ?) / ?) AS BIGINT) AS b, count(*) {base} GROUP BY b ORDER BY b",
                           [t0.timestamp(), bw * 3600]).fetchall()
        hist = {"bucket": round(bw, 4), "counts": [[int(b), int(n)] for b, n in rows]}
    flows, hidden = [], 0
    while rows := cur.fetchmany(10_000):
        for r in rows:
            ts, src, dst, port, action, est, proto = r[:7]
            s, d = ref(src), ref(dst)
            if s is None or d is None:
                hidden += 1
                continue
            f = (1 if action != "allow" or est is False else 0) | (2 if src in flagged or dst in flagged else 0) \
                | (4 if port and src not in scanners and _hits_service(services.get(dst, ()), port, proto, utc(ts)) else 0)
            flows.append([_hours(utc(ts), t0), s, d, port or 0, f])
    cur.close()

    def dst_ref(ip):
        r = ref(ip)
        return -1 if r is None or r < 0 else r
    timed, untimed = [], []
    for t in ds.threats:
        (timed.append((utc(t.ts), t)) if t.ts else untimed.append(t))
    timed.sort(key=lambda x: x[0])
    alerts = [[_hours(ts, t0), dst_ref(t.dst_ip), t.src_ip, t.name, t.blocked]
              for ts, t in _spread(timed, MAX_TIMELINE_ALERTS, favour=lambda x: not x[1].blocked)]
    no_time = [[dst_ref(t.dst_ip), t.src_ip, t.name, t.blocked] for t in untimed[:MAX_TIMELINE_ALERTS]]
    domains = {m["value"].lower() for m in res.get("ioc_matches", []) if m.get("type") == "domain"}
    found = []
    if domains:
        for e in ds.zeek_events:
            q = str((e.fields or {}).get("query") or "").lower().rstrip(".")
            if e.ts and q in domains:
                r = ref(e.src_ip)
                if r is not None and r >= 0:
                    found.append((utc(e.ts), r, q))
        found.sort(key=lambda x: x[0])
    lookups = [[_hours(ts, t0), r, q] for ts, r, q in _spread(found, MAX_TIMELINE_IOC_LOOKUPS)]
    return {"t0": _iso(t0), "hours": _hours(t1, t0), "total": total, "sampled": sampled, "hist": hist,
            "hidden": hidden, "flows": flows,
            "ext": [[ip, ip in flagged] for ip in ext_idx], "more": [[ip, _subnet(ip)] for ip in more_idx],
            "alerts": alerts, "alerts_total": len(timed), "untimed": no_time, "untimed_total": len(untimed),
            "ioc_lookups": lookups, "ioc_lookups_total": len(found)}


KIND_RANK = {"alert": 0, "vuln": 1, "reached": 2, "outbound": 3, "attempt": 4, "blocked": 5}


def _interleave(by_in: list, by_out: list, cap: int) -> list:
    """Two inbound entries, then one outbound, until `cap`; whichever list runs out first leaves its
    slots to the other. An address in both lists is kept once, where it first comes up."""
    top, seen, i, o = [], set(), 0, 0
    while len(top) < cap and (i < len(by_in) or o < len(by_out)):
        take_out = o < len(by_out) and (len(top) % 3 == 2 or i >= len(by_in))
        if take_out:
            e, o = by_out[o], o + 1
        else:
            e, i = by_in[i], i + 1
        if e["ip"] not in seen:
            seen.add(e["ip"])
            top.append(e)
    return top


def _overview_summary(pairs, nodes, focus, kept, ext) -> dict:
    """Overview aggregates. Subnet totals and subnet-to-subnet traffic cover every host and pair,
    so they stay complete when the host graph is capped at MAX_NODES. Host-level links are kept
    only for risky paths (admin/lateral protocols, or completed sessions into a P1 or a host with
    exploitation evidence), and outside addresses are ranked by how they touched the network."""
    subnets = {}
    for ip, n in nodes.items():
        if ext(ip):
            continue
        sn = subnets.setdefault(n["subnet"], {"id": n["subnet"], "hosts": 0, "drawn": 0, "p1": 0, "likely": 0,
                                               "lead": 0, "max_score": 0, "exposed": 0, "alert_hosts": 0})
        sn["hosts"] += 1
        sn["drawn"] += ip in kept
        if "net" in n:
            sn.setdefault("nets", {})
            sn["nets"][n["net"]] = sn["nets"].get(n["net"], 0) + 1
        sn["p1"] += n["pri"] == "P1"
        sn["likely"] += n["ev"] == "likely"
        sn["lead"] += n["ev"] == "lead"
        sn["max_score"] = max(sn["max_score"], n["score"] or 0)
        f = focus.get(ip)
        if f and f["attackers_total"]:
            sn["exposed"] += 1
            sn["alert_hosts"] += any(a["kind"] == "alert" for a in f["attackers"])
    sublinks: dict[tuple, list] = defaultdict(lambda: [0, 0])
    risky = {}
    for (s, d), p in pairs.items():
        if not p.established or s not in nodes or d not in nodes or ext(s) or ext(d):
            continue
        a, b = nodes[s]["subnet"], nodes[d]["subnet"]
        lateral = sorted({LATERAL_PORTS[x] for x in p.ports if x in LATERAL_PORTS})
        if a != b:
            k = tuple(sorted((a, b)))
            sublinks[k][0] += p.established
            sublinks[k][1] += p.established if lateral else 0
        hot = nodes[d]["pri"] == "P1" or nodes[d]["ev"] in ("likely", "lead")
        if (lateral or hot) and s in kept and d in kept:
            parts = ([", ".join(lateral)] if lateral else []) + (["into " + (nodes[d]["pri"] or "flagged") + " host"] if hot else [])
            # level 2: admin protocol into a P1/flagged host; 1: either one
            risky[(s, d)] = [s, d, p.established, " · ".join(parts), 2 if lateral and hot else 1]
    inet = {}
    for host, f in focus.items():
        for a in f["attackers"]:
            e = inet.get(a["ip"])
            if e is None:
                e = inet[a["ip"]] = {"ip": a["ip"], "kind": a["kind"], "sessions": 0, "alerts": 0, "targets": [],
                                     "in_sessions": 0, "out_sessions": 0, "out_hosts": 0, "alerts_in": 0}
            if KIND_RANK[a["kind"]] < KIND_RANK[e["kind"]]:
                e["kind"] = a["kind"]
            e["sessions"] += a["sessions"] + a["out_sessions"]
            e["in_sessions"] += a["sessions"]
            e["out_sessions"] += a["out_sessions"]
            e["out_hosts"] += a["out_sessions"] > 0
            e["alerts"] += a["alerts"]
            e["alerts_in"] += a.get("alerts_in", 0)
            # direction of this host's traffic with the address: in (it reached the host), out (the host
            # connected out to it) or both
            d = "both" if a["sessions"] and a["out_sessions"] else "out" if a["out_sessions"] else "in"
            e["targets"].append([host, a["kind"], a["sessions"] + a["out_sessions"], d])
    for e in inet.values():
        # an alert only counts as inbound when the outside address set it off (it was the source);
        # a client-side alert such as a bad server certificate is the internal host going out
        e["dir"] = ("both" if e["out_sessions"] and (e["in_sessions"] or e["alerts_in"])
                    else "out" if e["out_sessions"] else "in")
    # Inbound and outbound are ranked separately and interleaved, so internal hosts calling out are not
    # crowded off the overview by inbound scanners (which outnumber them and rank first by kind).
    by_in = sorted((e for e in inet.values() if e["dir"] != "out"),
                   key=lambda e: (KIND_RANK[e["kind"]], -len(e["targets"]), -e["sessions"], e["ip"]))
    by_out = sorted((e for e in inet.values() if e["out_sessions"]),
                    key=lambda e: (e["kind"] != "alert", -e["out_hosts"], -e["out_sessions"], e["ip"]))
    top = _interleave(by_in, by_out, MAX_INTERNET)
    internet = []
    for e in top[:MAX_INTERNET]:
        e["hosts_total"] = len(e["targets"])
        e["targets"] = sorted((t for t in e["targets"] if t[0] in kept),
                              key=lambda t: (KIND_RANK[t[1]], -t[2], t[0]))[:MAX_INTERNET_TARGETS]
        internet.append(e)
    for sn in subnets.values():          # a subnet belongs to the named network most of its hosts are in
        nets = sn.pop("nets", None)
        if nets:
            sn["net"] = max(nets, key=lambda k: (nets[k], -k))
    return {
        "subnets": sorted(subnets.values(), key=lambda x: x["id"]),
        "subnet_links": [[a, b, w, lw] for (a, b), (w, lw) in
                         sorted(sublinks.items(), key=lambda kv: (-kv[1][1], -kv[1][0]))[:MAX_SUBNET_LINKS]],
        "risky_links": sorted(risky.values(), key=lambda r: (-r[4], -r[2], r[0], r[1]))[:MAX_RISKY_LINKS],
        "internet": internet, "internet_total": len(inet),
        "internet_in_total": sum(e["dir"] != "out" for e in inet.values()),
        "internet_out_total": sum(e["out_sessions"] > 0 for e in inet.values()),
    }


def _read(name: str) -> str:
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


def html(data: dict, ioc_drawer: list | None = None) -> str:
    """The Explorer page for ``data``. ``ioc_drawer``: the IOC list for the indicator details drawer,
    when it should name hosts differently from the map (the all-networks map does)."""
    from . import ioc_archive
    from html import escape
    from .branding import EXPLORER_NAME, icon_data_uri, load as load_branding
    from .report import HTML_OPEN
    from .theme_backgrounds import explorer_background_css
    blob = json.dumps(data, separators=(",", ":"), default=str).replace("<", "\\u003c")
    brand = load_branding()
    logo = brand.logo_data_uri()
    brand_markup = ((f'<img class="brand-logo{brand.logo_class}" src="{logo}" alt="" aria-hidden="true">' if logo else "")
                    + (f'{escape(brand.prefix)} ' if brand.prefix else "") + "<b>VULNSCOPE</b>")
    report = data.get("report") or {}
    name = report.get("name") or ""
    report_markup = (f'<span id="report-name" title="{escape(report.get("description") or name)}">{escape(name)}</span>'
                     if name else "")
    return (HTML_OPEN + "<head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{escape(name) + ' · ' if name else ''}{EXPLORER_NAME} · {escape(brand.name)}</title><meta name=\"application-name\" content=\"{escape(brand.name)}\"><link rel=\"icon\" href=\"{icon_data_uri()}\"><style>" + _read("analyst_chat.css") + _read("explorer.css") + _read("attackpaths.css") + _read("timeline3d.css") + explorer_background_css() + ioc_archive.CSS + "</style></head><body>"
            + _read("explorer.html").replace("<!--BRAND-->", brand_markup, 1).replace("<!--REPORT-->", report_markup, 1)
            + f'<script id="vf-data" type="application/json">{blob}</script>'
            # Three.js (MIT, vendored so the page works offline) and the 3D renderer; the Explorer
            # falls back to its 2D canvas when WebGL is unavailable
            + "<script>" + _read("vendor/three.min.js") + "</script>"
            + "<script>" + _read("explorer3d.js") + "</script>"
            + "<script>" + _read("explorer.js") + "</script>"
            + "<script>" + _read("attackpaths.js") + "</script>"
            + "<script>" + _read("timeline3d.js") + "</script>"
            + "<script>" + _read("analyst_chat.js") + "</script>"
            + ioc_archive.drawer_html(data["ioc_matches"] if ioc_drawer is None else ioc_drawer,
                                     data.get("article_briefs")) + "</body></html>\n")
