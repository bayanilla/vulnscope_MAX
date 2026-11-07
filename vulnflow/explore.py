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

from .correlate import LATERAL_PORTS, Config, _Net
from .store import utc

STATIC = os.path.join(os.path.dirname(__file__), "static")
MAX_HOP2, MAX_NODES = 30, 2000
MAX_SUBNET_LINKS, MAX_RISKY_LINKS, MAX_INTERNET, MAX_INTERNET_TARGETS = 600, 200, 80, 12
MAX_CONNECTION_EXAMPLES, MAX_OT_EVENTS_PER_HOST = 6, 40
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
    __slots__ = ("sessions", "established", "blocked", "ports", "tried", "bytes", "first", "last", "examples")

    def __init__(self):
        self.sessions = self.established = self.blocked = self.bytes = 0
        self.ports: set = set()       # ports with completed sessions
        self.tried: set = set()       # every port seen, including blocked attempts
        self.first = self.last = None
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
               coalesce(sum(bytes_out + bytes_in), 0), min(ts), max(ts)
        FROM flows WHERE src_ip <> dst_ip GROUP BY src_ip, dst_ip ORDER BY min(seq)""")
    while rows := cur.fetchmany(10_000):
        for src, dst, n, est, blocked, tried, ports, nbytes, first, last in rows:
            p = _Pair()
            p.sessions, p.established, p.blocked, p.bytes = int(n), int(est), int(blocked), int(nbytes)
            p.tried, p.ports = set(tried or ()), set(ports or ())
            p.first, p.last = utc(first), utc(last)
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
    hostinfo = {h["host"]: h for h in res["hosts"]}
    alerts = defaultdict(lambda: defaultdict(list))
    for t in ds.threats:
        alerts[t.dst_ip][t.src_ip].append(t)
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
        best, v = None, 0.1
        for fd in findings.get(b, []):
            cv = (fd["cvss"] or 0) / 10
            if fd["port"] and fd["port"] in used:
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

    def node(ip):
        if ip in nodes:
            return nodes[ip]
        h = hostinfo.get(ip)
        fl = findings.get(ip, [])
        worst = max((r["severity"] for r in fl), default=-1)
        ev = ("likely" if any(i["confidence"] == "corroborated" for r in fl for i in r["indicators"])
              else "lead" if any(r["indicators"] for r in fl) else "")
        nodes[ip] = {"id": ip, "name": (h or {}).get("hostname", "") or "", "scanned": ip in ds.scanned_hosts,
                     "observed": h is not None,
                     "subnet": _subnet(ip), "sev": SEV.get(worst, ""), "pri": (h or {}).get("priority", ""),
                     "score": (h or {}).get("max_score", 0), "ev": ev, "os": (h or {}).get("os", "") or ""}
        return nodes[ip]

    focus = {}
    for ip in scanned:
        node(ip)
        # north/south: every outside address this host exchanged traffic with, in either direction
        vuln_ports = {r["port"] for r in findings.get(ip, []) if r["port"]}
        atk = []
        for src in in_to.get(ip, set()) | out_of.get(ip, set()):
            if not ext(src):
                continue
            p, back = pairs.get((src, ip)), pairs.get((ip, src))
            al = alerts[ip].get(src, [])
            open_al = [t for t in al if not t.blocked]
            hit = sorted(p.ports & vuln_ports) if p else []
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
                        "alert_examples": [{"src_ip": t.src_ip, "dst_ip": t.dst_ip,
                                            "dst_port": t.dst_port, "name": t.name,
                                            "blocked": t.blocked} for t in al[:MAX_CONNECTION_EXAMPLES]],
                        "signatures": sorted({t.name for t in al})[:3],
                        "returned": bool(back and back.established),
                        "first": _iso(first), "last": _iso(last)})
        known_outside = {a["ip"] for a in atk}
        for src, al in alerts[ip].items():           # IPS-only sources with no flow in either direction
            if ext(src) and src not in known_outside:
                open_al = [t for t in al if not t.blocked]
                atk.append({"ip": src, "kind": "alert" if open_al else "blocked", "dir": "in", "sessions": 0,
                            "established": 0, "blocked": 0, "ports": sorted({t.dst_port for t in al if t.dst_port})[:8],
                            "vuln_ports": [], "out_sessions": 0, "out_established": 0, "out_ports": [],
                            "connection_examples": [],
                            "alerts": len(open_al), "alerts_blocked": len(al) - len(open_al),
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
    keep = sorted(nodes, key=lambda n: (not nodes[n]["observed"], n))[:MAX_NODES]
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
    s = res["summary"]
    return {
        "vulnerability_data_available": not telemetry_only,
        "generated": res["generated"], "window": [s.get("window_start"), s.get("window_end")],
        "counts": {"hosts": len(scanned), "flows": s["flows"], "p1": s["priority_counts"]["P1"],
                   "alerts": s.get("threat_alerts", 0)},
        "nodes": [nodes[n] for n in keep],
        "links": [[a, b, w] for (a, b), w in sorted(links.items(), key=lambda kv: -kv[1])[:3000]],
        "focus": focus, "ioc_matches": res.get("ioc_matches", []), **overview,
        "ioc_counts": {host: len(ids) for host, ids in ioc_by_host.items()},
        "article_briefs": res.get("article_briefs", {}),
        "start": res["hosts"][0]["host"] if res["hosts"] else None,
    }


KIND_RANK = {"alert": 0, "vuln": 1, "reached": 2, "outbound": 3, "attempt": 4, "blocked": 5}


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
                e = inet[a["ip"]] = {"ip": a["ip"], "kind": a["kind"], "sessions": 0, "alerts": 0, "targets": []}
            if KIND_RANK[a["kind"]] < KIND_RANK[e["kind"]]:
                e["kind"] = a["kind"]
            e["sessions"] += a["sessions"] + a["out_sessions"]
            e["alerts"] += a["alerts"]
            e["targets"].append([host, a["kind"], a["sessions"] + a["out_sessions"]])
    top = sorted(inet.values(), key=lambda e: (KIND_RANK[e["kind"]], -len(e["targets"]), -e["sessions"], e["ip"]))
    internet = []
    for e in top[:MAX_INTERNET]:
        e["hosts_total"] = len(e["targets"])
        e["targets"] = sorted((t for t in e["targets"] if t[0] in kept),
                              key=lambda t: (KIND_RANK[t[1]], -t[2], t[0]))[:MAX_INTERNET_TARGETS]
        internet.append(e)
    return {
        "subnets": sorted(subnets.values(), key=lambda x: x["id"]),
        "subnet_links": [[a, b, w, lw] for (a, b), (w, lw) in
                         sorted(sublinks.items(), key=lambda kv: (-kv[1][1], -kv[1][0]))[:MAX_SUBNET_LINKS]],
        "risky_links": sorted(risky.values(), key=lambda r: (-r[4], -r[2], r[0], r[1]))[:MAX_RISKY_LINKS],
        "internet": internet, "internet_total": len(inet),
    }


def _read(name: str) -> str:
    with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
        return fh.read()


def html(data: dict) -> str:
    from . import ioc_archive
    from .branding import EXPLORER_NAME, PRODUCT_NAME, icon_data_uri
    from .theme_backgrounds import explorer_background_css
    blob = json.dumps(data, separators=(",", ":"), default=str).replace("<", "\\u003c")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{EXPLORER_NAME} · {PRODUCT_NAME}</title><link rel=\"icon\" href=\"{icon_data_uri()}\"><style>" + _read("analyst_chat.css") + _read("explorer.css") + explorer_background_css() + ioc_archive.CSS + "</style></head><body>"
            + _read("explorer.html")
            + f'<script id="vf-data" type="application/json">{blob}</script>'
            # Three.js (MIT, vendored so the page works offline) and the 3D renderer; the Explorer
            # falls back to its 2D canvas when WebGL is unavailable
            + "<script>" + _read("vendor/three.min.js") + "</script>"
            + "<script>" + _read("explorer3d.js") + "</script>"
            + "<script>" + _read("explorer.js") + "</script>"
            + "<script>" + _read("analyst_chat.js") + "</script>"
            + ioc_archive.drawer_html(data["ioc_matches"], data.get("article_briefs")) + "</body></html>\n")
