"""Tie scanner findings to observed network activity.

For every vulnerability we ask three questions of the telemetry:
  1. Exposure:    is the vulnerable service actually reachable, and from where?
  2. Blast radius: if this host is compromised, what can it reach next?
  3. Indicators:  does the traffic already look like exploitation?
and fold the answers into an explainable 0-100 risk score.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .normalize import Dataset
from .schema import SEVERITY_NAMES, Finding, Flow
from .store import naive, utc

DEFAULT_INTERNAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                         "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"]
EXTERNAL_ZONES = {"untrust", "outside", "internet", "external", "wan"}
LATERAL_PORTS = {22: "SSH", 23: "Telnet", 88: "Kerberos", 135: "RPC", 139: "NetBIOS",
                 389: "LDAP", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 3306: "MySQL",
                 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
SEVERITY_CVSS = {4: 9.5, 3: 7.5, 2: 5.0, 1: 2.5, 0: 0.0}
EXFIL_BYTES = 20 * 1024 * 1024
BROAD_REACH = 5               # distinct internal clients that make a service "widely reached"


@dataclass
class Config:
    internal_nets: list[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL_NETS))
    hops: int = 2                 # depth of the blast-radius walk
    min_severity: int = 1         # ignore Info findings by default
    # Only telemetry within this many days of a host's scan (Nessus HOST_START/HOST_END) is
    # used for that host's findings. None or 0 uses all telemetry; findings without a scan
    # time always use all telemetry.
    scan_window_days: float | None = 7
    # Clock-skew tolerance for recognising one session seen by two sensors (Zeek + firewall).
    dedup_skew_seconds: float | None = 2.0
    # Optional CSV naming address ranges (cidr,name,type), e.g. AWS VPCs; see netmap.py.
    network_map: str | None = None


class _Net:
    def __init__(self, cidrs):
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self._cache = {}

    def internal(self, ip: str) -> bool:
        if ip not in self._cache:
            addr = ipaddress.ip_address(ip)
            self._cache[ip] = any(addr.version == n.version and addr in n for n in self.nets)
        return self._cache[ip]

    def external_src(self, f: Flow) -> bool:
        return not self.internal(f.src_ip) or f.src_zone in EXTERNAL_ZONES


def _iso(ts):
    return ts.isoformat(timespec="seconds").replace("+00:00", "Z") if ts else None


def _priority(score: int, indicators: list) -> str:
    if score >= 75 or any(i["confidence"] == "corroborated" for i in indicators):
        return "P1"
    if score >= 50 or indicators:
        return "P2"
    return "P3" if score >= 25 else "P4"


PRIORITY_LABELS = {"P1": "P1 - act now", "P2": "P2 - this cycle", "P3": "P3 - scheduled",
                   "P4": "P4 - routine"}


# Flow lookups run as DuckDB SQL over the clean ``flows`` table (see store.py); the
# correlator never holds per-host flow lists in memory. ``fx`` is that table plus the
# internal/external classification for the current Config.
_KEY_MATCH = ("f.dst_ip = k.host AND (k.host_level OR (f.dst_port = k.port AND f.proto = k.proto)) "
              "AND {win}")
_WIN = "(k.lo IS NULL OR f.ts IS NULL OR f.ts BETWEEN k.lo AND k.hi)"
_LATERAL_SQL = ", ".join(str(p) for p in LATERAL_PORTS)


def _win(alias: str = "f") -> str:
    return _WIN.replace("f.ts", f"{alias}.ts")


def _key_match(alias: str = "f") -> str:
    return _KEY_MATCH.replace("f.", f"{alias}.").format(win=_win(alias))


def _port(v):
    return None if v == -1 else v


class Correlator:
    def __init__(self, ds: Dataset, cfg: Config):
        self.ds, self.cfg, self.net = ds, cfg, _Net(cfg.internal_nets)
        self.store = ds.flow_store()
        self.con = self.store.con
        con = self.con
        ips = [r[0] for r in con.execute(
            "SELECT src_ip FROM flows UNION SELECT dst_ip FROM flows").fetchall()]
        self.store.insert_rows("ipnet", {"ip": "VARCHAR", "internal": "BOOLEAN"},
                               ((ip, self.net.internal(ip)) for ip in ips))
        zones = ", ".join(f"'{z}'" for z in sorted(EXTERNAL_ZONES))
        con.execute(f"""
            CREATE OR REPLACE TABLE fx AS
            SELECT f.*, s.internal AS src_int, d.internal AS dst_int,
                   (NOT s.internal OR f.src_zone IN ({zones})) AS ext_src,
                   (f.action = 'allow' AND f.established) AS est
            FROM flows f JOIN ipnet s ON s.ip = f.src_ip JOIN ipnet d ON d.ip = f.dst_ip""")
        self.internal_ips = {r[0] for r in con.execute("SELECT ip FROM ipnet WHERE internal").fetchall()}
        del ips
        # per-host session counts, for internal hosts and scanned hosts
        wanted = self.internal_ips | {fd.host_ip for fd in ds.findings}
        self.store.insert_rows("wanted", {"ip": "VARCHAR"}, ((ip,) for ip in wanted))
        self.in_count, self.out_count = {}, {}
        for ip, n_in, n_out in con.execute("""
                SELECT ip, sum(i), sum(o) FROM (
                    SELECT dst_ip AS ip, 1 AS i, 0 AS o FROM flows
                    UNION ALL SELECT src_ip, 0, 1 FROM flows) JOIN wanted USING (ip)
                GROUP BY ip""").fetchall():
            if n_in:
                self.in_count[ip] = int(n_in)
            if n_out:
                self.out_count[ip] = int(n_out)
        self.adj: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        for src, dst, ports in con.execute("""
                SELECT src_ip, dst_ip, list(DISTINCT coalesce(CAST(dst_port AS VARCHAR), 'None') || '/' || proto)
                FROM fx WHERE est AND src_int AND dst_int AND src_ip <> dst_ip
                GROUP BY src_ip, dst_ip""").fetchall():
            self.adj[src][dst].update(ports)
        self.max_sev = Counter()
        for fd in ds.findings:
            self.max_sev[fd.host_ip] = max(self.max_sev[fd.host_ip], fd.severity)
        self._blast_cache = {}
        self._blast_data = {}
        self.threats_by_dst: dict[str, list] = defaultdict(list)
        for t in ds.threats:
            self.threats_by_dst[t.dst_ip].append(t)
        self.suspects: dict[str, datetime | None] = {}   # host -> when it was first flagged for investigation
        self._kid: dict[tuple, int] = {}
        self._agg, self._top, self._contact, self._returns = {}, {}, {}, {}
        self._before, self._new_lat, self._exfil, self._spread = {}, {}, {}, {}

    # -- scan time window -------------------------------------------------
    def window(self, fd: Finding):
        days = self.cfg.scan_window_days
        if not days or fd.scan_start is None:
            return None, None
        end = fd.scan_end or fd.scan_start
        return fd.scan_start - timedelta(days=days), max(end, fd.scan_start) + timedelta(days=days)

    def _key(self, fd: Finding) -> tuple:
        lo, hi = self.window(fd)
        if fd.port == 0:
            return (fd.host_ip, None, None, True, lo, hi)
        return (fd.host_ip, fd.port, fd.proto, False, lo, hi)

    # -- batch SQL ----------------------------------------------------------
    def prepare(self, findings: list[Finding]):
        """Run every flow query the findings need, in a few set-based SQL statements."""
        con = self.con
        for fd in findings:
            self._kid.setdefault(self._key(fd), len(self._kid))
        self.store.insert_rows(
            "xkeys", {"kid": "BIGINT", "host": "VARCHAR", "port": "INTEGER", "proto": "VARCHAR",
                      "host_level": "BOOLEAN", "lo": "TIMESTAMP", "hi": "TIMESTAMP"},
            ((kid, h, p, pr, hl, naive(lo), naive(hi)) for (h, p, pr, hl, lo, hi), kid in self._kid.items()))
        m = _key_match()
        for row in con.execute(f"""
                SELECT k.kid, count(*), count(*) FILTER (f.est), count(*) FILTER (f.action = 'deny'),
                       count(*) FILTER (f.action = 'reject'),
                       count(DISTINCT f.src_ip) FILTER (f.est AND f.ext_src),
                       count(DISTINCT f.src_ip) FILTER (f.est AND NOT f.ext_src),
                       min(f.ts), max(f.ts), coalesce(sum(f.bytes_out + f.bytes_in) FILTER (f.est), 0)
                FROM xkeys k JOIN fx f ON {m} GROUP BY k.kid""").fetchall():
            self._agg[row[0]] = row[1:]
        for kid, ip, n, ext in con.execute(f"""
                SELECT kid, src_ip, n, ext FROM (
                    SELECT k.kid, f.src_ip, count(*) AS n, bool_or(f.ext_src) AS ext,
                           row_number() OVER (PARTITION BY k.kid ORDER BY count(*) DESC, min(f.seq)) AS rn
                    FROM xkeys k JOIN fx f ON {m} WHERE f.est GROUP BY k.kid, f.src_ip)
                WHERE rn <= 8 ORDER BY kid, rn""").fetchall():
            self._top.setdefault(kid, []).append([ip, int(n), bool(ext)])
        # first contact by each outside address that completed a session to the service
        con.execute(f"""
            CREATE OR REPLACE TABLE contact AS
            SELECT k.kid, f.src_ip AS peer, min(f.ts) AS t0, min(f.seq) AS first
            FROM xkeys k JOIN fx f ON {m} WHERE f.est AND f.ext_src GROUP BY k.kid, f.src_ip""")
        for kid, peer, t0 in con.execute("SELECT kid, peer, t0 FROM contact ORDER BY kid, first").fetchall():
            self._contact.setdefault(kid, []).append((peer, utc(t0)))
        # the vulnerable host later connects back out to that address
        for kid, peer, n, ports in con.execute(f"""
                SELECT c.kid, c.peer, count(*), list(DISTINCT coalesce(f.dst_port, -1))
                FROM contact c JOIN xkeys k USING (kid)
                JOIN fx f ON f.src_ip = k.host AND f.dst_ip = c.peer
                WHERE f.est AND (c.t0 IS NULL OR f.ts IS NULL OR f.ts >= c.t0) AND {_win()}
                GROUP BY c.kid, c.peer""").fetchall():
            self._returns[(kid, peer)] = (int(n), [_port(p) for p in ports])
        # anchors depend on alerts and return connections, both known now
        anchors = []
        for fd in findings:
            kid = self._kid[self._key(fd)]
            t0 = self._anchor(fd, kid)
            if t0 is not None:
                anchors.append((kid, naive(t0)))
        self.store.insert_rows("anchors", {"kid": "BIGINT", "t0": "TIMESTAMP"}, set(anchors))
        for (kid,) in con.execute(f"""
                SELECT DISTINCT a.kid FROM anchors a JOIN xkeys k USING (kid)
                JOIN fx f ON f.src_ip = k.host
                WHERE f.action = 'allow' AND f.ts < a.t0 AND {_win()}""").fetchall():
            self._before[kid] = True
        for kid, ip, ports in con.execute(f"""
                SELECT a.kid, f.dst_ip, list(DISTINCT f.dst_port)
                FROM anchors a JOIN xkeys k USING (kid) JOIN fx f ON f.src_ip = k.host
                WHERE f.est AND f.ts >= a.t0 AND f.dst_int AND f.dst_port IN ({_LATERAL_SQL}) AND {_win()}
                  AND NOT EXISTS (SELECT 1 FROM fx g WHERE g.src_ip = k.host AND g.dst_ip = f.dst_ip
                                  AND g.action = 'allow' AND g.ts < a.t0 AND {_win('g')})
                GROUP BY a.kid, f.dst_ip""").fetchall():
            self._new_lat.setdefault(kid, {})[ip] = set(ports)
        for kid, ip, n in con.execute(f"""
                SELECT a.kid, f.dst_ip, sum(f.bytes_out) AS n
                FROM anchors a JOIN xkeys k USING (kid) JOIN fx f ON f.src_ip = k.host
                WHERE f.est AND f.ts >= a.t0 AND NOT f.dst_int AND {_win()}
                GROUP BY a.kid, f.dst_ip HAVING sum(f.bytes_out) >= {EXFIL_BYTES}
                ORDER BY a.kid, min(f.seq)""").fetchall():
            self._exfil.setdefault(kid, []).append((ip, int(n)))

    def prepare_spread(self):
        """Lateral spread: the first completed session from a flagged host to each service."""
        self._spread = {}
        if not self.suspects:
            return
        self.store.insert_rows("suspects", {"ip": "VARCHAR", "t": "TIMESTAMP"},
                               ((ip, naive(t)) for ip, t in self.suspects.items()))
        for kid, src, port, proto, ts in self.con.execute(f"""
                SELECT kid, src_ip, dst_port, proto, ts FROM (
                    SELECT k.kid, f.src_ip, f.dst_port, f.proto, f.ts,
                           row_number() OVER (PARTITION BY k.kid ORDER BY f.seq) AS rn
                    FROM xkeys k JOIN fx f ON {_key_match()} JOIN suspects s ON s.ip = f.src_ip
                    WHERE f.est AND f.src_ip <> k.host
                      AND NOT (s.t IS NOT NULL AND f.ts IS NOT NULL AND f.ts < s.t)
                      -- ignore the suspect's normal pre-incident traffic to this host
                      AND NOT (s.t IS NOT NULL AND EXISTS (
                          SELECT 1 FROM fx g WHERE g.src_ip = f.src_ip AND g.dst_ip = k.host
                          AND g.ts < s.t AND {_win('g')})))
                WHERE rn = 1""").fetchall():
            self._spread[kid] = (src, port, proto, utc(ts))

    def prepare_blast(self, hosts):
        con = self.con
        hosts = [h for h in hosts if h not in self._blast_data]
        if not hosts:
            return
        self.store.insert_rows("bhosts", {"ip": "VARCHAR"}, ((h,) for h in hosts))
        data = {h: {"lateral": {}, "ext_total": 0, "ext_top": []} for h in hosts}
        for src, port, n, first in con.execute(f"""
                SELECT f.src_ip, f.dst_port, count(*), min(f.seq) FROM fx f JOIN bhosts b ON b.ip = f.src_ip
                WHERE f.est AND f.dst_int AND f.dst_port IN ({_LATERAL_SQL})
                GROUP BY f.src_ip, f.dst_port""").fetchall():
            name = LATERAL_PORTS[port]
            n0, f0 = data[src]["lateral"].get(name, (0, first))
            data[src]["lateral"][name] = (n0 + n, min(f0, first))
        for src, total, dst, n in con.execute("""
                SELECT src_ip, total, dst_ip, n FROM (
                    SELECT f.src_ip, f.dst_ip, count(*) AS n,
                           count(*) OVER (PARTITION BY f.src_ip) AS total,
                           row_number() OVER (PARTITION BY f.src_ip ORDER BY count(*) DESC, min(f.seq)) AS rn
                    FROM fx f JOIN bhosts b ON b.ip = f.src_ip
                    WHERE f.est AND NOT f.dst_int GROUP BY f.src_ip, f.dst_ip)
                WHERE rn <= 5 ORDER BY src_ip, rn""").fetchall():
            data[src]["ext_total"] = int(total)
            data[src]["ext_top"].append([dst, int(n)])
        self._blast_data.update(data)

    # -- exposure ---------------------------------------------------------
    def exposure(self, fd: Finding) -> dict:
        host_level = fd.port == 0
        kid = self._kid[self._key(fd)]
        total, n_est, denied, refused, n_ext, n_int, first, last, nbytes = self._agg.get(
            kid, (0, 0, 0, 0, 0, 0, None, None, 0))
        seen = fd.host_ip in self.in_count or fd.host_ip in self.out_count
        alerts, blocked = self._threats_to(fd)

        if not seen:
            label, factor = "No telemetry for this host (unknown)", 0.5
        elif host_level:
            # local/client-side flaws need another foothold first, so weigh them lower
            if n_ext:
                label, factor = "Host receives internet traffic", 0.7
            elif n_est or self.out_count.get(fd.host_ip):
                label, factor = "Host is active on the network", 0.5
            else:
                label, factor = "Host seen, little activity", 0.35
        elif n_ext:
            label, factor = "Vulnerable service reached from the internet", 1.0
        elif n_int >= BROAD_REACH:
            label, factor = "Vulnerable service reached internally by many hosts", 0.85
        elif n_int:
            label, factor = "Vulnerable service reached internally", 0.75
        elif denied and not n_est:
            label, factor = "Connections to service blocked by firewall", 0.35
        elif refused and not n_est:
            # Zeek REJ: the host answered with a reset (closed port or host firewall), not a network block
            label, factor = "Connections to service refused by the host", 0.35
        elif total:
            label, factor = "Connection attempts only (no completed sessions)", 0.45
        else:
            label, factor = "Service not observed in use", 0.3
        exp = {
            "label": label, "factor": factor, "scope": "host" if host_level else "port",
            "telemetry_seen": seen, "inbound_total": total, "established": n_est,
            "denied": denied, "refused": refused, "attempts": total - n_est - denied - refused,
            "internal_sources": n_int, "external_sources": n_ext,
            "top_sources": self._top.get(kid, []),
            "first_seen": _iso(utc(first)), "last_seen": _iso(utc(last)),
            "bytes": int(nbytes),
            "threat_alerts": len(alerts), "threat_blocked": len(blocked),
            "threat_blocked_sources": [[ip, n] for ip, n in
                                       Counter(t.src_ip for t in blocked).most_common(8)],
            "_kid": kid,
        }
        lo, hi = self.window(fd)
        if lo is not None:
            exp["window"] = {"start": _iso(lo), "end": _iso(hi), "days": self.cfg.scan_window_days}
        return exp

    # -- blast radius -----------------------------------------------------
    def blast(self, host: str) -> dict:
        if host in self._blast_cache:
            return self._blast_cache[host]
        if host not in self._blast_data:
            self.prepare_blast([host])
        hops, frontier = {}, [host]
        for depth in range(1, self.cfg.hops + 1):
            nxt = []
            for h in frontier:
                for peer in self.adj.get(h, {}):
                    if peer != host and peer not in hops:
                        hops[peer] = depth
                        nxt.append(peer)
            frontier = nxt
        direct = self.adj.get(host, {})
        reachable = sorted(
            ({"ip": ip, "hop": d, "ports": sorted(direct.get(ip, set())) if d == 1 else [],
              "max_severity": SEVERITY_NAMES.get(self.max_sev.get(ip), "") if ip in self.max_sev else ""}
             for ip, d in hops.items()),
            key=lambda r: (r["hop"], -self.max_sev.get(r["ip"], -1), r["ip"]))
        data = self._blast_data[host]
        lateral = {name: n for name, (n, _) in
                   sorted(data["lateral"].items(), key=lambda kv: (-kv[1][0], kv[1][1]))}
        pivots = [r["ip"] for r in reachable if self.max_sev.get(r["ip"], 0) >= 3]
        b = {
            "reachable_count": len(reachable), "direct_count": len(direct),
            "reachable": reachable[:50], "vulnerable_pivots": pivots,
            "lateral_protocols": lateral,
            "external_destinations": data["ext_total"],
            "top_external_destinations": data["ext_top"],
        }
        b["factor"] = round(1 + min(0.5, 0.04 * len(direct) + 0.02 * (len(reachable) - len(direct))
                                    + 0.08 * len(pivots) + (0.1 if lateral else 0)), 2)
        self._blast_cache[host] = b
        return b

    # -- exploitation indicators -----------------------------------------
    # Every network pattern on its own is a "lead": worth investigating, not proof.
    # A finding is "corroborated" only when an IPS/IDS alert and post-contact host
    # behaviour agree. Even then only host forensics can confirm a compromise.
    def _threats_to(self, fd: Finding) -> tuple[list, list]:
        lo, hi = self.window(fd)
        hits = [t for t in self.threats_by_dst.get(fd.host_ip, [])
                if (fd.port == 0 or t.dst_port in (None, fd.port))
                and (lo is None or t.ts is None or lo <= t.ts <= hi)]
        return [t for t in hits if not t.blocked], [t for t in hits if t.blocked]

    def _return_peers(self, kid: int) -> list[tuple]:
        """[(peer, first contact, sessions back, ports)] in first-contact order."""
        out = []
        for ip, t0 in self._contact.get(kid, []):
            back = self._returns.get((kid, ip))
            if back:
                out.append((ip, t0, back[0], back[1]))
        return out

    def _anchor(self, fd: Finding, kid: int):
        # Anchor "after" checks on contact that triggered a return connection or an alert. A
        # service the whole internet uses has no meaningful "first contact", so otherwise we only
        # anchor when very few outside addresses reached it.
        contact = self._contact.get(kid, [])
        if not contact:
            return None
        alerts, _ = self._threats_to(fd)
        flagged = {p[0] for p in self._return_peers(kid)} | {t.src_ip for t in alerts}
        anchors = [t for ip, t in contact if t and (ip in flagged or (not flagged and len(contact) <= 3))]
        return min(anchors) if anchors else None

    def indicators(self, fd: Finding, exp: dict) -> list[dict]:
        found = []
        kid = exp["_kid"]
        # a host already flagged for investigation newly reached this vulnerable service
        if kid in self._spread:
            src, port, proto, ts = self._spread[kid]
            found.append({"type": "lateral_spread", "confidence": "lead", "peer": src,
                          "port": port, "proto": proto, "text":
                          f"{src}, which is flagged for investigation, newly connected to this "
                          f"vulnerable service at {_iso(ts) or 'an unknown time'}. Check this host "
                          f"for signs of lateral movement."})
        alerts, _ = self._threats_to(fd)
        if alerts:
            names = sorted({t.name for t in alerts})
            cve_hit = sorted({c for c in fd.cves for t in alerts if c.lower() in t.name.lower()})
            srcs = sorted({t.src_ip for t in alerts})
            found.append({"type": "threat_alert", "confidence": "lead",
                          "sources": [[ip, n] for ip, n in Counter(t.src_ip for t in alerts).most_common()],
                          "text":
                          f"IPS/IDS alerted {len(alerts)} time(s) on traffic to this service and did not block it: "
                          f"{'; '.join(names[:3])}{' ...' if len(names) > 3 else ''} (from {', '.join(srcs[:4])})"
                          + (f", matching {', '.join(cve_hit)}" if cve_hit else "")
                          + ". An alert shows an attempt, not that it succeeded."})
        if not self._contact.get(kid):
            return found
        # 1. the vulnerable host later connects out to the same outside address that reached the service
        for ip, t0, n, port_list in self._return_peers(kid):
            ports = sorted({str(p) for p in port_list})
            found.append({"type": "return_connection", "confidence": "lead", "at": _iso(t0), "peer": ip,
                          "ports": sorted(set(port_list)), "text":
                          f"{fd.host_ip} opened {n} outbound connection(s) to {ip} "
                          f"(port {', '.join(ports)}) after {ip} connected to the vulnerable service. "
                          f"This is consistent with an exploit callback, but on its own it can also be "
                          f"legitimate traffic; confirm with IPS/threat logs, payload or application logs, "
                          f"or host evidence."})
        t0 = self._anchor(fd, kid)
        if t0 is not None:
            # 2. new lateral movement that only starts after outside contact
            targets = self._new_lat.get(kid) if self._before.get(kid) else None
            if targets:
                protos = sorted({LATERAL_PORTS[p] for ps in targets.values() for p in ps})
                found.append({"type": "new_lateral", "confidence": "lead", "at": _iso(t0),
                              "targets": [{"ip": ip, "ports": sorted(ps)} for ip, ps in sorted(targets.items())],
                              "text":
                              f"After the flagged inbound contact at {_iso(t0)}, {fd.host_ip} "
                              f"began connecting to {len(targets)} internal host(s) it had not talked to "
                              f"before, over {', '.join(protos)}."})
            # 3. large uploads to the internet after outside contact
            for ip, n in self._exfil.get(kid, []):
                found.append({"type": "exfil", "confidence": "lead", "at": _iso(t0), "peer": ip, "bytes": n,
                              "text":
                              f"{fd.host_ip} sent {n / 1048576:.1f} MB to external address {ip} "
                              f"after the flagged inbound contact at {_iso(t0)}."})
        # Corroboration: an alert on this service plus post-contact behaviour from the host.
        behaviour = [i for i in found if i["type"] in ("return_connection", "new_lateral", "exfil")]
        if alerts and behaviour:
            peers = {i.get("peer") for i in behaviour if i.get("peer")}
            same = sorted({t.src_ip for t in alerts} & peers)
            found.append({"type": "corroborated", "confidence": "corroborated",
                          "at": min((i["at"] for i in behaviour if i.get("at")), default=None), "text":
                          "Independent signals agree: the IPS/IDS alerted on traffic to this vulnerable service"
                          + (f" from {', '.join(same)}, the same address the host then connected back to" if same else "")
                          + f", and the host then showed {', '.join(sorted({i['type'].replace('_', ' ') for i in behaviour}))}. "
                          "Treat this as likely exploitation and start incident response; host forensics is "
                          "still needed to confirm a compromise."})
        return found

    # -- scoring ----------------------------------------------------------
    def score(self, fd: Finding) -> dict:
        exp = self.exposure(fd)
        bl = self.blast(fd.host_ip)
        ind = self.indicators(fd, exp)
        cvss = fd.cvss if fd.cvss is not None else SEVERITY_CVSS.get(fd.severity, 0)
        e_factor = (1.0 + (0.1 if fd.exploit_frameworks else 0)) if fd.exploit_available else 0.65
        raw = cvss * 10 * e_factor * exp["factor"] * bl["factor"]
        if any(i["confidence"] == "corroborated" for i in ind):
            raw *= 1.25
        elif ind:
            raw *= 1.1
        score = int(min(100, round(raw)))
        likelihood = e_factor * exp["factor"]
        why = [f"Base severity: CVSS{fd.cvss_version and ' v' + fd.cvss_version} {cvss:.1f} ({fd.severity_name})."]
        if fd.exploit_available:
            fw = f" ({', '.join(fd.exploit_frameworks)})" if fd.exploit_frameworks else ""
            why.append(f"A public exploit is available{fw}.")
        else:
            why.append("No public exploit is known to the scanner.")
        why.append(f"Exposure: {exp['label'].lower()}"
                   + (f" - {exp['established']} completed sessions from {exp['external_sources']} "
                      f"external and {exp['internal_sources']} internal sources." if exp["established"] else "."))
        if exp["denied"]:
            why.append(f"{exp['denied']} connection(s) to it were blocked by a firewall.")
        if exp["refused"]:
            why.append(f"{exp['refused']} connection(s) to it were refused by the host (reset, as Zeek logs REJ).")
        if bl["reachable_count"]:
            why.append(f"Blast radius: the host talks to {bl['direct_count']} internal host(s) directly and "
                       f"{bl['reachable_count']} within {self.cfg.hops} hops"
                       + (f", including {len(bl['vulnerable_pivots'])} with High/Critical findings." if bl["vulnerable_pivots"] else "."))
        if exp["threat_blocked"]:
            why.append(f"The IPS/IDS blocked {exp['threat_blocked']} alerted attempt(s) against it.")
        if any(i["confidence"] == "corroborated" for i in ind):
            why.append("Corroborated exploitation evidence (IPS alert plus host behaviour); see indicators.")
        elif ind:
            why.append("Traffic gives leads worth investigating; nothing in the logs confirms exploitation.")
        exp_public = {k: v for k, v in exp.items() if not k.startswith("_")}
        return {
            "host": fd.host_ip, "hostname": fd.hostname, "os": fd.os,
            "plugin_id": fd.plugin_id, "plugin_name": fd.plugin_name,
            "severity": fd.severity, "severity_name": fd.severity_name,
            "port": fd.port, "proto": fd.proto, "service": fd.service,
            "cvss": cvss, "cves": fd.cves, "exploit_available": fd.exploit_available,
            "exploit_frameworks": fd.exploit_frameworks, "synopsis": fd.synopsis,
            "solution": fd.solution, "source": fd.source,
            "exposure": exp_public, "blast_factor": bl["factor"], "exploit_factor": e_factor,
            "likelihood": "High" if likelihood >= 0.75 else "Medium" if likelihood >= 0.45 else "Low",
            "score": score, "priority": _priority(score, ind), "indicators": ind, "rationale": why,
        }

    # -- whole run --------------------------------------------------------
    def run(self) -> dict:
        ds, cfg = self.ds, self.cfg
        vulnerability_data_available = bool(ds.findings)
        todo = [fd for fd in ds.findings if fd.severity >= cfg.min_severity]
        self.prepare(todo)
        self.prepare_blast(sorted({fd.host_ip for fd in todo}))
        scored = [self.score(fd) for fd in todo]
        # second pass: hosts flagged for investigation make the vulnerable services they reach riskier
        for r in scored:
            for i in r["indicators"]:
                if i["type"] in ("return_connection", "corroborated"):
                    t = datetime.fromisoformat(i["at"].replace("Z", "+00:00")) if i.get("at") else None
                    cur = self.suspects.get(r["host"], "no")
                    if cur == "no" or (t and cur and t < cur):
                        self.suspects[r["host"]] = t
        if self.suspects:
            self.prepare_spread()
            scored = [self.score(fd) for fd in todo]
        scored.sort(key=lambda r: (r["priority"], -r["score"], -r["severity"], r["host"]))

        hosts = {}
        for r in scored:
            h = hosts.setdefault(r["host"], {
                "host": r["host"], "hostname": r["hostname"], "os": r["os"], "findings": 0,
                "by_severity": Counter(), "max_score": 0, "priority": "P4",
                "internet_exposed": False, "indicators": 0, "blast": self.blast(r["host"]),
                "telemetry_seen": r["exposure"]["telemetry_seen"],
                "inbound_flows": self.in_count.get(r["host"], 0),
                "outbound_flows": self.out_count.get(r["host"], 0),
            })
            h["findings"] += 1
            h["by_severity"][r["severity_name"]] += 1
            h["max_score"] = max(h["max_score"], r["score"])
            h["priority"] = min(h["priority"], r["priority"])
            h["internet_exposed"] |= r["exposure"]["external_sources"] > 0 and r["exposure"]["scope"] == "port"
            h["indicators"] += len(r["indicators"])
        host_list = sorted(hosts.values(), key=lambda h: (h["priority"], -h["max_score"], h["host"]))
        if not vulnerability_data_available:
            # Keep observed internal hosts navigable without assigning a vulnerability score.
            telemetry_hosts = sorted(self.internal_ips | {ip for t in ds.threats
                                                          for ip in (t.src_ip, t.dst_ip)
                                                          if self.net.internal(ip)})
            self.prepare_blast(telemetry_hosts)
            for ip in telemetry_hosts:
                hosts[ip] = {"host": ip, "hostname": "", "os": "", "findings": 0,
                             "by_severity": {}, "max_score": None, "priority": None,
                             "internet_exposed": None, "indicators": 0, "blast": self.blast(ip),
                             "telemetry_seen": True, "inbound_flows": self.in_count.get(ip, 0),
                             "outbound_flows": self.out_count.get(ip, 0)}
            host_list = list(hosts.values())
        for h in host_list:
            h["by_severity"] = dict(h["by_severity"])

        internal_seen = set(self.internal_ips)
        # a scanned host counts as seen whenever it is in the telemetry, internal address or not
        # (DMZ hosts on public addresses are scanned too)
        seen_scanned = set(self.in_count) | set(self.out_count)
        if not vulnerability_data_available:
            internal_seen |= {ip for t in ds.threats for ip in (t.src_ip, t.dst_ip)
                              if self.net.internal(ip)}
        servers: dict[str, list] = defaultdict(list)     # ip -> [(service, sessions)] most used first
        for ip, svc, n in self.con.execute("""
                SELECT dst_ip, CAST(dst_port AS VARCHAR) || '/' || proto, count(*) FROM fx
                WHERE est AND dst_int AND dst_port IS NOT NULL
                GROUP BY dst_ip, dst_port, proto ORDER BY dst_ip, count(*) DESC, min(seq)""").fetchall():
            servers[ip].append((svc, int(n)))
        scanned = set(ds.scanned_hosts)
        sessions = {ip: sum(n for _, n in svcs) for ip, svcs in servers.items()}
        not_scanned = sorted(set(servers) - scanned, key=lambda ip: (-sessions[ip], ip))
        coverage = {
            "scanned_hosts": len(scanned), "telemetry_internal_hosts": len(internal_seen),
            "scanned_and_seen": len(scanned & (internal_seen | seen_scanned)),
            "scanned_not_seen": sorted(scanned - internal_seen - seen_scanned),
            "active_servers_not_scanned": [
                {"ip": ip, "services": [p for p, _ in servers[ip][:6]],
                 "sessions": sessions[ip]} for ip in not_scanned],
        }
        kinds = defaultdict(set)
        for r in scored:
            kinds[r["host"]] |= {i["type"] for i in r["indicators"]}
        corroborated = {h for h, k in kinds.items() if "corroborated" in k}
        spread = {h for h, k in kinds.items() if k == {"lateral_spread"}}
        investigate = {h for h, k in kinds.items() if k} - corroborated - spread
        t_min, t_max = self.con.execute("SELECT min(ts), max(ts) FROM flows").fetchone()
        times = [utc(t) for t in (t_min, t_max) if t] + [t.ts for t in ds.threats if t.ts]
        pc = Counter(r["priority"] for r in scored)
        summary = {
            "vulnerability_data_available": vulnerability_data_available,
            "flows": len(ds.flows), "findings_total": len(ds.findings), "findings_scored": len(scored),
            "hosts_with_findings": len({r["host"] for r in scored}),
            "priority_counts": {p: pc.get(p, 0) if vulnerability_data_available else None
                                for p in ("P1", "P2", "P3", "P4")},
            "internet_exposed_findings": (sum(1 for r in scored if r["exposure"]["external_sources"]
                                              and r["exposure"]["scope"] == "port")
                                          if vulnerability_data_available else None),
            "exploitable_and_exposed": (sum(1 for r in scored if r["exploit_available"]
                                            and r["exposure"]["established"] and r["exposure"]["scope"] == "port")
                                        if vulnerability_data_available else None),
            "hosts_with_indicators": sorted({r["host"] for r in scored if r["indicators"]}),
            "hosts_corroborated": sorted(corroborated),
            "hosts_to_investigate": sorted(investigate),
            "hosts_possible_spread": sorted(spread),
            "threat_alerts": len(ds.threats),
            "zeek_event_counts": dict(sorted(Counter(e.stream for e in ds.zeek_events).items())),
            "ot_protocol_counts": dict(sorted(Counter(e.protocol for e in ds.ot_events).items())),
            "hosts_internet_exposed": sum(1 for h in host_list if h["internet_exposed"]),
            "window_start": _iso(min(times)) if times else None,
            "window_end": _iso(max(times)) if times else None,
            "duplicate_flows_removed": ds.duplicate_flows,
            "cross_sensor_duplicates_removed": ds.cross_sensor_duplicates,
            "duplicate_findings_merged": ds.duplicate_findings,
        }
        network_leads = []
        if not vulnerability_data_available:
            rows = self.con.execute("""
                WITH c AS (SELECT dst_ip AS host, src_ip AS peer, min(ts) AS contact FROM fx
                           WHERE est AND ext_src GROUP BY dst_ip, src_ip)
                SELECT c.host, c.peer, count(*) FROM c JOIN fx f ON f.src_ip = c.host AND f.dst_ip = c.peer
                WHERE f.est AND (c.contact IS NULL OR f.ts IS NULL OR f.ts >= c.contact)
                GROUP BY c.host, c.peer""").fetchall()
            for host, peer, n in sorted(r for r in rows if r[0] in hosts):
                network_leads.append({"host": host, "peer": peer, "sessions": int(n),
                                      "note": "Host connected to an outside address after inbound contact; this may be legitimate traffic."})
        return {
            "generated": _iso(datetime.now(timezone.utc)),
            "config": {"internal_nets": cfg.internal_nets, "hops": cfg.hops,
                       "min_severity": SEVERITY_NAMES[cfg.min_severity]},
            "inputs": [{"file": s.file, "format": s.fmt, "read": s.read, "kept": s.kept,
                        "dropped": dict(s.dropped), "notes": s.notes} for s in ds.stats],
            "summary": summary, "coverage": coverage, "hosts": host_list, "findings": scored,
            "telemetry_leads": [
                {"host": ip, "alerts": len(alerts), "unblocked": sum(not t.blocked for t in alerts),
                 "blocked": sum(t.blocked for t in alerts),
                 "signatures": sorted({t.name for t in alerts}),
                 "note": "IPS/IDS alerts are investigation leads, not verified exploitation."}
                for ip, alerts in sorted(self.threats_by_dst.items())] if not vulnerability_data_available else [],
            "network_leads": network_leads,
        }


def correlate(ds: Dataset, cfg: Config | None = None) -> dict:
    return Correlator(ds, cfg or Config()).run()
