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
from datetime import datetime, timezone

from .normalize import Dataset
from .schema import SEVERITY_NAMES, Finding, Flow

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


class Correlator:
    def __init__(self, ds: Dataset, cfg: Config):
        self.ds, self.cfg, self.net = ds, cfg, _Net(cfg.internal_nets)
        self.inbound: dict[str, list[Flow]] = defaultdict(list)
        self.outbound: dict[str, list[Flow]] = defaultdict(list)
        self.adj: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        for f in ds.flows:
            self.inbound[f.dst_ip].append(f)
            self.outbound[f.src_ip].append(f)
            if (f.action == "allow" and f.established and self.net.internal(f.src_ip)
                    and self.net.internal(f.dst_ip) and f.src_ip != f.dst_ip):
                self.adj[f.src_ip][f.dst_ip].add(f"{f.dst_port}/{f.proto}")
        self.max_sev = Counter()
        for fd in ds.findings:
            self.max_sev[fd.host_ip] = max(self.max_sev[fd.host_ip], fd.severity)
        self._blast_cache = {}
        self.threats_by_dst: dict[str, list] = defaultdict(list)
        for t in ds.threats:
            self.threats_by_dst[t.dst_ip].append(t)
        self.suspects: dict[str, datetime | None] = {}   # host -> when it was first flagged for investigation

    # -- exposure ---------------------------------------------------------
    def exposure(self, fd: Finding) -> dict:
        host_level = fd.port == 0
        flows = [f for f in self.inbound.get(fd.host_ip, [])
                 if host_level or (f.dst_port == fd.port and f.proto == fd.proto)]
        est = [f for f in flows if f.action == "allow" and f.established]
        denied = [f for f in flows if f.action == "deny"]
        ext_est = {f.src_ip for f in est if self.net.external_src(f)}
        int_est = {f.src_ip for f in est if not self.net.external_src(f)}
        src_counts = Counter(f.src_ip for f in est)
        seen = fd.host_ip in self.inbound or fd.host_ip in self.outbound
        times = [f.ts for f in flows if f.ts]

        if not seen:
            label, factor = "No telemetry for this host (unknown)", 0.5
        elif host_level:
            # local/client-side flaws need another foothold first, so weigh them lower
            if ext_est:
                label, factor = "Host receives internet traffic", 0.7
            elif est or self.outbound.get(fd.host_ip):
                label, factor = "Host is active on the network", 0.5
            else:
                label, factor = "Host seen, little activity", 0.35
        elif ext_est:
            label, factor = "Vulnerable service reached from the internet", 1.0
        elif len(int_est) >= BROAD_REACH:
            label, factor = "Vulnerable service reached internally by many hosts", 0.85
        elif int_est:
            label, factor = "Vulnerable service reached internally", 0.75
        elif denied and not est:
            label, factor = "Connections to service blocked by firewall", 0.35
        elif flows:
            label, factor = "Connection attempts only (no completed sessions)", 0.45
        else:
            label, factor = "Service not observed in use", 0.3
        return {
            "label": label, "factor": factor, "scope": "host" if host_level else "port",
            "telemetry_seen": seen, "inbound_total": len(flows), "established": len(est),
            "denied": len(denied), "attempts": len(flows) - len(est) - len(denied),
            "internal_sources": len(int_est), "external_sources": len(ext_est),
            "top_sources": [[ip, n, ip in ext_est] for ip, n in src_counts.most_common(8)],
            "first_seen": _iso(min(times)) if times else None,
            "last_seen": _iso(max(times)) if times else None,
            "bytes": sum(f.bytes_out + f.bytes_in for f in est),
            "threat_alerts": len(self._threats_to(fd)[0]), "threat_blocked": len(self._threats_to(fd)[1]),
            "threat_blocked_sources": [[ip, n] for ip, n in
                                       Counter(t.src_ip for t in self._threats_to(fd)[1]).most_common(8)],
            "_ext_flows": [f for f in est if self.net.external_src(f)],
            "_all_est": est,
        }

    # -- blast radius -----------------------------------------------------
    def blast(self, host: str) -> dict:
        if host in self._blast_cache:
            return self._blast_cache[host]
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
        out = [f for f in self.outbound.get(host, []) if f.action == "allow" and f.established]
        lateral = Counter(LATERAL_PORTS[f.dst_port] for f in out
                          if f.dst_port in LATERAL_PORTS and self.net.internal(f.dst_ip))
        ext_dst = Counter(f.dst_ip for f in out if not self.net.internal(f.dst_ip))
        pivots = [r["ip"] for r in reachable if self.max_sev.get(r["ip"], 0) >= 3]
        b = {
            "reachable_count": len(reachable), "direct_count": len(direct),
            "reachable": reachable[:50], "vulnerable_pivots": pivots,
            "lateral_protocols": dict(lateral.most_common()),
            "external_destinations": len(ext_dst),
            "top_external_destinations": [[ip, n] for ip, n in ext_dst.most_common(5)],
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
        hits = [t for t in self.threats_by_dst.get(fd.host_ip, [])
                if fd.port == 0 or t.dst_port in (None, fd.port)]
        return [t for t in hits if not t.blocked], [t for t in hits if t.blocked]

    def indicators(self, fd: Finding, exp: dict) -> list[dict]:
        found = []
        # a host already flagged for investigation newly reached this vulnerable service
        for f in exp["_all_est"]:
            t_sus = self.suspects.get(f.src_ip, "no")
            if t_sus == "no" or f.src_ip == fd.host_ip or (t_sus and f.ts and f.ts < t_sus):
                continue
            # ignore the suspect's normal pre-incident traffic to this host
            if t_sus and any(g.dst_ip == fd.host_ip and g.ts and g.ts < t_sus
                             for g in self.outbound.get(f.src_ip, [])):
                continue
            found.append({"type": "lateral_spread", "confidence": "lead", "peer": f.src_ip,
                          "port": f.dst_port, "proto": f.proto, "text":
                          f"{f.src_ip}, which is flagged for investigation, newly connected to this "
                          f"vulnerable service at {_iso(f.ts) or 'an unknown time'}. Check this host "
                          f"for signs of lateral movement."})
            break
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
        ext_flows = exp["_ext_flows"]
        if not ext_flows:
            return found
        out = [f for f in self.outbound.get(fd.host_ip, []) if f.action == "allow"]
        first_contact = {}
        for f in ext_flows:
            cur = first_contact.get(f.src_ip, "unset")
            if cur == "unset" or (f.ts and (cur is None or f.ts < cur)):
                first_contact[f.src_ip] = f.ts
        # 1. the vulnerable host later connects out to the same outside address that reached the service
        for ip, t0 in first_contact.items():
            back = [f for f in out if f.dst_ip == ip and f.established and (not t0 or not f.ts or f.ts >= t0)]
            if back:
                ports = sorted({str(f.dst_port) for f in back})
                found.append({"type": "return_connection", "confidence": "lead", "at": _iso(t0), "peer": ip,
                              "ports": sorted({f.dst_port for f in back}), "text":
                              f"{fd.host_ip} opened {len(back)} outbound connection(s) to {ip} "
                              f"(port {', '.join(ports)}) after {ip} connected to the vulnerable service. "
                              f"This is consistent with an exploit callback, but on its own it can also be "
                              f"legitimate traffic; confirm with IPS/threat logs, payload or application logs, "
                              f"or host evidence."})
        # Anchor "after" checks on contact that triggered a return connection or an alert. A
        # service the whole internet uses has no meaningful "first contact", so otherwise we only
        # anchor when very few outside addresses reached it.
        flagged = {i["peer"] for i in found if i["type"] == "return_connection"} | {t.src_ip for t in alerts}
        anchors = [t for ip, t in first_contact.items() if t and (ip in flagged or
                   (not flagged and len(first_contact) <= 3))]
        if anchors:
            t0 = min(anchors)
            before = [f for f in out if f.ts and f.ts < t0]
            after = [f for f in out if f.ts and f.ts >= t0 and f.established]
            # 2. new lateral movement that only starts after outside contact
            if before:
                known = {f.dst_ip for f in before}
                new_lat = {f.dst_ip for f in after if f.dst_port in LATERAL_PORTS
                           and self.net.internal(f.dst_ip) and f.dst_ip not in known}
                if new_lat:
                    protos = sorted({LATERAL_PORTS[f.dst_port] for f in after if f.dst_ip in new_lat
                                     and f.dst_port in LATERAL_PORTS})
                    targets = {}
                    for f in after:
                        if f.dst_ip in new_lat and f.dst_port in LATERAL_PORTS:
                            targets.setdefault(f.dst_ip, set()).add(f.dst_port)
                    found.append({"type": "new_lateral", "confidence": "lead", "at": _iso(t0),
                                  "targets": [{"ip": ip, "ports": sorted(ps)} for ip, ps in sorted(targets.items())],
                                  "text":
                                  f"After the flagged inbound contact at {_iso(t0)}, {fd.host_ip} "
                                  f"began connecting to {len(new_lat)} internal host(s) it had not talked to "
                                  f"before, over {', '.join(protos)}."})
            # 3. large uploads to the internet after outside contact
            big = Counter()
            for f in after:
                if not self.net.internal(f.dst_ip):
                    big[f.dst_ip] += f.bytes_out
            for ip, n in big.items():
                if n >= EXFIL_BYTES:
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
            scored = [self.score(fd) for fd in todo]
        scored.sort(key=lambda r: (r["priority"], -r["score"], -r["severity"], r["host"]))

        hosts = {}
        for r in scored:
            h = hosts.setdefault(r["host"], {
                "host": r["host"], "hostname": r["hostname"], "os": r["os"], "findings": 0,
                "by_severity": Counter(), "max_score": 0, "priority": "P4",
                "internet_exposed": False, "indicators": 0, "blast": self.blast(r["host"]),
                "telemetry_seen": r["exposure"]["telemetry_seen"],
                "inbound_flows": len(self.inbound.get(r["host"], [])),
                "outbound_flows": len(self.outbound.get(r["host"], [])),
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
            for ip in sorted({ip for f in ds.flows for ip in (f.src_ip, f.dst_ip)
                              if self.net.internal(ip)} | {ip for t in ds.threats
                                                         for ip in (t.src_ip, t.dst_ip)
                                                         if self.net.internal(ip)}):
                hosts[ip] = {"host": ip, "hostname": "", "os": "", "findings": 0,
                             "by_severity": {}, "max_score": None, "priority": None,
                             "internet_exposed": None, "indicators": 0, "blast": self.blast(ip),
                             "telemetry_seen": True, "inbound_flows": len(self.inbound.get(ip, [])),
                             "outbound_flows": len(self.outbound.get(ip, []))}
            host_list = list(hosts.values())
        for h in host_list:
            h["by_severity"] = dict(h["by_severity"])

        internal_seen = {ip for f in ds.flows for ip in (f.src_ip, f.dst_ip) if self.net.internal(ip)}
        if not vulnerability_data_available:
            internal_seen |= {ip for t in ds.threats for ip in (t.src_ip, t.dst_ip)
                              if self.net.internal(ip)}
        servers = defaultdict(Counter)
        for f in ds.flows:
            if f.established and f.action == "allow" and self.net.internal(f.dst_ip) and f.dst_port is not None:
                servers[f.dst_ip][f"{f.dst_port}/{f.proto}"] += 1
        scanned = set(ds.scanned_hosts)
        not_scanned = sorted(set(servers) - scanned, key=lambda ip: -sum(servers[ip].values()))
        coverage = {
            "scanned_hosts": len(scanned), "telemetry_internal_hosts": len(internal_seen),
            "scanned_and_seen": len(scanned & internal_seen),
            "scanned_not_seen": sorted(scanned - internal_seen),
            "active_servers_not_scanned": [
                {"ip": ip, "services": [p for p, _ in servers[ip].most_common(6)],
                 "sessions": sum(servers[ip].values())} for ip in not_scanned],
        }
        kinds = defaultdict(set)
        for r in scored:
            kinds[r["host"]] |= {i["type"] for i in r["indicators"]}
        corroborated = {h for h, k in kinds.items() if "corroborated" in k}
        spread = {h for h, k in kinds.items() if k == {"lateral_spread"}}
        investigate = {h for h, k in kinds.items() if k} - corroborated - spread
        times = [f.ts for f in ds.flows if f.ts] + [t.ts for t in ds.threats if t.ts]
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
            "duplicate_findings_merged": ds.duplicate_findings,
        }
        network_leads = []
        if not vulnerability_data_available:
            for host in hosts:
                inbound = [f for f in self.inbound.get(host, []) if f.action == "allow"
                           and f.established and self.net.external_src(f)]
                for peer in sorted({f.src_ip for f in inbound}):
                    contact = min((f.ts for f in inbound if f.src_ip == peer and f.ts), default=None)
                    returned = [f for f in self.outbound.get(host, []) if f.dst_ip == peer
                                and f.action == "allow" and f.established
                                and (contact is None or f.ts is None or f.ts >= contact)]
                    if returned:
                        network_leads.append({"host": host, "peer": peer, "sessions": len(returned),
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
