"""Shared writer for the intrusion samples that replay published reporting (Artex AI, CyberStrike AI).

A sample module builds a :class:`Log` (sessions, DNS lookups, HTTP requests, TLS handshakes, IDS alerts,
Zeek notices), describes its scanned hosts and findings, and calls :func:`write`. Everything written is
plain text: Zeek TSV logs, a Suricata eve.json, a .nessus XML scan, an IOC CSV and article previews.
No payloads, binaries or captures are produced.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

IOC_HEADER = ["indicatorType", "indicator", "disposition", "dispositionReason", "riskTags", "firstSeenAt",
              "lastSeenAt", "sightingCount", "sources", "articleUrls", "extractionMethods", "confidences"]
HISTORY = {"SF": "ShADadFf", "REJ": "Sr", "S0": "S", "RSTO": "ShADaR", "RSTR": "ShADar", "S1": "ShAD"}


class Log:
    """Every record of one sample. One method per kind of thing a sensor saw."""

    def __init__(self, rng, resolver: str, prefix: str = "C"):
        self.rng, self.resolver, self.prefix = rng, resolver, prefix
        self.conn, self.dns, self.http, self.ssl, self.notice, self.eve = ([] for _ in range(6))
        self.uid = 0

    def _uid(self):
        self.uid += 1
        return f"{self.prefix}{self.uid:09x}"

    def session(self, ts, s, d, dp, svc="-", proto="tcp", state="SF", ob=None, rb=None, dur=None):
        """One connection as Zeek's conn.log records it. Returns (uid, source port)."""
        rng = self.rng
        sp = rng.randint(49152, 65535)
        ob = rng.randint(300, 4000) if ob is None else ob
        rb = (rng.randint(800, 40000) if state == "SF" else 0) if rb is None else rb
        dur = (rng.uniform(0.05, 20) if state == "SF" else rng.uniform(0.0005, 0.01)) if dur is None else dur
        uid = self._uid()
        self.conn.append(dict(ts=ts, uid=uid, s=s, sp=sp, d=d, dp=dp, proto=proto, svc=svc, dur=dur,
                              ob=ob, rb=rb, state=state))
        return uid, sp

    def lookup(self, ts, client, query, answer, qtype="A"):
        self.dns.append(dict(ts=ts, uid=self._uid(), s=client, sp=self.rng.randint(49152, 65535), d=self.resolver,
                             q=query, a=answer, qt=qtype))

    def web(self, ts, s, d, dp, method, host, uri, ua, status, ob=None, rb=None, dur=None):
        """A plaintext HTTP request: a conn.log session plus its http.log line."""
        rb = self.rng.randint(200, 6000) if rb is None else rb
        ob = self.rng.randint(250, 900) if ob is None else ob
        uid, sp = self.session(ts, s, d, dp, svc="http", ob=ob, rb=rb,
                               dur=self.rng.uniform(0.02, 0.6) if dur is None else dur)
        self.http.append(dict(ts=ts, uid=uid, s=s, sp=sp, d=d, dp=dp, method=method, host=host, uri=uri, ua=ua,
                              status=status, rb=rb))
        return uid

    def tls(self, ts, s, d, dp=443, sni="", ob=None, rb=None, dur=None, ja3="", ja3s="", log_ssl=True,
            state="SF"):
        """A TLS session; with ``log_ssl`` its handshake also goes to ssl.log."""
        uid, sp = self.session(ts, s, d, dp, svc="ssl" if state == "SF" else "-", ob=ob, rb=rb, dur=dur,
                               state=state)
        if log_ssl and state == "SF":
            self.ssl.append(dict(ts=ts, uid=uid, s=s, sp=sp, d=d, dp=dp, sni=sni, ja3=ja3, ja3s=ja3s))
        return uid

    def alert(self, ts, s, d, dp, sig, sid, category, sev=2, app="", blocked=False):
        """A Suricata alert. Names follow Emerging Threats style; the sids are local placeholders."""
        self.eve.append(dict(ts=ts, s=s, d=d, dp=dp, sig=sig, sid=sid, cat=category, sev=sev, app=app,
                             blocked=blocked))

    def note(self, ts, s, d, dp, note, msg):
        """A Zeek notice from a local detection script."""
        self.notice.append(dict(ts=ts, uid=self._uid(), s=s, d=d, dp=dp, note=note, msg=msg))


def _ts(t: datetime) -> str:
    return f"{t.timestamp():.6f}"


def _zeek(path, name, start, end, fields, types, rows):
    with open(path, "w") as fh:
        fh.write(f"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\t{name}\n"
                 f"#open\t{start.strftime('%Y-%m-%d-%H-%M-%S')}\n")
        fh.write("#fields\t" + "\t".join(fields) + "\n#types\t" + "\t".join(types) + "\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
        fh.write("#close\t" + end.strftime("%Y-%m-%d-%H-%M-%S") + "\n")


def _clean(text: str) -> str:
    return text.replace("\t", " ").replace("\n", " ") or "-"


def check_addresses(log: Log) -> None:
    """Every generated address must be a real address (no 2-octet prefixes)."""
    for r in log.conn + log.dns + log.eve + log.notice:
        ipaddress.ip_address(r["s"]), ipaddress.ip_address(r["d"])


def write_zeek(outdir, log: Log, start, end) -> list[str]:
    by_ts = lambda r: (r["ts"], r.get("uid", ""))
    paths = []
    p = os.path.join(outdir, "conn.log")
    _zeek(p, "conn", start, end,
          ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
           "orig_bytes", "resp_bytes", "conn_state", "history"],
          ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
           "string", "string"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), r["proto"], r["svc"],
            f"{r['dur']:.3f}", str(r["ob"]), str(r["rb"]), r["state"], HISTORY.get(r["state"], "S")]
           for r in sorted(log.conn, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "dns.log")
    _zeek(p, "dns", start, end,
          ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name",
           "rcode_name", "answers"],
          ["time", "string", "addr", "port", "addr", "port", "enum", "string", "string", "string", "vector[string]"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], "53", "udp", r["q"], r["qt"],
            "NOERROR" if r["a"] else "NXDOMAIN", r["a"] or "-"] for r in sorted(log.dns, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "http.log")
    _zeek(p, "http", start, end,
          ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "method", "host", "uri", "user_agent",
           "status_code", "response_body_len"],
          ["time", "string", "addr", "port", "addr", "port", "string", "string", "string", "string", "count", "count"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), r["method"], r["host"],
            _clean(r["uri"]), _clean(r["ua"]), str(r["status"]), str(r["rb"])] for r in sorted(log.http, key=by_ts)))
    paths.append(p)

    p = os.path.join(outdir, "ssl.log")
    _zeek(p, "ssl", start, end,
          ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "server_name", "established",
           "ja3", "ja3s"],
          ["time", "string", "addr", "port", "addr", "port", "string", "string", "bool", "string", "string"],
          ([_ts(r["ts"]), r["uid"], r["s"], str(r["sp"]), r["d"], str(r["dp"]), "TLSv13", r["sni"] or "-", "T",
            r["ja3"] or "-", r["ja3s"] or "-"] for r in sorted(log.ssl, key=by_ts)))
    paths.append(p)

    if log.notice:
        p = os.path.join(outdir, "notice.log")
        _zeek(p, "notice", start, end,
              ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "note", "msg", "src", "dst", "p",
               "actions"],
              ["time", "string", "addr", "port", "addr", "port", "string", "string", "addr", "addr", "port",
               "set[enum]"],
              ([_ts(r["ts"]), r["uid"], r["s"], "-", r["d"], str(r["dp"]), r["note"], _clean(r["msg"]), r["s"], r["d"],
                str(r["dp"]), "Notice::ACTION_LOG"] for r in sorted(log.notice, key=by_ts)))
        paths.append(p)
    return paths


def write_eve(path, log: Log, rng) -> str:
    with open(path, "w") as fh:
        for i, r in enumerate(sorted(log.eve, key=lambda r: (r["ts"], r["sid"], r["s"]))):
            ev = {"timestamp": r["ts"].strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000", "flow_id": 2_000_000 + i,
                  "event_type": "alert", "src_ip": r["s"], "src_port": rng.randint(49152, 65535), "dest_ip": r["d"],
                  "dest_port": r["dp"], "proto": "TCP",
                  "alert": {"action": "blocked" if r["blocked"] else "allowed", "gid": 1, "signature_id": r["sid"],
                            "rev": 1, "signature": r["sig"], "category": r["cat"], "severity": r["sev"]}}
            if r["app"]:
                ev["app_proto"] = r["app"]
            fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
    return path


def write_nessus(path, report_name, hosts: dict, vulns: list, scan_start: datetime) -> str:
    """``hosts``: ip -> (fqdn, os). ``vulns``: dicts with ip, port, svc, pid, name, sev, cvss, cves, expl, msf,
    syn, sol, family (optional), proto (optional)."""
    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report", name=report_name)
    for k, (ip, (fqdn, os_name)) in enumerate(hosts.items()):
        rh = ET.SubElement(report, "ReportHost", name=ip)
        hp = ET.SubElement(rh, "HostProperties")
        t = scan_start + timedelta(seconds=20 * k)
        for key, val in (("host-ip", ip), ("host-fqdn", fqdn), ("operating-system", os_name),
                         ("HOST_START_TIMESTAMP", str(int(t.timestamp()))),
                         ("HOST_END_TIMESTAMP", str(int(t.timestamp()) + 180))):
            ET.SubElement(hp, "tag", name=key).text = val
        ET.SubElement(rh, "ReportItem", port="0", svc_name="general", protocol="tcp", severity="0",
                      pluginID="19506", pluginName="Nessus Scan Information", pluginFamily="Settings")
        for v in vulns:
            if v["ip"] != ip:
                continue
            it = ET.SubElement(rh, "ReportItem", port=str(v["port"]), svc_name=v["svc"],
                               protocol=v.get("proto", "tcp"), severity=str(v["sev"]), pluginID=v["pid"],
                               pluginName=v["name"], pluginFamily=v.get("family", "General"))
            ET.SubElement(it, "cvss3_base_score").text = str(v["cvss"])
            for c in v["cves"]:
                ET.SubElement(it, "cve").text = c
            ET.SubElement(it, "exploit_available").text = "true" if v["expl"] else "false"
            if v["msf"]:
                ET.SubElement(it, "exploit_framework_metasploit").text = "true"
            ET.SubElement(it, "synopsis").text = v["syn"]
            ET.SubElement(it, "solution").text = v["sol"]
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
    return path


def write_iocs(path, rows: list[list]) -> str:
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(IOC_HEADER)
        w.writerows(rows)
    return path


def write_previews(path, previews: dict) -> str:
    with open(path, "w") as fh:
        json.dump(previews, fh, indent=2)
        fh.write("\n")
    return path


def vuln(ip, port, svc, pid, name, sev, cvss, cves=(), expl=False, msf=False, syn="", sol="", family="General",
         proto="tcp") -> dict:
    return dict(ip=ip, port=port, svc=svc, pid=pid, name=name, sev=sev, cvss=cvss, cves=list(cves), expl=expl,
                msf=msf, syn=syn, sol=sol, family=family, proto=proto)


def bursts(rng, start, total, burst=(2, 25), per=(4, 30), pause=(5, 40)):
    """Times for ``total`` requests sent the way agent workers send them: bursts of 2-25 seconds,
    a handful to a few dozen requests each, then a short pause while the model plans the next step."""
    out, t = [], start
    while len(out) < total:
        n = min(rng.randint(*per), total - len(out))
        span = rng.uniform(*burst)
        out += sorted(t + timedelta(seconds=rng.uniform(0, span)) for _ in range(n))
        t += timedelta(seconds=span + rng.uniform(*pause))
    return out
