"""Ground truth from raw Zeek logs and Suricata EVE, written separately from VulnScope.

Nothing here imports vulnflow: it reads the logs itself and applies the definitions in METHODS.md,
so a bug in VulnScope's parsers or SQL cannot hide by being repeated here.
"""
import collections
import datetime
import glob
import gzip
import ipaddress
import json
import os
import re

INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]
# Zeek's own bookkeeping logs, and capture_loss (a sensor-quality signal, not activity)
NOT_ACTIVITY = {"loaded_scripts", "packet_filter", "stats", "capture_loss", "reporter", "telemetry",
                "print", "broker", "cluster", "config"}
COMPLETED = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}

_internal = {}


def internal(addr):
    if addr not in _internal:
        try:
            ip = ipaddress.ip_address(addr)
            _internal[addr] = any(ip in n for n in INTERNAL)
        except ValueError:
            _internal[addr] = False
    return _internal[addr]


def multicast_or_broadcast(addr):
    try:
        return ipaddress.ip_address(addr).is_multicast or addr == "255.255.255.255"
    except ValueError:
        return False


def two_way(c):
    """Both sides exchanged packets: a completed handshake, data both ways, a mid-stream TCP
    session with an ACK or data from each side, or UDP/ICMP packets in both directions."""
    state = c.get("conn_state")
    if state in COMPLETED:
        return True
    if (c.get("orig_bytes") or 0) > 0 and (c.get("resp_bytes") or 0) > 0:
        return True
    if c.get("proto") == "tcp":
        hist = (c.get("history") or "").replace("^", "")
        return state in ("OTH", "SH", "SHR") and any(x in hist for x in "AD") and any(x in hist for x in "ad")
    return (c.get("orig_pkts") or 0) > 0 and (c.get("resp_pkts") or 0) > 0


def answered(c):
    return two_way(c) or c.get("conn_state") == "REJ" or (c.get("resp_bytes") or 0) > 0


# -- readers ---------------------------------------------------------------------------------

def _open(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")


_DUR = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600, "d": 86400}


def _norm(rec):
    """Flatten nested objects (Zui exports) and turn ISO times / Zed durations into seconds."""
    flat = {}
    for k, v in rec.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                flat[f"{k}.{k2}"] = v2
        elif v is not None:
            flat[k] = v
    if isinstance(flat.get("ts"), str):
        flat["ts"] = datetime.datetime.fromisoformat(flat["ts"].replace("Z", "+00:00")).timestamp()
    d = flat.get("duration")
    if isinstance(d, str):
        try:
            flat["duration"] = float(d)
        except ValueError:
            flat["duration"] = sum(float(n) * _DUR[u] for n, u in re.findall(r"([0-9.]+)(ns|us|ms|s|m|h|d)", d))
    return flat


def _stream_name(path):
    name = os.path.basename(path)
    name = re.sub(r"\.(log|json)(\.gz)?$", "", name)
    name = name.split(".")[0]
    return name.split("-")[-1]            # "alerts-conn" (VulnScope PCAP output) -> "conn"


def read_zeek(path):
    """Yield (stream, record) from a Zeek TSV, Zeek JSON-lines or Zui JSON-array file."""
    with _open(path) as fh:
        if fh.read(1) == "[":
            fh.seek(0)
            for rec in json.load(fh):
                rec = _norm(rec)
                yield rec.pop("_path"), rec
            return
    stream = _stream_name(path)
    fields = types = None
    sep, unset, empty = "\t", "-", "(empty)"
    with _open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                rec = _norm(json.loads(line))
                yield rec.pop("_path", stream), rec
                continue
            if line.startswith("#"):
                key, _, value = line.partition(sep if not line.startswith("#separator") else " ")
                if key == "#separator":
                    sep = value.encode().decode("unicode_escape")
                elif key == "#fields":
                    fields = value.split(sep)
                elif key == "#types":
                    types = value.split(sep)
                elif key == "#unset_field":
                    unset = value
                elif key == "#empty_field":
                    empty = value
                elif key == "#path":
                    stream = value
                continue
            rec = {}
            for f, t, v in zip(fields, types, line.split(sep)):
                if v == unset:
                    continue
                if t in ("count", "int", "port"):
                    v = int(v)
                elif t in ("time", "interval", "double"):
                    v = float(v)
                elif t.startswith(("set", "vector")):
                    v = [] if v == empty else v.split(",")
                rec[f] = v
            yield stream, rec


def read_folder(folder):
    streams = collections.defaultdict(list)
    eve = []
    for path in sorted(glob.glob(os.path.join(folder, "**", "*"), recursive=True)):
        if not os.path.isfile(path):
            continue
        base = os.path.basename(path)
        if base.startswith("eve") and ".json" in base:
            with _open(path) as fh:
                eve += [json.loads(l) for l in fh if l.strip()]
        elif re.search(r"\.(log|json)(\.gz)?$", base):
            for stream, rec in read_zeek(path):
                if stream not in NOT_ACTIVITY:
                    streams[stream].append(rec)
    return streams, eve


# -- ground truth ----------------------------------------------------------------------------

def zeek_truth(folder):
    streams, eve = read_folder(folder)
    conn = streams.pop("conn", [])
    notices = [n for n in streams.get("notice", [])
               if n.get("src") or n.get("dst") or n.get("id.orig_h") or n.get("id.resp_h")]
    seen, unique = set(), []
    for c in conn:
        key = (c.get("uid"), c.get("ts"), c.get("id.orig_h"), c.get("id.orig_p"), c.get("id.resp_h"),
               c.get("id.resp_p"), c.get("proto"))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    conn = unique

    hosts, probed_targets, tcp_targets, n_answered = set(), set(), set(), 0
    inbound, outbound = collections.Counter(), collections.Counter()
    ext = collections.defaultdict(collections.Counter)
    pairs, failed, total = collections.defaultdict(set), collections.Counter(), collections.Counter()
    for c in conn:
        o, r = c["id.orig_h"], c["id.resp_h"]
        ans = answered(c)
        n_answered += ans
        if internal(o):
            hosts.add(o)
            outbound[o] += 1
            if not internal(r) and not multicast_or_broadcast(r) and two_way(c):
                ext[o][r] += 1
        if internal(r):
            inbound[r] += 1
            probed_targets.add(r)
            if ans:
                hosts.add(r)
            if c.get("proto") == "tcp":
                tcp_targets.add(r)
        pairs[o].add((r, c.get("id.resp_p")))
        total[o] += 1
        failed[o] += not two_way(c)

    scanners = {h for h in pairs if len(pairs[h]) >= 100 and failed[h] >= 0.7 * total[h]}
    scanners |= {n["src"] for n in notices if str(n.get("note", "")).startswith("Scan::") and n.get("src")}

    def broadcast(a):
        return multicast_or_broadcast(a) or (a.endswith(".255") and a not in tcp_targets)

    alerts = [(n.get("src") or n.get("id.orig_h"), n.get("dst") or n.get("id.resp_h")) for n in notices]
    alerts += [(e["src_ip"], e["dest_ip"]) for e in eve if e.get("event_type") == "alert"]
    leads = collections.defaultdict(lambda: [0, set()])
    for s, d in alerts:
        for ip, role in ((s, "source"), (d, "target")):
            if ip and internal(ip):
                leads[ip][0] += 1
                leads[ip][1].add(role)

    ts = [c["ts"] for c in conn]
    return {
        "sessions": len(conn),
        "window_start": min(ts) if ts else None,
        "window_end": max(ts) if ts else None,
        "hosts": sorted(hosts),
        "probed_only": len({a for a in probed_targets - hosts if not broadcast(a)}),
        "answered_pct": round(100 * n_answered / len(conn), 1) if conn else None,
        "alerts": len(alerts),
        "event_counts": {s: len(v) for s, v in sorted(streams.items()) if s != "notice"},
        "per_host": {h: {"in": inbound[h], "out": outbound[h], "ext": len(ext[h]),
                         "top_ext": sorted(n for _, n in ext[h].most_common(5))} for h in hosts},
        "leads": {h: {"alerts": v[0], "role": sorted(v[1])} for h, v in leads.items()},
        "scanners": {h: {"sessions": total[h], "targets": len(pairs[h]),
                         "hosts": len({a for a, _ in pairs[h]}), "ports": len({p for _, p in pairs[h]}),
                         "failed_pct": round(100 * failed[h] / total[h])} for h in sorted(scanners)},
    }


def suricata_only_truth(eve_path, zeek_folder):
    """Suricata EVE alone. Each flow's direction is taken from Zeek's record of the same session
    (Zeek decides who is the client independently); flows Zeek did not log keep Suricata's order."""
    streams, _ = read_folder(zeek_folder)
    side = {}
    for c in streams.get("conn", []):
        a = (c["id.orig_h"], c.get("id.orig_p"), c["id.resp_h"], c.get("id.resp_p"), c.get("proto"))
        side[a] = (a[0], a[2])
        side[(a[2], a[3], a[0], a[1], a[4])] = (a[0], a[2])
    with _open(eve_path) as fh:
        eve = [json.loads(l) for l in fh if l.strip()]
    inbound, outbound, flows = collections.Counter(), collections.Counter(), 0
    for e in eve:
        if e.get("event_type") != "flow":
            continue
        flows += 1
        key = (e["src_ip"], e.get("src_port"), e["dest_ip"], e.get("dest_port"), e.get("proto", "").lower())
        o, r = side.get(key, (e["src_ip"], e["dest_ip"]))
        if internal(o):
            outbound[o] += 1
        if internal(r):
            inbound[r] += 1
    alerts = [e for e in eve if e.get("event_type") == "alert"]
    leads = collections.defaultdict(lambda: [0, set()])
    for e in alerts:
        for ip, role in ((e["src_ip"], "source"), (e["dest_ip"], "target")):
            if internal(ip):
                leads[ip][0] += 1
                leads[ip][1].add(role)
    return {"sessions": flows, "alerts": len(alerts),
            "per_host": {h: {"in": inbound[h], "out": outbound[h]} for h in set(inbound) | set(outbound)},
            "leads": {h: {"alerts": v[0], "role": sorted(v[1])} for h, v in leads.items()}}
