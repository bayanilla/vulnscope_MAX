"""Palo Alto Networks TRAFFIC log parser.

Handles both the CSV exported from the web UI / Panorama (with a header row)
and raw syslog lines in the PAN-OS default CSV order (no header).
"""
from __future__ import annotations

import csv

from ..schema import Flow, ParseStats, ThreatEvent
from ._util import clean_ip, clean_port, clean_proto, norm_header, open_text, parse_ts, to_int

# Offsets relative to the "Type" column (which holds TRAFFIC) in syslog CSV.
SYSLOG_OFFSETS = {
    "ts": 3, "src_ip": 4, "dst_ip": 5, "app": 11, "src_zone": 13, "dst_zone": 14,
    "src_port": 21, "dst_port": 22, "proto": 26, "action": 27, "bytes": 28,
    "bytes_sent": 29, "bytes_received": 30, "start": 32,
}
HEADER_ALIASES = {
    "ts": ["start_time", "generate_time", "receive_time", "time_logged"],
    "src_ip": ["source_address", "source_ip", "src_ip"],
    "dst_ip": ["destination_address", "destination_ip", "dst_ip"],
    "src_port": ["source_port", "src_port"],
    "dst_port": ["destination_port", "dst_port"],
    "proto": ["ip_protocol", "protocol"],
    "action": ["action"],
    "app": ["application"],
    "src_zone": ["source_zone", "from_zone"],
    "dst_zone": ["destination_zone", "to_zone"],
    "bytes_sent": ["bytes_sent"],
    "bytes_received": ["bytes_received"],
    "type": ["type"],
    "threat": ["threat/content_name", "threat_name", "threat_id", "name"],
    "severity": ["severity"],
}
# THREAT logs share the TRAFFIC layout up to Action, then carry these (offsets from Type)
THREAT_OFFSETS = {"threat": 29, "severity": 31}
DENY_ACTIONS = ("deny", "drop", "reset", "block")


def _flow(get, stats: ParseStats) -> Flow | None:
    src, dst = clean_ip(get("src_ip")), clean_ip(get("dst_ip"))
    if not src or not dst:
        stats.drop("missing or invalid IP")
        return None
    action_raw = (get("action") or "").strip().lower()
    action = "deny" if action_raw.startswith(DENY_ACTIONS) else "allow"
    b_out, b_in = to_int(get("bytes_sent"), 0), to_int(get("bytes_received"), 0)
    ts = parse_ts(get("ts"))
    if ts is None:
        stats.note("some rows had no parseable timestamp (kept, untimed)")
    return Flow(
        ts=ts, src_ip=src, dst_ip=dst,
        src_port=clean_port(get("src_port")), dst_port=clean_port(get("dst_port")),
        proto=clean_proto(get("proto")), action=action,
        established=action == "allow" and (b_in > 0 or get("bytes_received") is None),
        bytes_out=b_out, bytes_in=b_in, app=(get("app") or "").strip(),
        src_zone=(get("src_zone") or "").strip().lower(),
        dst_zone=(get("dst_zone") or "").strip().lower(),
    )


def _threat(get, stats: ParseStats) -> ThreatEvent | None:
    src, dst = clean_ip(get("src_ip")), clean_ip(get("dst_ip"))
    if not src or not dst:
        stats.drop("missing or invalid IP")
        return None
    return ThreatEvent(ts=parse_ts(get("ts")), src_ip=src, dst_ip=dst, dst_port=clean_port(get("dst_port")),
                       name=(get("threat") or "unnamed threat").strip(), severity=(get("severity") or "").strip().lower(),
                       action=(get("action") or "alert").strip().lower())


def parse(path: str, stats: ParseStats):
    stats.note("firewall timestamps are assumed to be UTC")
    # yields Flow records plus ThreatEvent records from THREAT rows; .gz exports are read directly
    with open_text(path, newline="") as fh:
        first = fh.readline()
        fh.seek(0)
        low = first.lower()
        if "source address" in low or "destination port" in low:
            reader = csv.reader(fh)
            header = [norm_header(h) for h in next(reader)]
            idx = {}
            for key, aliases in HEADER_ALIASES.items():
                for a in aliases:
                    if a in header:
                        idx[key] = header.index(a)
                        break
            # every time column the export has, in preference order: THREAT rows leave Start Time
            # empty, so each row falls back to the next column that has a value (e.g. Receive Time)
            ts_cols = [header.index(a) for a in HEADER_ALIASES["ts"] if a in header]

            def get(k):
                if k == "ts":
                    return next((row[i] for i in ts_cols if i < len(row) and row[i].strip()), None)
                return row[idx[k]] if k in idx and idx[k] < len(row) else None
            for row in reader:
                if not any(c.strip() for c in row):
                    continue
                stats.read += 1
                kind = (get("type") or "TRAFFIC").strip().upper()
                if kind == "THREAT":
                    t = _threat(get, stats)
                    if t:
                        yield t
                    continue
                if kind != "TRAFFIC":
                    stats.drop(f"{kind} log type not used")
                    continue
                flow = _flow(get, stats)
                if flow:
                    yield flow
        else:
            for line in fh:
                if not line.strip():
                    continue
                stats.read += 1
                row = next(csv.reader([line.strip()]))
                base = next((i for i, c in enumerate(row) if c.strip() in
                             ("TRAFFIC", "THREAT", "SYSTEM", "CONFIG")), None)
                if base is None:
                    stats.drop("unrecognized line")
                    continue
                kind = row[base].strip()
                if kind not in ("TRAFFIC", "THREAT"):
                    stats.drop(f"{kind} log type not used")
                    continue

                def get(k, row=row, base=base, kind=kind):
                    if k == "ts":
                        i = base + SYSLOG_OFFSETS["start"]
                        v = row[i] if kind == "TRAFFIC" and i < len(row) else None
                        return v or row[base + SYSLOG_OFFSETS["ts"]]
                    off = THREAT_OFFSETS.get(k) if kind == "THREAT" else None
                    off = off if off is not None else SYSLOG_OFFSETS.get(k)
                    i = base + off if off is not None else None
                    return row[i] if i is not None and i < len(row) else None
                if kind == "THREAT":
                    t = _threat(get, stats)
                    if t:
                        yield t
                    continue
                flow = _flow(get, stats)
                if flow:
                    yield flow
