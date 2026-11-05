"""Generic delimited flow parser (NetFlow/nfdump CSV, AWS VPC flow logs,
SIEM exports, etc.). Columns are matched by common header names."""
from __future__ import annotations

import csv

from ..schema import Flow, ParseStats
from ._util import clean_ip, clean_port, clean_proto, norm_header, open_text, parse_ts, to_int

ALIASES = {
    "src_ip": ["src_ip", "src", "source", "source_ip", "sa", "srcaddr", "src_addr",
               "id.orig_h", "source_address", "client_ip"],
    "dst_ip": ["dst_ip", "dst", "dest", "destination", "destination_ip", "da", "dstaddr",
               "dst_addr", "dest_ip", "id.resp_h", "destination_address", "server_ip"],
    "src_port": ["src_port", "sport", "sp", "srcport", "id.orig_p", "source_port"],
    "dst_port": ["dst_port", "dport", "dp", "dstport", "dest_port", "id.resp_p",
                 "destination_port", "port"],
    "proto": ["proto", "protocol", "pr", "transport", "ip_protocol"],
    "ts": ["ts", "timestamp", "time", "start", "start_time", "_time", "ts_start",
           "first_seen", "event_time", "date"],
    "action": ["action", "disposition", "verdict"],
    "bytes_out": ["bytes_out", "orig_bytes", "out_bytes", "ibyt", "bytes_sent",
                  "sent_bytes", "bytes"],
    "bytes_in": ["bytes_in", "resp_bytes", "in_bytes", "obyt", "bytes_received", "rcvd_bytes"],
    "app": ["app", "application", "service", "app_name"],
}
DENY = ("deny", "denied", "drop", "dropped", "reject", "rejected", "block", "blocked", "reset")


def parse(path: str, stats: ParseStats):
    with open_text(path, newline="") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample.splitlines()[0], delimiters=",\t;| ")
        except (csv.Error, IndexError):
            dialect = csv.excel
        reader = csv.reader(fh, dialect)
        header = [norm_header(h) for h in next(reader, [])]
        idx = {}
        for key, aliases in ALIASES.items():
            for a in aliases:
                if a in header:
                    idx[key] = header.index(a)
                    break
        if "src_ip" not in idx or "dst_ip" not in idx:
            stats.note("could not find source/destination IP columns; header was: "
                       + ", ".join(header[:15]))
            for row in reader:
                stats.read += 1
                stats.drop("unmapped columns")
            return
        for row in reader:
            if not any(c.strip() for c in row):
                continue
            stats.read += 1
            get = lambda k: row[idx[k]] if k in idx and idx[k] < len(row) else None
            src, dst = clean_ip(get("src_ip")), clean_ip(get("dst_ip"))
            if not src or not dst:
                stats.drop("missing or invalid IP")
                continue
            action = "deny" if (get("action") or "").strip().lower().startswith(DENY) else "allow"
            b_out, b_in = to_int(get("bytes_out"), 0), to_int(get("bytes_in"), 0)
            ts = parse_ts(get("ts"))
            if ts is None:
                stats.note("some rows had no parseable timestamp (kept, untimed)")
            yield Flow(
                ts=ts, src_ip=src, dst_ip=dst,
                src_port=clean_port(get("src_port")), dst_port=clean_port(get("dst_port")),
                proto=clean_proto(get("proto")), action=action,
                # without response bytes we can only assume allowed == established
                established=action == "allow" and ("bytes_in" not in idx or b_in > 0),
                bytes_out=b_out, bytes_in=b_in, app=(get("app") or "").strip(),
            )
