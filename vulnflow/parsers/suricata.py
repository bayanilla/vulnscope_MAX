"""Suricata EVE JSON parser: `alert` events become threat events, `flow` events become flows."""
from __future__ import annotations

import json

from ..schema import Flow, ParseStats, ThreatEvent
from ._util import clean_ip, clean_port, clean_proto, open_text, parse_ts, to_int


def parse(path: str, stats: ParseStats):
    with open_text(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            stats.read += 1
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                stats.drop("malformed JSON")
                continue
            kind = ev.get("event_type")
            if kind not in ("alert", "flow"):
                stats.drop(f"{kind} events not used")
                continue
            src, dst = clean_ip(ev.get("src_ip")), clean_ip(ev.get("dest_ip"))
            if not src or not dst:
                stats.drop("missing or invalid IP")
                continue
            if kind == "alert":
                a = ev.get("alert") or {}
                yield (ThreatEvent(ts=parse_ts(ev.get("timestamp")), src_ip=src, dst_ip=dst,
                                       dst_port=clean_port(ev.get("dest_port")),
                                       name=a.get("signature") or "Suricata alert",
                                       severity=str(a.get("severity", "")),
                                       action="block" if a.get("action") == "blocked" else "alert"))
            else:
                f = ev.get("flow") or {}
                b_out, b_in = to_int(f.get("bytes_toserver"), 0), to_int(f.get("bytes_toclient"), 0)
                yield (Flow(ts=parse_ts(f.get("start") or ev.get("timestamp")), src_ip=src, dst_ip=dst,
                                src_port=clean_port(ev.get("src_port")), dst_port=clean_port(ev.get("dest_port")),
                                proto=clean_proto(ev.get("proto")),
                                action="deny" if f.get("action") == "drop" else "allow",
                                established=(f.get("state") in ("established", "closed") and b_in > 0),
                                bytes_out=b_out, bytes_in=b_in, app=ev.get("app_proto") or ""))
