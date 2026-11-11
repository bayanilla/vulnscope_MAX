"""Zeek ASCII/JSON log reader with explicit stream classification."""
from __future__ import annotations

import json
import os
import re

from ..schema import Flow, OTEvent, ParseStats, ThreatEvent, ZeekEvent
from ._util import clean_ip, clean_port, clean_proto, open_text, parse_ts, to_int

ESTABLISHED_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}
# REJ: the responder answered the SYN with a reset. Usually the host itself refused (closed port or
# host firewall), so it is recorded as "reject", not as a network firewall "deny". RSTOS0/RSTRH are
# aborted handshakes and count as plain attempts.
REJECTED_STATES = {"REJ"}
OT_PREFIXES = {"modbus": "Modbus", "dnp3": "DNP3", "bacnet": "BACnet",
               "s7comm": "S7", "cotp": "S7", "enip": "EtherNet/IP",
               "cip": "CIP", "opcua": "OPC UA"}


def stream_from_name(path: str) -> str:
    """Use the upload-safe basename; never infer a stream from shared ID fields."""
    name = os.path.basename(path)
    name = re.sub(r"^\d+_", "", name)
    name = re.sub(r"\.(?:log|json)(?:\.gz)?$", "", name, flags=re.I)
    name = re.sub(r"\.\d{4}-\d{2}-\d{2}(?:[-_T].*)?$", "", name)
    return name or "unknown"


def _to_flow(rec: dict, stats: ParseStats) -> Flow | None:
    if not any(k in rec for k in ("conn_state", "orig_bytes", "resp_bytes", "history", "duration")):
        stats.drop("conn record missing connection fields")
        return None
    src, dst = clean_ip(rec.get("id.orig_h")), clean_ip(rec.get("id.resp_h"))
    if not src or not dst:
        stats.drop("missing or invalid IP")
        return None
    state = (rec.get("conn_state") or "").upper()
    # Filebeat drops orig_bytes/resp_bytes; fall back to the IP-level counts only when absent.
    b_out = to_int(rec["orig_bytes"] if "orig_bytes" in rec else rec.get("orig_ip_bytes"), 0)
    b_in = to_int(rec["resp_bytes"] if "resp_bytes" in rec else rec.get("resp_ip_bytes"), 0)
    ts = parse_ts(rec.get("ts"))
    if ts is None:
        stats.note("some rows had no parseable timestamp (kept, untimed)")
    return Flow(
        ts=ts, src_ip=src, dst_ip=dst,
        src_port=clean_port(rec.get("id.orig_p")), dst_port=clean_port(rec.get("id.resp_p")),
        proto=clean_proto(rec.get("proto")),
        action="reject" if state in REJECTED_STATES else "allow",
        established=state in ESTABLISHED_STATES or (b_out > 0 and b_in > 0),
        bytes_out=b_out, bytes_in=b_in, app=rec.get("service") or "",
    )


def _notice(rec: dict, stats: ParseStats) -> ThreatEvent | None:
    src, dst = clean_ip(rec.get("src") or rec.get("id.orig_h")), clean_ip(rec.get("dst") or rec.get("id.resp_h"))
    if not src or not dst:
        stats.drop("notice without source/destination IP")
        return None
    actions = rec.get("actions") or ""
    if isinstance(actions, list):
        actions = ",".join(actions)
    return ThreatEvent(ts=parse_ts(rec.get("ts")), src_ip=src, dst_ip=dst,
                       dst_port=clean_port(rec.get("p") or rec.get("id.resp_p")),
                       name=" - ".join(x for x in (rec.get("note"), rec.get("msg")) if x) or "Zeek notice",
                       action="block" if "DROP" in actions.upper() else "alert")


def _event(rec: dict, stream: str) -> ZeekEvent:
    common = dict(ts=parse_ts(rec.get("ts")), stream=stream,
                  uid=str(rec.get("uid") or ""), fields=rec)
    protocol = next((name for prefix, name in OT_PREFIXES.items()
                     if stream == prefix or stream.startswith(prefix + "_")), "")
    if protocol:
        is_orig = str(rec.get("is_orig", "")).lower()
        direction = ("originator" if is_orig in ("t", "true", "1") else
                     "responder" if is_orig in ("f", "false", "0") else "unknown")
        orig, resp = rec.get("id.orig_h"), rec.get("id.resp_h")
        src = rec.get("source_h") or rec.get("src")
        dst = rec.get("destination_h") or rec.get("dst")
        if not src and direction != "unknown":
            src = orig if direction == "originator" else resp
        if not dst and direction != "unknown":
            dst = resp if direction == "originator" else orig
        operation = next((str(rec[k]) for k in
                          ("func", "function", "fc_request", "fc_reply", "service", "pdu_type", "operation")
                          if rec.get(k) not in (None, "")), "")
        return OTEvent(src_ip=clean_ip(src), dst_ip=clean_ip(dst),
                       protocol=protocol, operation=operation, direction=direction, **common)
    return ZeekEvent(src_ip=clean_ip(rec.get("id.orig_h") or rec.get("src")),
                     dst_ip=clean_ip(rec.get("id.resp_h") or rec.get("dst")), **common)


def _decode_separator(value: str) -> str:
    try:
        return value.encode("utf-8").decode("unicode_escape")
    except UnicodeError:
        return value


def _typed_value(value: str, kind: str, set_sep: str, empty: str, unset: str):
    if value == unset:
        return None
    if kind.startswith(("set[", "vector[")):
        if value == empty:
            return []
        inner = kind[kind.find("[") + 1:-1]
        return [_typed_value(v, inner, set_sep, empty, unset) for v in value.split(set_sep)]
    if value == empty:
        return ""
    try:
        if kind in ("count", "int", "port"):
            return int(value)
        if kind in ("double", "time", "interval"):
            return float(value)
        if kind == "bool":
            return value in ("T", "true")
    except ValueError:
        pass
    return value


def parse(path: str, stats: ParseStats):
    """Yield Flow, ThreatEvent, ZeekEvent and OTEvent records one at a time."""
    sep, fields, types, stream = "\t", None, None, stream_from_name(path)
    set_sep, empty, unset = ",", "(empty)", "-"
    generic_streams: set[str] = set()
    with open_text(path) as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#separator "):
                    sep = _decode_separator(line.split(" ", 1)[1])
                elif sep in line:
                    key, value = line.split(sep, 1)
                    if key == "#fields":
                        fields = value.split(sep)
                    elif key == "#types":
                        types = value.split(sep)
                    elif key == "#path":
                        stream = value.strip()
                    elif key == "#set_separator":
                        set_sep = value
                    elif key == "#empty_field":
                        empty = value
                    elif key == "#unset_field":
                        unset = value
                continue
            stats.read += 1
            if line.lstrip().startswith("{"):
                try:
                    rec = json.loads(line)
                    if not isinstance(rec, dict):
                        raise ValueError
                except (json.JSONDecodeError, ValueError):
                    stats.drop("malformed JSON")
                    continue
                row_stream = str(rec.get("_path") or stream)
            else:
                if fields is None:
                    stats.drop("no #fields header")
                    continue
                vals = line.split(sep)
                if len(vals) != len(fields):
                    stats.drop("column count mismatch")
                    continue
                row_types = types if types and len(types) == len(fields) else ["string"] * len(fields)
                rec = {k: _typed_value(v, kind, set_sep, empty, unset)
                       for k, v, kind in zip(fields, vals, row_types)}
                row_stream = stream
            if row_stream == "conn":
                item = _to_flow(rec, stats)
            elif row_stream == "notice":
                item = _notice(rec, stats)
            else:
                item = _event(rec, row_stream)
                generic_streams.add(row_stream)
            if item is not None:
                yield item
    if generic_streams:
        stats.note("Zeek stream records preserved as events; only conn sessions and notice alerts affect scoring")
