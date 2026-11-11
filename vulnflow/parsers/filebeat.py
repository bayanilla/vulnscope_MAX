"""Zeek logs that Filebeat shipped to Elasticsearch, exported again as CSV or NDJSON.

Filebeat's Zeek module (and the Elastic Agent Zeek integration) rewrites each Zeek record
into ECS fields: ``id.orig_h`` becomes ``source.ip``, ``uid`` becomes ``zeek.session_id``,
``conn_state`` becomes ``zeek.connection.state``, ``ts`` becomes ``@timestamp`` and so on,
and adds its own fields (geo, ``related.*``, ``agent.*``, ``host.*``, ``tags``). A Kibana
Discover "CSV report", an ``elasticdump``/``_search`` NDJSON dump, or Filebeat's own file
output then carries those ECS rows.

This module undoes that: each row goes back to the Zeek field names of its log (conn, dns,
http, ssl, notice, ...). When the row still holds the raw Zeek line (``event.original``, kept
by the dns/intel/ntp/signature filesets and by the "preserve original event" option, or a
``message`` column) that line is used as is. Otherwise the record is rebuilt from the ECS
columns with the rename table below, generated from the Filebeat module configs
(x-pack/filebeat/module/zeek/*/config/*.yml).

Two things cannot be recovered and are reported: Filebeat drops conn.log ``orig_bytes``,
``resp_bytes`` and ``tunnel_parents`` (the IP-level ``orig_ip_bytes``/``resp_ip_bytes``
survive as ``source.bytes``/``destination.bytes``), and notice.log ``actions``.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

from ..schema import ParseStats
from . import zeek
from ._util import open_text, parse_ts

# Filebeat fileset name -> Zeek log (stream) name, where they differ.
STREAM_FOR_FILESET = {"connection": "conn", "signature": "signatures"}

# ECS fields every fileset fills the same way (fileset-specific entries below win).
COMMON = {
    "source.ip": "id.orig_h", "source.address": "id.orig_h", "source.port": "id.orig_p",
    "destination.ip": "id.resp_h", "destination.address": "id.resp_h", "destination.port": "id.resp_p",
    "zeek.session_id": "uid", "event.id": "uid", "network.transport": "proto",
}

# Final Filebeat field -> original Zeek field, per fileset. Generated from the rename/convert
# processors in elastic/beats x-pack/filebeat/module/zeek/*/config/*.yml. Fields that only
# moved under zeek.<fileset>. (e.g. zeek.connection.history) are handled by stripping the prefix.
ALIASES = {
    "connection": {"destination.bytes": "resp_ip_bytes", "destination.mac": "resp_l2_addr", "destination.packets": "resp_pkts", "network.protocol": "service", "source.bytes": "orig_ip_bytes", "source.mac": "orig_l2_addr", "source.packets": "orig_pkts", "temp.duration": "duration", "zeek.connection.icmp.code": "id.resp_p", "zeek.connection.icmp.type": "id.orig_p", "zeek.connection.state": "conn_state"},
    "dhcp": {"client.address": "client_addr", "destination.address": "server_addr", "destination.ip": "server_addr", "destination.port": "server_port", "network.name": "domain", "server.address": "server_addr", "source.address": "client_addr", "source.ip": "client_addr", "source.port": "client_port", "zeek.dhcp.address.assigned": "assigned_addr", "zeek.dhcp.address.client": "client_addr", "zeek.dhcp.address.mac": "mac", "zeek.dhcp.address.requested": "requested_addr", "zeek.dhcp.address.server": "server_addr", "zeek.dhcp.hostname": "host_name", "zeek.dhcp.id.circuit": "circuit_id", "zeek.dhcp.id.remote_agent": "agent_remote_id", "zeek.dhcp.id.subscriber": "subscriber_id", "zeek.dhcp.msg.client": "client_message", "zeek.dhcp.msg.origin": "msg_orig", "zeek.dhcp.msg.server": "server_message", "zeek.dhcp.msg.types": "msg_types", "zeek.dhcp.software.client": "client_software", "zeek.dhcp.software.server": "server_software", "zeek.session_id": "uids", "event.id": "uids"},
    "dnp3": {"zeek.dnp3.function.reply": "fc_reply", "zeek.dnp3.function.request": "fc_request", "zeek.dnp3.id": "iin"},
    "dns": {"dns.id": "trans_id", "dns.question.name": "query", "dns.question.type": "qtype_name", "dns.response_code": "rcode_name"},
    "files": {"file.hash.md5": "md5", "file.hash.sha1": "sha1", "file.hash.sha256": "sha256", "file.mime_type": "mime_type", "file.name": "filename", "file.size": "total_bytes", "zeek.files.session_ids": "conn_uids"},
    "ftp": {"event.action": "command", "file.size": "file_size", "user.name": "user", "zeek.ftp.data_channel.originating_host": "data_channel.orig_h", "zeek.ftp.data_channel.response_host": "data_channel.resp_h", "zeek.ftp.data_channel.response_port": "data_channel.resp_p", "zeek.ftp.file.mime_type": "mime_type", "zeek.ftp.file.size": "file_size", "zeek.ftp.file.uid": "fuid", "zeek.ftp.reply.code": "reply_code", "zeek.ftp.reply.msg": "reply_msg"},
    "http": {"event.action": "method", "http.request.body.bytes": "request_body_len", "http.request.method": "method", "http.request.referrer": "referrer", "http.response.body.bytes": "response_body_len", "http.response.status_code": "status_code", "http.version": "version", "url.domain": "host", "url.original": "uri", "url.password": "password", "url.username": "username", "user.name": "username", "user_agent.original": "user_agent"},
    "irc": {"event.action": "command", "file.name": "dcc_file_name", "file.size": "dcc_file_size", "user.name": "user", "zeek.irc.dcc.file.name": "dcc_file_name", "zeek.irc.dcc.file.size": "dcc_file_size"},
    "kerberos": {"event.action": "request_type", "zeek.kerberos.cert.client.fuid": "cert.client_fuid", "zeek.kerberos.cert.client.subject": "cert.client_subject", "zeek.kerberos.cert.client.value": "cert.client", "zeek.kerberos.cert.server.fuid": "cert.server_fuid", "zeek.kerberos.cert.server.subject": "cert.server_subject", "zeek.kerberos.cert.server.value": "cert.server", "zeek.kerberos.error.code": "error_code", "zeek.kerberos.error.msg": "error_msg", "zeek.kerberos.ticket.auth": "auth_ticket", "zeek.kerberos.ticket.new": "new_ticket", "zeek.kerberos.valid.from": "from", "zeek.kerberos.valid.until": "till"},
    "modbus": {"event.action": "func", "zeek.modbus.function": "func"},
    "mysql": {"event.action": "cmd"},
    "notice": {"file.mime_type": "file_mime_type", "file.size": "f.total_bytes", "rule.description": "msg", "rule.name": "note", "zeek.notice.connnection_id": "conn", "zeek.notice.connection_id": "conn", "zeek.notice.file.id": "f.id", "zeek.notice.file.is_orig": "f.is_orig", "zeek.notice.file.mime_type": "file_mime_type", "zeek.notice.file.parent_id": "f.parent_id", "zeek.notice.file.seen_bytes": "f.seen_bytes", "zeek.notice.file.source": "f.source", "zeek.notice.file.total_bytes": "f.total_bytes", "zeek.notice.icmp_id": "iconn"},
    "ntlm": {"user.domain": "domainname", "user.name": "username", "zeek.ntlm.domain": "domainname", "zeek.ntlm.server.name.dns": "server_dns_computer_name", "zeek.ntlm.server.name.netbios": "server_nb_computer_name", "zeek.ntlm.server.name.tree": "server_tree_name"},
    "ocsp": {"zeek.ocsp.file_id": "id", "zeek.ocsp.hash.algorithm": "hashAlgorithm", "zeek.ocsp.hash.issuer.key": "issuerKeyHash", "zeek.ocsp.hash.issuer.name": "issuerNameHash", "zeek.ocsp.revoke.date": "revoketime", "zeek.ocsp.revoke.reason": "revokereason", "zeek.ocsp.serial_number": "serialNumber", "zeek.ocsp.status": "certStatus", "zeek.ocsp.update.next": "nextUpdate", "zeek.ocsp.update.this": "thisUpdate"},
    "pe": {"zeek.pe.compile_time": "compile_ts"},
    "radius": {"event.outcome": "result", "user.name": "username"},
    "rdp": {"zeek.rdp.cert.count": "cert_count", "zeek.rdp.cert.permanent": "cert_permanent", "zeek.rdp.cert.type": "cert_type", "zeek.rdp.client.build": "client_build", "zeek.rdp.client.name": "client_name", "zeek.rdp.client.product_id": "client_dig_product_id", "zeek.rdp.desktop.color_depth": "requested_color_depth", "zeek.rdp.desktop.height": "desktop_height", "zeek.rdp.desktop.width": "desktop_width", "zeek.rdp.encryption.level": "encryption_level", "zeek.rdp.encryption.method": "encryption_method"},
    "rfb": {"zeek.rfb.auth.method": "authentication_method", "zeek.rfb.auth.success": "auth", "zeek.rfb.version.client.major": "client_major_version", "zeek.rfb.version.client.minor": "client_minor_version", "zeek.rfb.version.server.major": "server_major_version", "zeek.rfb.version.server.minor": "server_minor_version"},
    "signature": {"destination.address": "dst_addr", "destination.ip": "dst_addr", "destination.port": "dst_port", "rule.description": "event_msg", "rule.id": "sig_id", "source.address": "src_addr", "source.ip": "src_addr", "source.port": "src_port"},
    "sip": {"event.action": "method", "url.full": "uri", "zeek.sip.request.body_length": "request_body_len", "zeek.sip.request.from": "request_from", "zeek.sip.request.path": "request_path", "zeek.sip.request.to": "request_to", "zeek.sip.response.body_length": "response_body_len", "zeek.sip.response.from": "response_from", "zeek.sip.response.path": "response_path", "zeek.sip.response.to": "response_to", "zeek.sip.sequence.method": "method", "zeek.sip.status.code": "status_code", "zeek.sip.status.msg": "status_msg", "zeek.sip.transaction_depth": "trans_depth"},
    "smb_cmd": {"event.action": "command", "user.name": "username", "zeek.smb_cmd.file.action": "referenced_file.action", "zeek.smb_cmd.file.host.rx": "referenced_file.id.resp_h", "zeek.smb_cmd.file.host.tx": "referenced_file.id.orig_h", "zeek.smb_cmd.file.name": "referenced_file.name", "zeek.smb_cmd.file.path": "referenced_file.path", "zeek.smb_cmd.file.uid": "referenced_file.uid"},
    "smb_files": {"event.action": "action", "file.name": "name", "file.size": "size"},
    "smtp": {"tls.established": "tls", "zeek.smtp.mail_from": "mailfrom", "zeek.smtp.rcpt_to": "rcptto", "zeek.smtp.transaction_depth": "trans_depth"},
    "snmp": {"zeek.snmp.get.bulk_requests": "get_bulk_requests", "zeek.snmp.get.requests": "get_requests", "zeek.snmp.get.responses": "get_responses", "zeek.snmp.set.requests": "set_requests"},
    "socks": {"user.name": "user", "zeek.socks.bound.port": "bound_p", "zeek.socks.request.host": "request.name", "zeek.socks.request.port": "request_p"},
    "ssh": {"zeek.ssh.algorithm.cipher": "cipher_alg", "zeek.ssh.algorithm.compression": "compression_alg", "zeek.ssh.algorithm.host_key": "host_key_alg", "zeek.ssh.algorithm.key_exchange": "kex_alg", "zeek.ssh.algorithm.mac": "mac_alg", "zeek.ssh.auth.attempts": "auth_attempts", "zeek.ssh.auth.success": "auth_success"},
    "ssl": {"tls.client.hash.sha1": "orig_certificate_sha1", "tls.client.ja3": "ja3", "tls.server.hash.sha1": "resp_certificate_sha1", "tls.server.ja3s": "ja3s", "tls.server.not_after": "not_valid_after", "tls.server.not_before": "not_valid_before", "zeek.ssl.client.cert_chain": "client_cert_chain", "zeek.ssl.client.cert_chain_fuids": "client_cert_chain_fuids", "zeek.ssl.server.cert_chain": "cert_chain", "zeek.ssl.server.cert_chain_fuids": "cert_chain_fuids", "zeek.ssl.server.name": "server_name", "zeek.ssl.validation.code": "validation_code", "zeek.ssl.validation.status": "validation_status"},
    "stats": {"zeek.stats.bytes.received": "bytes_recv", "zeek.stats.connections.icmp.active": "active_icmp_conns", "zeek.stats.connections.icmp.count": "icmp_conns", "zeek.stats.connections.tcp.active": "active_tcp_conns", "zeek.stats.connections.tcp.count": "tcp_conns", "zeek.stats.connections.udp.active": "active_udp_conns", "zeek.stats.connections.udp.count": "udp_conns", "zeek.stats.dns_requests.active": "active_dns_requests", "zeek.stats.dns_requests.count": "dns_requests", "zeek.stats.events.processed": "events_proc", "zeek.stats.events.queued": "events_queued", "zeek.stats.files.active": "active_files", "zeek.stats.files.count": "files", "zeek.stats.memory": "mem", "zeek.stats.packets.dropped": "pkts_dropped", "zeek.stats.packets.processed": "pkts_proc", "zeek.stats.packets.received": "pkts_link", "zeek.stats.reassembly_size.file": "reassem_file_size", "zeek.stats.reassembly_size.frag": "reassem_frag_size", "zeek.stats.reassembly_size.tcp": "reassem_tcp_size", "zeek.stats.reassembly_size.unknown": "reassem_unknown_size", "zeek.stats.timers.active": "active_timers", "zeek.stats.timers.count": "timers", "zeek.stats.timestamp_lag": "pkt_lag"},
    "syslog": {"log.syslog.facility.name": "facility", "log.syslog.severity.name": "severity", "zeek.syslog.msg": "message"},
    "traceroute": {"destination.address": "dst", "destination.ip": "dst", "source.address": "src", "source.ip": "src"},
    "tunnel": {"event.action": "action", "zeek.tunnel.type": "tunnel_type"},
    "weird": {"rule.name": "name", "zeek.weird.additional_info": "addl"},
    "x509": {"zeek.session_id": "id", "event.id": "id", "zeek.x509.basic_constraints.certificate_authority": "basic_constraints.ca", "zeek.x509.basic_constraints.path_length": "basic_constraints.path_len", "zeek.x509.certificate.common_name": "certificate.cn", "zeek.x509.certificate.iss": "certificate.issuer", "zeek.x509.certificate.key.algorithm": "certificate.key_alg", "zeek.x509.certificate.key.length": "certificate.key_length", "zeek.x509.certificate.key.type": "certificate.key_type", "zeek.x509.certificate.signature_algorithm": "certificate.sig_alg", "zeek.x509.certificate.sub": "certificate.subject", "zeek.x509.certificate.valid.from": "certificate.not_valid_before", "zeek.x509.certificate.valid.until": "certificate.not_valid_after", "zeek.x509.log_cert": "logcert"},
}

# Fields the Filebeat pipelines add under zeek.<fileset>. that Zeek never wrote.
ADDED = {"state_message", "icmp.type", "icmp.code"}
# Zeek fields that are lists; a CSV export joins them with ", " (Kibana) or "," .
LIST_FIELDS = {"answers", "TTLs", "tunnel_parents", "resp_fuids", "resp_mime_types", "resp_filenames",
               "orig_fuids", "orig_mime_types", "orig_filenames", "tags", "client_header_names",
               "server_header_names", "cert_chain", "cert_chain_fuids", "client_cert_chain",
               "client_cert_chain_fuids", "conn_uids", "tx_hosts", "rx_hosts", "analyzers",
               "msg_types", "uids", "rcptto", "seen.where", "sources", "matched"}
FIRST_KEYS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")
DATASET_RE = re.compile(r'"(?:event\.)?dataset"\s*:\s*"zeek\.|"(?:event\.)?module"\s*:\s*"zeek"')
KIBANA_TS = ("%b %d, %Y @ %H:%M:%S.%f", "%b %d, %Y @ %H:%M:%S", "%B %d, %Y @ %H:%M:%S.%f",
             "%B %d, %Y @ %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")
BYTES_RE = re.compile(r"^\s*([\d.,]+)\s*([KMGTP]?i?B)\s*$", re.I)
UNITS = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4, "P": 1024 ** 5}


def looks_like(head: str, first: str) -> bool:
    """True for a Filebeat/Elastic export of Zeek records (CSV header or NDJSON)."""
    s = first.lstrip()
    if s.startswith("{"):
        return bool(DATASET_RE.search(first)) and '"@timestamp"' in first
    cols = {c.strip().strip('"').strip() for c in re.split(r"[,;\t|]", first)}
    zeek_cols = any(c.startswith("zeek.") for c in cols)
    ecs = bool(cols & {"event.dataset", "data_stream.dataset", "fileset.name", "event.module"})
    return zeek_cols or (ecs and "zeek." in head)


# -- reading rows ----------------------------------------------------------------------------

def _flatten(obj: dict, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
        else:
            out[key] = v
    return out


def _cell(v):
    if v is None:
        return None
    if not isinstance(v, str):
        return v
    s = v.strip()
    if len(s) > 1 and s[0] == "'" and s[1] in "=+-@":   # Kibana's spreadsheet-formula guard
        s = s[1:]
    return None if s in ("", "-", "(empty)") else s


def _rows(path: str, stats: ParseStats):
    with open_text(path, newline="") as fh:
        head = fh.read(65536)
        fh.seek(0)
        first = next((l for l in head.splitlines() if l.strip()), "")
        if first.lstrip().startswith("{"):
            for line in fh:
                if not line.strip():
                    continue
                stats.read += 1
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    stats.drop("malformed JSON")
                    continue
                if not isinstance(doc, dict):
                    stats.drop("malformed JSON")
                    continue
                if isinstance(doc.get("_source"), dict):      # elasticdump / _search hits
                    doc = doc["_source"]
                yield {k: _cell(v) for k, v in _flatten(doc).items()}
            return
        # Only the delimiter is sniffed (Kibana's csv:separator can change it); quoting is
        # always Excel-style "" escaping, which the sniffer misreads on long JSON cells.
        counts = {d: first.count(d) for d in ",;\t|"}
        delim = max(counts, key=counts.get) if any(counts.values()) else ","
        csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))  # event.original can be long
        for row in csv.DictReader(fh, delimiter=delim):
            stats.read += 1
            row = {(k or "").strip(): _cell(v) for k, v in row.items() if k is not None}
            src = row.pop("_source", None)
            if isinstance(src, str) and src.startswith("{"):
                try:
                    row = {**{k: _cell(v) for k, v in _flatten(json.loads(src)).items()}, **row}
                except json.JSONDecodeError:
                    pass
            yield row


# -- value clean-up --------------------------------------------------------------------------

def _epoch(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value / 1000.0 if value > 1e12 else float(value)
    s = str(value).strip()
    dt = parse_ts(s)
    if dt is None:
        for fmt in KIBANA_TS:          # Kibana's default "MMM D, YYYY @ HH:mm:ss.SSS"
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    return None if dt is None else round(dt.timestamp(), 6)


def _num(value):
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    s = value.replace(",", "")
    m = BYTES_RE.match(value)
    if m:                                # Kibana "bytes" formatter, e.g. 1.2KB
        unit = m.group(2).upper().replace("IB", "").replace("B", "")
        try:
            return int(round(float(m.group(1).replace(",", "")) * UNITS.get(unit, 1)))
        except ValueError:
            return value
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return value


ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _value(key: str, value):
    """Turn an exported cell back into the type Zeek wrote (numbers, bools, lists, epoch times)."""
    if isinstance(value, list):
        return [_num(v) if isinstance(v, str) and re.fullmatch(r"-?\d+(\.\d+)?", v) else v for v in value]
    if isinstance(value, str):
        if ISO_RE.match(value):           # the pipelines turn Zeek epoch times into dates
            return _epoch(value)
        low = value.lower()
        if low in ("true", "false"):
            return low == "true"
        if key in LIST_FIELDS:
            if value.startswith("["):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    pass
            return _value(key, [v.strip() for v in re.split(r",\s*", value) if v.strip()])
        if re.fullmatch(r"[\d.,]+\s*[KMGTP]?i?B|-?[\d,]+(\.\d+)?", value, flags=re.I) and not \
                key.endswith(("_h", "addr", "_addr", "query", "uid", "id", "trans_id", "version")):
            return _num(value)
    return value


def _duration(value):
    """event.duration is nanoseconds; Kibana may print it as '76.967 ms' or '1.5 seconds'."""
    if value is None:
        return None
    n = _num(value)
    if isinstance(n, (int, float)):
        return round(n / 1e9, 6)
    m = re.match(r"^\s*([\d.,]+)\s*([a-zµ]+)", str(value), re.I)
    if not m:
        return None
    scale = {"ns": 1e-9, "nanoseconds": 1e-9, "µs": 1e-6, "us": 1e-6, "microseconds": 1e-6,
             "ms": 1e-3, "milliseconds": 1e-3, "s": 1, "sec": 1, "seconds": 1,
             "m": 60, "min": 60, "minutes": 60, "h": 3600, "hours": 3600}.get(m.group(2).lower())
    return None if scale is None else round(float(m.group(1).replace(",", "")) * scale, 6)


# -- one row back to a Zeek record -----------------------------------------------------------

def _fileset(row: dict) -> str | None:
    for key in ("event.dataset", "data_stream.dataset"):
        v = row.get(key)
        if isinstance(v, str) and v:
            return v[5:] if v.startswith("zeek.") else None   # another module's row (system.auth, ...)
    if row.get("event.module") == "zeek" and row.get("fileset.name"):
        return str(row["fileset.name"])
    path = row.get("log.file.path")
    if isinstance(path, str) and path:
        name = zeek.stream_from_name(path.replace("\\", "/"))
        return {v: k for k, v in STREAM_FOR_FILESET.items()}.get(name, name)
    for key, value in row.items():
        if value is not None and key.startswith("zeek.") and key.count(".") >= 2:
            return key.split(".")[1]
    return None


def _original(row: dict):
    for key in ("event.original", "message", "log.original"):
        v = row.get(key)
        if isinstance(v, dict):
            return v
        if isinstance(v, str) and v.lstrip().startswith("{"):
            try:
                rec = json.loads(v)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and ("ts" in rec or "uid" in rec or "id.orig_h" in rec):
                return rec
    return None


def to_zeek(row: dict) -> tuple[str, dict, bool] | None:
    """Return (stream, Zeek record, came_from_raw_line) for one exported row, or None."""
    fileset = _fileset(row)
    if not fileset:
        return None
    stream = STREAM_FOR_FILESET.get(fileset, fileset)
    raw = _original(row)
    if raw is not None:
        return stream, raw, True
    aliases = ALIASES.get(fileset, {})
    prefix = f"zeek.{fileset}."
    rec: dict = {}
    for key, value in row.items():                 # 1. ECS names every fileset shares
        if value is not None and key in COMMON and key not in aliases:
            rec[COMMON[key]] = value
    for key, value in row.items():                 # 2. fields that only moved under zeek.<fileset>.
        if value is not None and key.startswith(prefix) and key not in aliases:
            name = key[len(prefix):]
            if name not in ADDED:
                rec[name] = value
    for key, value in row.items():                 # 3. fileset-specific renames
        if value is not None and key in aliases:
            rec[aliases[key]] = value
    if "duration" not in rec and row.get("event.duration") is not None:
        rec["duration"] = _duration(row["event.duration"])
    if "ts" in rec:
        rec["ts"] = _epoch(rec["ts"])
    else:
        rec["ts"] = _epoch(row.get("@timestamp") or row.get("timestamp"))
    rec = {k: _value(k, v) for k, v in rec.items()}
    if isinstance(rec.get("duration"), str):
        rec["duration"] = _duration(rec["duration"])
    return stream, rec, False


def _ordered(rec: dict) -> dict:
    out = {k: rec[k] for k in FIRST_KEYS if k in rec}
    out.update((k, v) for k, v in rec.items() if k not in out)
    return out


def records(path: str, stats: ParseStats):
    """Yield (stream, Zeek record) for every Zeek row in a Filebeat export."""
    rebuilt = raw = 0
    lost_bytes = False
    for row in _rows(path, stats):
        got = to_zeek(row)
        if got is None:
            stats.drop("not a Zeek record (no zeek.* event.dataset)")
            continue
        stream, rec, from_raw = got
        if from_raw:
            raw += 1
        else:
            rebuilt += 1
            lost_bytes = lost_bytes or (stream == "conn" and "orig_bytes" not in rec)
        yield stream, _ordered(rec)
    if raw:
        stats.note(f"{raw} Filebeat row(s) carried the original Zeek line (event.original); used as is")
    if rebuilt:
        stats.note(f"{rebuilt} Filebeat row(s) rebuilt from ECS fields into Zeek field names")
    if lost_bytes:
        stats.note("Filebeat drops conn.log orig_bytes/resp_bytes; byte counts use orig_ip_bytes/resp_ip_bytes "
                   "(includes IP/TCP headers)")


def parse(path: str, stats: ParseStats):
    """Yield the same records the Zeek parser yields, from a Filebeat export."""
    generic_streams: set[str] = set()
    for stream, rec in records(path, stats):
        if stream == "conn":
            item = zeek._to_flow(rec, stats)
        elif stream == "notice":
            item = zeek._notice(rec, stats)
        else:
            item = zeek._event(rec, stream)
            generic_streams.add(stream)
        if item is not None:
            yield item
    if generic_streams:
        stats.note("Zeek stream records preserved as events; only conn sessions and notice alerts affect scoring")


def export(paths: list[str], outdir: str, log=None) -> dict[str, int]:
    """Write clean Zeek JSON logs (conn.log, dns.log, ...) to ``outdir``; return rows per log."""
    os.makedirs(outdir, exist_ok=True)
    handles: dict[str, object] = {}
    counts: dict[str, int] = {}
    try:
        for path in paths:
            stats = ParseStats(file=os.path.basename(path), fmt="filebeat_zeek")
            for stream, rec in records(path, stats):
                safe = re.sub(r"[^A-Za-z0-9_-]", "_", stream) or "unknown"
                fh = handles.get(safe)
                if fh is None:
                    fh = handles[safe] = open(os.path.join(outdir, f"{safe}.log"), "w", encoding="utf-8")
                fh.write(json.dumps(rec, separators=(",", ":"), default=str) + "\n")
                counts[safe] = counts.get(safe, 0) + 1
            for line in stats.notes if log else ():
                log(f"{stats.file}: {line}")
    finally:
        for fh in handles.values():
            fh.close()
    return counts
