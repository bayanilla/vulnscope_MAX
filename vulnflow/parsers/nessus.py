"""Nessus parsers: .nessus (NessusClientData_v2 XML) and the CSV export."""
from __future__ import annotations

import csv
import re
import xml.etree.ElementTree as ET

from ..errors import UserError
from ..schema import Finding, ParseStats
from ._util import clean_ip, norm_header, open_gzip_binary, open_text, parse_ts, to_int

RISK_TO_SEV = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FRAMEWORKS = {"exploit_framework_metasploit": "Metasploit",
              "exploit_framework_canvas": "CANVAS",
              "exploit_framework_core": "Core Impact"}


SCAN_INFO_PLUGIN = "19506"
_SCANNER_IP = re.compile(r"Scanner IP\s*:\s*([0-9A-Fa-f:.]+)")


def scanner_ip(plugin_output: str) -> str:
    """The scanner's own address from the "Nessus Scan Information" plugin output, if present."""
    m = _SCANNER_IP.search(plugin_output or "")
    return (clean_ip(m.group(1).rstrip(".")) or "") if m else ""


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _refuse_dtd(path: str) -> None:
    """Refuse a DOCTYPE in the prolog: real .nessus files have none, and DTD entities are how
    XML entity-expansion bombs and external-entity tricks work."""
    with (open_gzip_binary(path) if path.lower().endswith(".gz") else open(path, "rb")) as fh:
        head = fh.read(1 << 20)
    root = head.find(b"<NessusClientData")
    doctype = head.upper().find(b"<!DOCTYPE")
    if doctype >= 0 and (root < 0 or doctype < root):
        raise UserError("XML DOCTYPE declarations are not allowed in scan files")


def parse_xml(path: str, stats: ParseStats):
    findings: list[Finding] = []
    _refuse_dtd(path)
    source = open_gzip_binary(path) if path.lower().endswith(".gz") else path
    for _, host in ET.iterparse(source, events=("end",)):
        if host.tag != "ReportHost":
            continue
        props = {t.get("name"): (t.text or "").strip()
                 for t in host.findall("./HostProperties/tag")}
        name = host.get("name", "")
        ip = clean_ip(props.get("host-ip")) or clean_ip(name)
        hostname = props.get("host-fqdn") or props.get("netbios-name") or (name if not clean_ip(name) else "")
        if not ip:
            for _ in host.findall("ReportItem"):
                stats.read += 1
                stats.drop("host has no IP address (name only)")
            stats.note(f"host '{name}' had no IP; add host-ip or scan by IP to correlate it")
            host.clear()
            continue
        scan_start = parse_ts(props.get("HOST_START_TIMESTAMP")) or parse_ts(props.get("HOST_START"))
        scan_end = parse_ts(props.get("HOST_END_TIMESTAMP")) or parse_ts(props.get("HOST_END"))
        scanner = next((scanner_ip(i.findtext("plugin_output") or "") for i in host.findall("ReportItem")
                        if i.get("pluginID") == SCAN_INFO_PLUGIN), "")
        for item in host.findall("ReportItem"):
            stats.read += 1
            child = lambda t: (item.findtext(t) or "").strip()
            cvss3, cvss2 = _float(child("cvss3_base_score")), _float(child("cvss_base_score"))
            findings.append(Finding(
                host_ip=ip, hostname=hostname, os=props.get("operating-system", ""),
                plugin_id=item.get("pluginID", ""), plugin_name=item.get("pluginName", ""),
                severity=to_int(item.get("severity"), 0),
                port=to_int(item.get("port"), 0), proto=(item.get("protocol") or "tcp").lower(),
                service=item.get("svc_name", ""),
                cvss=cvss3 if cvss3 is not None else cvss2,
                cvss_version="3" if cvss3 is not None else ("2" if cvss2 is not None else ""),
                cves=sorted({c.text.strip() for c in item.findall("cve") if c.text}),
                exploit_available=child("exploit_available").lower() == "true",
                exploit_frameworks=[n for t, n in FRAMEWORKS.items() if child(t).lower() == "true"],
                synopsis=child("synopsis"), solution=child("solution"),
                plugin_output=child("plugin_output")[:2000],
                scan_start=scan_start, scan_end=scan_end, scanner_ip=scanner,
            ))
        host.clear()
    return findings


def parse_csv(path: str, stats: ParseStats):
    """The CSV export has one row per CVE, so rows are merged per host/port/plugin."""
    merged: dict[tuple, Finding] = {}
    with open_text(path, newline="") as fh:
        for row in csv.DictReader(fh):
            row = {norm_header(k): (v or "").strip() for k, v in row.items() if k}
            stats.read += 1
            ip = clean_ip(row.get("host")) or clean_ip(row.get("ip_address"))
            if not ip:
                stats.drop("host is not an IP address")
                continue
            sev = RISK_TO_SEV.get(row.get("risk", "").lower(), to_int(row.get("severity"), 0))
            key = (ip, to_int(row.get("port"), 0), row.get("protocol", "tcp").lower(), row.get("plugin_id", ""))
            f = merged.get(key)
            if f is None:
                cvss3 = _float(row.get("cvss_v3.0_base_score"))
                cvss2 = _float(row.get("cvss_v2.0_base_score") or row.get("cvss"))
                f = merged[key] = Finding(
                    host_ip=ip, plugin_id=key[3], plugin_name=row.get("name", ""), severity=sev,
                    port=key[1], proto=key[2] or "tcp",
                    cvss=cvss3 if cvss3 is not None else cvss2,
                    cvss_version="3" if cvss3 is not None else ("2" if cvss2 is not None else ""),
                    exploit_available=row.get("exploit_available", "").lower() in ("true", "yes"),
                    exploit_frameworks=["Metasploit"] if row.get("metasploit", "").lower() in ("true", "yes") else [],
                    synopsis=row.get("synopsis", ""), solution=row.get("solution", ""),
                    plugin_output=row.get("plugin_output", "")[:2000],
                )
            cve = row.get("cve")
            if cve and cve not in f.cves:
                f.cves.append(cve)
            if key[3] == SCAN_INFO_PLUGIN:
                f.scanner_ip = f.scanner_ip or scanner_ip(row.get("plugin_output", ""))
    stats.note("Nessus CSV exports usually omit exploit availability; prefer the .nessus file")
    return list(merged.values())
