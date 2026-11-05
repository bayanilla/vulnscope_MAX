"""Common schema every input format is normalized into."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


@dataclass(slots=True)          # slots: millions of these can be in memory at once
class Flow:
    """One network connection/session, regardless of which sensor saw it."""
    ts: datetime | None
    src_ip: str
    dst_ip: str
    dst_port: int | None
    proto: str                   # tcp | udp | icmp | other
    src_port: int | None = None
    action: str = "allow"        # allow | deny
    established: bool = True     # handshake completed / data flowed both ways
    bytes_out: int = 0           # originator -> responder
    bytes_in: int = 0            # responder -> originator
    app: str = ""
    src_zone: str = ""
    dst_zone: str = ""
    source: str = ""             # input file the record came from

    def key(self):
        return (self.ts, self.src_ip, self.src_port, self.dst_ip, self.dst_port,
                self.proto, self.action)


@dataclass(slots=True)
class ThreatEvent:
    """An IPS/IDS alert (Palo Alto THREAT log, Zeek notice, Suricata alert)."""
    ts: datetime | None
    src_ip: str
    dst_ip: str
    dst_port: int | None
    name: str                    # signature / threat name, often with a vendor ID or CVE
    severity: str = ""
    action: str = "alert"        # alert/allow (traffic passed) or block (traffic stopped)
    source: str = ""

    @property
    def blocked(self) -> bool:
        return self.action.lower().startswith(("block", "drop", "deny", "reset", "reject"))

    def key(self):
        return (self.ts, self.src_ip, self.dst_ip, self.dst_port, self.name)


@dataclass(slots=True)
class ZeekEvent:
    """A Zeek record from a stream other than conn or notice.

    Keep the stream and original fields so custom/package logs remain usable
    without treating their shared connection ID as a separate session.
    """
    ts: datetime | None
    stream: str
    uid: str
    src_ip: str | None
    dst_ip: str | None
    fields: dict
    source: str = ""


@dataclass(slots=True)
class OTEvent(ZeekEvent):
    """An industrial protocol message or transaction observed by Zeek."""
    protocol: str = ""
    operation: str = ""
    direction: str = "unknown"


@dataclass
class Finding:
    """One vulnerability on one host/port, as reported by the scanner."""
    host_ip: str
    plugin_id: str
    plugin_name: str
    severity: int                # Nessus scale: 0 info .. 4 critical
    port: int = 0                # 0 = host-level (local/credentialed) check
    proto: str = "tcp"
    service: str = ""
    hostname: str = ""
    os: str = ""
    cvss: float | None = None
    cvss_version: str = ""
    cves: list[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_frameworks: list[str] = field(default_factory=list)
    synopsis: str = ""
    solution: str = ""
    plugin_output: str = ""
    source: str = ""
    scan_start: datetime | None = None   # when the scanner checked this host (HOST_START)
    scan_end: datetime | None = None

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, str(self.severity))

    def key(self):
        return (self.host_ip, self.port, self.proto, self.plugin_id)


@dataclass
class ParseStats:
    """Data-quality bookkeeping for one input file."""
    file: str
    fmt: str
    read: int = 0
    kept: int = 0
    dropped: Counter = field(default_factory=Counter)
    notes: list[str] = field(default_factory=list)

    def drop(self, reason: str):
        self.dropped[reason] += 1

    def note(self, msg: str):
        if msg not in self.notes:
            self.notes.append(msg)
