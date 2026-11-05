"""Field-level cleaning helpers shared by all parsers."""
from __future__ import annotations

import gzip
import ipaddress
from datetime import datetime, timezone
from functools import lru_cache

PROTO_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmp"}
TS_FORMATS = ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
              "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f", "%m/%d/%Y %H:%M:%S",
              "%a %b %d %H:%M:%S %Y")


def clean_ip(value) -> str | None:
    """Return a canonical IP string, or None if value is not an IP."""
    if value is None:
        return None
    return _canon_ip(str(value))


@lru_cache(maxsize=262144)          # the same addresses repeat across millions of log lines
def _canon_ip(s: str) -> str | None:
    s = s.strip().strip('"').strip("[]")
    if not s or s in ("-", "(empty)"):
        return None
    if "%" in s:                      # IPv6 zone id
        s = s.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def to_int(value, default=None):
    if value is None:
        return default
    s = str(value).strip().replace(",", "")
    if s in ("", "-", "(empty)"):
        return default
    try:
        return int(float(s))
    except ValueError:
        return default


def clean_port(value):
    p = to_int(value)
    return p if p is not None and 0 <= p <= 65535 else None


def clean_proto(value) -> str:
    s = str(value or "").strip().lower()
    s = PROTO_NUMBERS.get(s, s)
    if s.startswith("icmp"):
        return "icmp"
    return s if s in ("tcp", "udp") else (s or "other")


def parse_ts(value) -> datetime | None:
    """Parse epoch seconds/ms or common text timestamps; result is UTC."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s == "-":
        return None
    try:
        f = float(s)
        if f > 1e12:                  # epoch milliseconds
            f /= 1000.0
        return datetime.fromtimestamp(f, tz=timezone.utc)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def norm_header(h: str) -> str:
    return (h or "").strip().strip('"').strip().lower().replace(" ", "_")


def open_text(path: str, newline: str | None = None):
    """Open a plain or gzip-compressed text file (``.gz`` suffix) for streaming reads."""
    if path.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline=newline)
    return open(path, encoding="utf-8-sig", errors="replace", newline=newline)
