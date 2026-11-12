"""Field-level cleaning helpers shared by all parsers."""
from __future__ import annotations

import gzip
import io
import ipaddress
import os
from datetime import datetime, timezone
from functools import lru_cache

from ..errors import UserError

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


# A .gz file may not expand beyond this many times its own size (real logs compress about
# 5-20x), nor beyond VULNSCOPE_MAX_GZ_BYTES when that is set. Stops decompression bombs
# from filling the disk with Parquet and spool files.
MAX_GZ_RATIO = 200
MIN_GZ_ALLOWANCE = 256 * 1024 * 1024


class DecompressionLimit(UserError):
    pass


class _CappedGzip(io.RawIOBase):
    """Binary reader over a gzip file that refuses to produce more than ``limit`` bytes."""

    def __init__(self, path: str, limit: int):
        self._gz = gzip.open(path, "rb")
        self._left = limit
        self._limit = limit

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        pos = self._gz.seek(offset, whence)       # parsers rewind after sniffing the header
        self._left = max(0, self._limit - pos)
        return pos

    def tell(self):
        return self._gz.tell()

    def readinto(self, b):
        data = self._gz.read(min(len(b), self._left + 1))
        if len(data) > self._left:
            raise DecompressionLimit(f"decompresses to more than {self._limit // (1024 * 1024)} MB; "
                                     "set VULNSCOPE_MAX_GZ_BYTES to allow it")
        self._left -= len(data)
        b[:len(data)] = data
        return len(data)

    def close(self):
        self._gz.close()
        super().close()


def gz_limit(path: str) -> int:
    env = os.environ.get("VULNSCOPE_MAX_GZ_BYTES")
    if env and env.isdigit():
        return int(env)
    return max(MIN_GZ_ALLOWANCE, os.path.getsize(path) * MAX_GZ_RATIO)


def open_gzip_binary(path: str):
    return io.BufferedReader(_CappedGzip(path, gz_limit(path)), buffer_size=1 << 16)


def open_text(path: str, newline: str | None = None):
    """Open a plain or gzip-compressed text file (``.gz`` suffix) for streaming reads."""
    if path.lower().endswith(".gz"):
        return io.TextIOWrapper(open_gzip_binary(path), encoding="utf-8-sig", errors="replace", newline=newline)
    return open(path, encoding="utf-8-sig", errors="replace", newline=newline)
