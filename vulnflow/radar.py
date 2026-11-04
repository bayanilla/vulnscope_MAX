"""Small, on-demand Cloudflare Radar lookups for the local demo server."""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


class RadarError(Exception):
    """A Radar lookup failed without changing the local analysis result."""


_API = "https://api.cloudflare.com/client/v4/radar"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _domain(value: str) -> str:
    try:
        name = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid domain.") from exc
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid domain.")
    return name


def lookup(kind: str, value: str, token: str) -> dict:
    """Return selected Radar metadata; never return the token or raw provider payload."""
    if not token:
        raise RadarError("Cloudflare Radar is not configured on this server.")
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc
        if not address.is_global or address.version != 4:
            raise ValueError("Radar lookup requires a public IPv4 address.")
        value = str(address)
        url = _API + "/entities/ip?" + urllib.parse.urlencode({"ip": value})
    elif kind == "domain":
        value = _domain(value)
        url = _API + "/ranking/domain/" + urllib.parse.quote(value, safe="")
    else:
        raise ValueError("Radar lookup supports IP addresses and domains only.")

    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "User-Agent": "VulnScope-Radar-POC/1",
    })
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            raw = response.read(256_001)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise RadarError("Cloudflare rejected the Radar token or its permissions.") from exc
        if exc.code == 429:
            raise RadarError("Cloudflare Radar rate limit reached. Try again later.") from exc
        if exc.code == 404:
            raise RadarError("Cloudflare Radar has no result for this indicator.") from exc
        raise RadarError("Cloudflare Radar returned an error.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RadarError("Cloudflare Radar could not be reached.") from exc
    if len(raw) > 256_000:
        raise RadarError("Cloudflare Radar response was too large.")
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ValueError
        result = payload["result"]
        details = result["ip" if kind == "ip" else "details_0"]
        if not isinstance(details, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise RadarError("Cloudflare Radar returned an unexpected response.") from exc

    out = {"type": kind, "value": value,
           "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if kind == "ip":
        for field in ("asn", "asnName", "asnOrgName", "locationName", "asnLocation"):
            if details.get(field) is not None:
                out[field] = str(details[field])
    else:
        for field in ("rank", "bucket"):
            if details.get(field) is not None:
                out[field] = details[field]
        out["categories"] = [str(item["name"]) for item in (details.get("categories") or [])
                             if isinstance(item, dict) and item.get("name")][:10]
    return out
