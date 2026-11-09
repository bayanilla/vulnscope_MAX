"""Product name and logo for generated pages, with analyst-set branding.

Analysts can replace the part of the name before "VulnScope" (for example "Ford VulnScope")
and add a small logo shown to the left of the name. The choice is saved once per user in
``~/.vulnscope/branding.json`` (or ``$VULNSCOPE_HOME/branding.json``) so the upload page,
the CLI, reports and the Explorer all use it. Pages generated before a change keep the
branding they were made with.

Logos are limited to small PNG, JPEG, GIF or WebP files, recognised by their content rather
than their name; SVG is refused because it can carry script. Logos are embedded in pages as
``data:`` URIs inside ``<img>`` elements, so they cannot run code.
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import struct
import tempfile
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

BASE_NAME = "VulnScope"
DEFAULT_PREFIX = "Múcaro"
EXPLORER_NAME = "VulnScope Explorer"
MAX_PREFIX = 40
MAX_LOGO_BYTES = 256 * 1024
MAX_LOGO_SIDE = 2048
LOGO_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp")


class BrandingError(ValueError):
    pass


@dataclass(frozen=True)
class Branding:
    prefix: str = DEFAULT_PREFIX
    logo: bytes | None = None
    logo_type: str | None = None

    @property
    def name(self) -> str:
        return f"{self.prefix} {BASE_NAME}" if self.prefix else BASE_NAME

    def logo_data_uri(self) -> str | None:
        if not self.logo or self.logo_type not in LOGO_TYPES:
            return None
        return f"data:{self.logo_type};base64," + base64.b64encode(self.logo).decode("ascii")


def config_path() -> Path:
    home = os.environ.get("VULNSCOPE_HOME") or os.path.join(os.path.expanduser("~"), ".vulnscope")
    return Path(home) / "branding.json"


def clean_prefix(raw: str) -> str:
    """Normalise the analyst's prefix; raise BrandingError when it cannot be used."""
    text = unicodedata.normalize("NFC", raw or "")
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs") for ch in text):
        raise BrandingError("The name can't contain control or invisible characters.")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_PREFIX:
        raise BrandingError(f"Keep the name to {MAX_PREFIX} characters or fewer.")
    if text.casefold().endswith(BASE_NAME.casefold()):
        text = text[: -len(BASE_NAME)].rstrip(" -·")
    return text


def _image_size(data: bytes, kind: str) -> tuple[int, int] | None:
    try:
        if kind == "image/png":
            if data[12:16] != b"IHDR":
                return None
            return struct.unpack(">II", data[16:24])
        if kind == "image/gif":
            return struct.unpack("<HH", data[6:10])
        if kind == "image/webp":
            chunk = data[12:16]
            if chunk == b"VP8 ":
                w, h = struct.unpack("<HH", data[26:30])
                return w & 0x3FFF, h & 0x3FFF
            if chunk == b"VP8L":
                b = data[21:25]
                return 1 + (((b[1] & 0x3F) << 8) | b[0]), 1 + (((b[3] & 0xF) << 10) | (b[2] << 2) | (b[1] >> 6))
            if chunk == b"VP8X":
                return 1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")
            return None
        if kind == "image/jpeg":
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    return None
                marker = data[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg = struct.unpack(">H", data[i + 2:i + 4])[0]
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    h, w = struct.unpack(">HH", data[i + 5:i + 9])
                    return w, h
                i += 2 + seg
            return None
    except (struct.error, IndexError):
        return None
    return None


def sniff_logo(data: bytes) -> str:
    """Return the logo's MIME type from its content, or raise BrandingError."""
    if not data:
        raise BrandingError("The logo file is empty.")
    if len(data) > MAX_LOGO_BYTES:
        raise BrandingError(f"Logos must be {MAX_LOGO_BYTES // 1024} KB or smaller.")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        kind = "image/jpeg"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        kind = "image/gif"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind = "image/webp"
    else:
        raise BrandingError("Use a PNG, JPEG, GIF or WebP image for the logo. SVG isn't accepted.")
    size = _image_size(data, kind)
    if not size or not (0 < size[0] <= MAX_LOGO_SIDE and 0 < size[1] <= MAX_LOGO_SIDE):
        raise BrandingError(f"The logo must be a valid image no larger than {MAX_LOGO_SIDE}×{MAX_LOGO_SIDE} pixels.")
    return kind


@lru_cache(maxsize=1)
def _load_cached(path: str, mtime: float) -> Branding:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        prefix = clean_prefix(str(raw.get("prefix", DEFAULT_PREFIX)))
        logo = base64.b64decode(raw["logo"]) if raw.get("logo") else None
        kind = sniff_logo(logo) if logo else None
        return Branding(prefix, logo, kind)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return Branding()


def load() -> Branding:
    """The saved branding, or the Múcaro default when none is saved or the file is unusable."""
    path = config_path()
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return Branding()
    return _load_cached(str(path), mtime)


def save(branding: Branding) -> None:
    path = config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {"prefix": branding.prefix,
               "logo": base64.b64encode(branding.logo).decode("ascii") if branding.logo else None}
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".branding-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update(prefix: str, logo: bytes | None = None, remove_logo: bool = False) -> Branding:
    """Validate and save a change; ``logo`` None keeps the current logo unless ``remove_logo``."""
    current = load()
    new_prefix = clean_prefix(prefix)
    if logo:
        kind = sniff_logo(logo)
        new = Branding(new_prefix, logo, kind)
    elif remove_logo:
        new = Branding(new_prefix)
    else:
        new = Branding(new_prefix, current.logo, current.logo_type)
    save(new)
    return new


def reset() -> Branding:
    save(Branding())
    return Branding()


def product_name() -> str:
    return load().name


@lru_cache(maxsize=1)
def _default_icon() -> str:
    icon = Path(__file__).with_name("static") / "mucaro-icon.svg"
    return "data:image/svg+xml;base64," + base64.b64encode(icon.read_bytes()).decode("ascii")


def icon_data_uri() -> str:
    """Tab icon: the analyst's logo when one is set, otherwise the Múcaro icon."""
    return load().logo_data_uri() or _default_icon()


def logo_img(css_class: str = "brand-logo") -> str:
    """An <img> for the saved logo, or "" when none is set."""
    uri = load().logo_data_uri()
    return f'<img class="{css_class}" src="{uri}" alt="" aria-hidden="true">' if uri else ""


def brand_html(css_class: str = "brand-logo") -> str:
    """Logo (if any) followed by the escaped product name, for a page's top-left brand."""
    return logo_img(css_class) + html.escape(product_name())
