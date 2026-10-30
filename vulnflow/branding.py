"""Shared product name and self-contained Múcaro tab icon for generated pages."""
from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

PRODUCT_NAME = "Múcaro VulnScope"
EXPLORER_NAME = "VulnScope Explorer"


@lru_cache(maxsize=1)
def icon_data_uri() -> str:
    icon = Path(__file__).with_name("static") / "mucaro-icon.svg"
    return "data:image/svg+xml;base64," + base64.b64encode(icon.read_bytes()).decode("ascii")
