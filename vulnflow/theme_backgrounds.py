"""Self-contained theme textures for local pages and standalone reports."""
from __future__ import annotations

import base64
import os
from functools import lru_cache


@lru_cache(maxsize=None)
def texture_data(name: str) -> str:
    if name not in {"signal", "matrix", "world"}:
        raise ValueError(f"Unknown theme texture: {name}")
    filename = "world_map.svg" if name == "world" else "signal_traces.svg"
    with open(os.path.join(os.path.dirname(__file__), "static", filename), encoding="utf-8") as fh:
        svg = fh.read()
    if name == "matrix":
        svg = svg.replace("#22d3ee", "#22c55e").replace("#67e8f9", "#86efac")
    payload = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{payload}"


def explorer_background_css() -> str:
    signal = texture_data("signal")
    matrix = texture_data("matrix")
    world = texture_data("world")
    return f"""
#vignette::before{{content:"";position:absolute;inset:0;pointer-events:none;background-position:center;background-size:cover;opacity:.08;filter:blur(2px)}}
[data-theme="dark"] #vignette::before,[data-theme="dark"] #attack-paths::before{{background-image:url('{signal}')}}
[data-theme="olive-drab"] #vignette::before,[data-theme="olive-drab"] #attack-paths::before{{background-image:url('{world}');opacity:.09}}
[data-theme="matrix"] #vignette::before,[data-theme="matrix"] #attack-paths::before{{background-image:url('{matrix}')}}
[data-theme="light"] #attack-paths::before{{background-image:radial-gradient(at 8% 0%,#2f4b7c1a,transparent 48%),radial-gradient(at 95% 65%,#2f4b7c10,transparent 50%);opacity:.9}}
[data-theme="light"] #vignette::before{{background-image:radial-gradient(at 8% 0%,#2f4b7c1a,transparent 48%),radial-gradient(at 95% 65%,#2f4b7c10,transparent 50%);opacity:.55}}
[data-theme="high-contrast"] #vignette{{background-image:none}}
[data-theme="high-contrast"] #vignette::before,[data-theme="high-contrast"] #attack-paths::before{{display:none}}
"""
