"""What one upload-page server remembers between requests.

Everything that used to live in variables captured by one large closure is here, in the open:
the configuration it was started with, the AI provider chosen on the settings page, the CSRF
token, the Branding page's unlock state and what was last typed on the upload page.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, replace

from ..correlate import Config
from ..llm import LLMConfig
from .branding_page import BrandingGate


@dataclass
class App:
    data_dir: str                           # one folder per run: <data_dir>/<run id>/{in,out}
    base_cfg: Config
    llm: LLMConfig | None                   # None hides the Security Assistant entirely
    max_upload: int
    access_token: str | None = None         # remote access: every request must carry it (cookie)
    allowed_hosts: frozenset[str] = frozenset()   # Host headers accepted besides loopback
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(24))   # guards form posts from other sites
    branding: BrandingGate = field(default_factory=BrandingGate)
    last_path: str = ""                     # kept on the upload page after an error
    last_report: dict = field(default_factory=dict)

    def __post_init__(self):
        # an unready provider falls back to the built-in offline assistant, so the assistant
        # always works without one
        if self.llm is not None and not self.llm.ready:
            self.llm = LLMConfig.offline()

    def llm_config(self) -> LLMConfig | None:
        """A copy, so a request never sees the settings page change it halfway through."""
        return replace(self.llm) if self.llm is not None else None

    def csrf_ok(self, token) -> bool:
        return isinstance(token, str) and secrets.compare_digest(token, self.csrf)

    def run_root(self, run_id: str) -> str:
        """<data_dir>/<run id>: the run's input copy, working files and the out/ folder."""
        return os.path.join(self.data_dir, run_id)

    def run_out(self, run_id: str) -> str:
        return os.path.realpath(os.path.join(self.data_dir, run_id, "out"))
