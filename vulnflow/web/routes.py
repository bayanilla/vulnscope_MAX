"""Every page and call the upload server answers. A view is ``view(req, *groups)``: ``req`` is the
request (see handler.py), ``groups`` the pattern's groups. GET paths are URL-decoded first; POST
paths are matched exactly as sent. Anything else is a 404."""
from __future__ import annotations

import re

from ..runname import RUN_ID
from . import branding_page, folders, runs, settings, upload


def _table(rows):
    return [(re.compile(pattern), view) for pattern, view in rows]


GET = _table([
    (r"/(?:index\.html)?", upload.page),
    (r"/settings", settings.view),
    (r"/branding", branding_page.view),
    (rf"/runs/({RUN_ID})/(.*)", runs.get),
])

POST = _table([
    (r"/analyze", upload.analyze_upload),
    (r"/analyze-folder", upload.analyze_folder),
    (r"/folder-kind", upload.folder_kind),
    (r"/browse", folders.browse),
    (r"/locate-folder", folders.locate),
    (r"/pick-folder", folders.pick),
    (rf"/runs/({RUN_ID})/radar", runs.radar),
    (rf"/runs/({RUN_ID})/(brief|article-briefs|ask)", runs.ai),
    (r"/settings", settings.save),
    (r"/branding", branding_page.save),
    (r"/branding/unlock", branding_page.unlock),
    (r"/branding/lock", branding_page.lock),
])
