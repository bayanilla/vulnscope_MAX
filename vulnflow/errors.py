"""The one exception type whose message is meant for the person running VulnScope."""
from __future__ import annotations


class UserError(ValueError):
    """Something the person can fix: a bad or missing input, an unreadable saved report, a
    machine that is too busy. The message is written for them, so the command line prints it
    and the upload page shows it as is.

    Any other exception, including a plain ValueError from deep inside the analysis, is a bug:
    the upload page reports it as a failure and the details go to the server console. (It
    subclasses ValueError so callers that already catch ValueError keep working.)"""
