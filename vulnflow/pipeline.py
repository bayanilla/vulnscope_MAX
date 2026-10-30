"""One call that runs the whole workflow: load -> clean -> correlate -> report."""
from __future__ import annotations

from .correlate import Config, correlate
from .ioc_archive import is_archive, match_archive, read_archives
from .normalize import load
from .report import write_all


def run(paths: list[str], outdir: str, cfg: Config | None = None,
        overrides: dict[str, str] | None = None,
        article_previews: bool = True,
        article_preview_cache: str | None = None) -> tuple[dict, dict[str, str]]:
    archive_paths = [path for path in paths if is_archive(path)]
    ds = load([path for path in paths if path not in archive_paths], overrides)
    if not ds.findings and not any(s.fmt.startswith("nessus") for s in ds.stats):
        raise ValueError("No vulnerability scan was provided. Add a .nessus file or Nessus CSV export.")
    if not ds.flows:
        raise ValueError("No network telemetry was provided (or none could be parsed). "
                         "Add Zeek conn.log, Palo Alto traffic logs or a flow CSV.")
    archive, archive_stats = read_archives(archive_paths)
    ds.stats.extend(archive_stats)
    res = correlate(ds, cfg)
    if archive_paths:
        res["ioc_matches"] = match_archive(ds, archive)
        if article_previews:
            from .article_preview import add_previews, read_preview_cache
            cached = read_preview_cache(article_preview_cache) if article_preview_cache else None
            add_previews(res["ioc_matches"], cached)
        res["ioc_archive"] = {"files": [s.file for s in archive_stats],
                              "indicators": len(archive), "matches": len(res["ioc_matches"])}
    return res, write_all(res, ds, outdir)
