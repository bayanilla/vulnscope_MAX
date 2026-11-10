"""One call that runs the whole workflow: load -> clean -> correlate -> report."""
from __future__ import annotations

import sys

from . import netmap, resources
from .correlate import Config, correlate
from .ioc_archive import is_archive, match_archive, read_archives
from .normalize import load
from .report import write_all


def run(paths: list[str], outdir: str, cfg: Config | None = None,
        overrides: dict[str, str] | None = None,
        article_previews: bool = True,
        article_preview_cache: str | None = None,
        workdir: str | None = None) -> tuple[dict, dict[str, str]]:
    """``workdir`` holds the run's Parquet batches and DuckDB file (default: system temp,
    or $VULNSCOPE_WORKDIR); it is deleted when the run finishes."""
    cfg = cfg or Config()
    map_files = [path for path in paths if netmap.is_map_file(path)] + ([cfg.network_map] if cfg.network_map else [])
    networks = [e for path in map_files for e in netmap.read(path)]       # read first: a bad map fails fast
    paths = [path for path in paths if not netmap.is_map_file(path)]
    archive_paths = [path for path in paths if is_archive(path)]
    with resources.job_slot():               # one heavy analysis at a time (VULNSCOPE_MAX_JOBS)
        budget = resources.plan(workdir=workdir)
        for warning in budget.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(budget.describe(), file=sys.stderr)
        ds = load([path for path in paths if path not in archive_paths], overrides,
                  workdir=workdir, skew_seconds=cfg.dedup_skew_seconds, budget=budget)
        try:
            return _run(ds, archive_paths, outdir, cfg, article_previews, article_preview_cache, networks)
        except Exception as exc:
            friendly = resources.explain(exc, budget)
            if friendly is not None:
                raise friendly from exc
            raise
        finally:
            ds.close()


def _run(ds, archive_paths, outdir, cfg, article_previews, article_preview_cache, networks=()):
    if not ds.flows and not ds.threats:
        raise ValueError("No network telemetry was provided (or none could be parsed). "
                         "Add Zeek conn.log, Palo Alto traffic/threat logs, IDS alerts or a flow CSV.")
    archive, archive_stats = read_archives(archive_paths)
    ds.stats.extend(archive_stats)
    res = correlate(ds, cfg)
    if networks:
        _apply_networks(res, ds, networks)
    if archive_paths:
        res["ioc_matches"] = match_archive(ds, archive, {h["host"] for h in res["hosts"]})
        if article_previews:
            from .article_preview import add_previews, read_preview_cache
            cached = read_preview_cache(article_preview_cache) if article_preview_cache else None
            add_previews(res["ioc_matches"], cached)
        res["ioc_archive"] = {"files": [s.file for s in archive_stats],
                              "indicators": len(archive), "matches": len(res["ioc_matches"])}
    return res, write_all(res, ds, outdir)


def _apply_networks(res, ds, networks):
    """Tag hosts and findings with their named network and add per-network totals."""
    nm = netmap.NetMap(networks)
    for h in res["hosts"]:
        h["network"] = nm.name(h["host"])
    for r in res["findings"]:
        r["network"] = nm.name(r["host"])
    res["network_map"] = networks
    res["networks"] = netmap.summarize(networks, res, sorted(ds.scanned_hosts))
