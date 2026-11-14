"""One call that runs the whole workflow: load -> clean -> correlate -> report."""
from __future__ import annotations

import ipaddress
import os
import shutil
import sys
import tempfile

from . import netmap, pcap, resources, runname, scanners
from .correlate import Config, correlate
from .errors import UserError
from .ioc_archive import is_archive, match_archive, read_archives
from .normalize import load
from .report import write_all


def run(paths: list[str], outdir: str, cfg: Config | None = None,
        overrides: dict[str, str] | None = None,
        article_previews: bool = True,
        article_preview_cache: str | None = None,
        workdir: str | None = None,
        report: dict | None = None) -> tuple[dict, dict[str, str]]:
    """``workdir`` holds the run's Parquet batches and DuckDB file (default: system temp,
    or $VULNSCOPE_WORKDIR); it is deleted when the run finishes.

    Packet captures (.pcap/.pcapng, plain or .gz) are converted to Zeek logs with a local Zeek
    first. ``VULNSCOPE_OFFLINE=1`` turns off every outbound lookup (article previews).

    ``report`` is the optional {"name", "description", "network"} the analyst gave the run; it is
    stored in results.json and shown at the top of the reports and in the Explorer."""
    cfg = cfg or Config()
    check_internal_nets(cfg.internal_nets)           # a typo here would otherwise fail after loading
    if offline():
        article_previews = False
    map_files = [path for path in paths if netmap.is_map_file(path)] + ([cfg.network_map] if cfg.network_map else [])
    networks = [e for path in map_files for e in netmap.read(path)]       # read first: a bad map fails fast
    paths = [path for path in paths if not netmap.is_map_file(path)]
    scanner_files = [path for path in paths if scanners.is_list_file(path)] + ([cfg.known_scanners] if cfg.known_scanners else [])
    cfg.known_scanner_list = [e for path in scanner_files for e in scanners.read(path)]
    paths = [path for path in paths if not scanners.is_list_file(path)]
    archive_paths = [path for path in paths if is_archive(path)]
    overrides = overrides or {}
    captures = [path for path in paths if path not in archive_paths and _is_capture(path, overrides)]
    with resources.job_slot():               # one heavy analysis at a time (VULNSCOPE_MAX_JOBS)
        budget = resources.plan(workdir=workdir)
        for warning in budget.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(budget.describe(), file=sys.stderr)
        zeek_dir = None
        try:
            capture_logs, capture_stats = [], []
            if captures:
                base = workdir or os.environ.get("VULNSCOPE_WORKDIR") or None
                if base:
                    os.makedirs(base, exist_ok=True)
                zeek_dir = tempfile.mkdtemp(prefix="vulnscope-pcap-", dir=base)
                capture_logs, capture_stats = pcap.convert(captures, zeek_dir)
            inputs = [path for path in paths if path not in archive_paths and path not in captures]
            ds = load(inputs + capture_logs, overrides,
                      workdir=workdir, skew_seconds=cfg.dedup_skew_seconds, budget=budget)
            ds.stats[:0] = capture_stats
        finally:
            if zeek_dir:
                shutil.rmtree(zeek_dir, ignore_errors=True)
        try:
            return _run(ds, archive_paths, outdir, cfg, article_previews, article_preview_cache, networks,
                        runname.clean(*((report or {}).get(k) for k in ("name", "description", "network"))))
        except Exception as exc:
            friendly = resources.explain(exc, budget)
            if friendly is not None:
                raise friendly from exc
            raise
        finally:
            ds.close()


def input_files(paths: list[str], outdir: str) -> list[str]:
    """Expand input folders recursively, ignoring hidden files and the output folder."""
    files = []
    output = os.path.abspath(outdir)
    for path in paths:
        if not os.path.isdir(path):
            files.append(path)
            continue
        for root, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and
                             os.path.abspath(os.path.join(root, d)) != output)
            files.extend(os.path.join(root, name) for name in sorted(names)
                         if not name.startswith(".") and os.path.isfile(os.path.join(root, name)))
    return files


def check_internal_nets(nets: list[str]) -> None:
    """Refuse an internal network that is not an address range, before any data is read."""
    for net in nets:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            raise UserError(f"Internal networks: '{net}' is not an address range. Write them like "
                            "10.0.0.0/8, 192.168.1.0/24, separated by commas.") from None


def offline() -> bool:
    """True when VULNSCOPE_OFFLINE asks for no outbound network use (air-gapped enclaves)."""
    return os.environ.get("VULNSCOPE_OFFLINE", "").strip().lower() in ("1", "true", "yes", "on")


def _is_capture(path: str, overrides: dict[str, str]) -> bool:
    forced = overrides.get(path) or overrides.get(os.path.basename(path))
    return forced == "pcap" or (forced is None and pcap.is_pcap(path))


def _run(ds, archive_paths, outdir, cfg, article_previews, article_preview_cache, networks=(), report=None):
    if not ds.flows and not ds.threats:
        raise UserError("No network telemetry was provided (or none could be parsed). "
                         "Add Zeek conn.log, Palo Alto traffic/threat logs, IDS alerts or a flow CSV.")
    archive, archive_stats = read_archives(archive_paths)
    ds.stats.extend(archive_stats)
    res = correlate(ds, cfg)
    res["report"] = report or runname.clean("", "")
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
