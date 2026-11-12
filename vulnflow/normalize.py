"""Load every input file, normalize it into the common schema and clean it."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import resources
from .errors import UserError
from .parsers import FORMATS, detect
from .schema import Finding, Flow, OTEvent, ParseStats, ThreatEvent, ZeekEvent
from .store import (DEFAULT_BATCH, DEFAULT_SKEW_SECONDS, SENSOR_RANK, EventSpool, FlowView,
                    FlowWriter, Store)


@dataclass
class Dataset:
    """Normalized inputs.

    ``load`` fills ``flows`` with a disk-backed FlowView and the Zeek/OT event lists with
    JSONL spools, so memory stays flat as inputs grow. Plain lists still work (tests and
    small callers build Datasets by hand); ``flow_store`` loads them into DuckDB on demand.
    """
    flows: list[Flow] | FlowView = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    threats: list[ThreatEvent] = field(default_factory=list)      # IPS/IDS alerts
    zeek_events: list[ZeekEvent] | EventSpool = field(default_factory=list)
    ot_events: list[OTEvent] | EventSpool = field(default_factory=list)
    scanned_hosts: dict[str, dict] = field(default_factory=dict)   # ip -> {hostname, os}
    scanner_ips: set[str] = field(default_factory=set)   # the vulnerability scanner(s), from plugin 19506
    stats: list[ParseStats] = field(default_factory=list)
    duplicate_flows: int = 0
    duplicate_findings: int = 0
    cross_sensor_duplicates: int = 0
    store: Store | None = field(default=None, repr=False, compare=False)

    def flow_store(self) -> Store:
        """The DuckDB store holding ``flows``; built from a plain list the first time."""
        if isinstance(self.flows, FlowView):
            return self.flows.store
        key = (id(self.flows), len(self.flows))
        if self.store is None or getattr(self, "_list_key", None) != key:
            if self.store is not None:
                self.store.close()
            self.store = Store()
            self.store.load_flow_list(self.flows)
            object.__setattr__(self, "_list_key", key)
        return self.store

    def close(self):
        """Delete the working directory (Parquet, DuckDB file, event spools)."""
        if self.store is not None:
            self.store.close()


def _scan_times(f: Finding) -> list[tuple]:
    return list(f.scan_times) or ([(f.scan_start, f.scan_end)] if f.scan_start else [])


def _sensor(fmt: str) -> str:
    return "zeek" if fmt in ("zeek", "filebeat_zeek") else fmt if fmt in SENSOR_RANK else "generic"


def load(paths: list[str], overrides: dict[str, str] | None = None, *,
         workdir: str | None = None, skew_seconds: float | None = DEFAULT_SKEW_SECONDS,
         batch_size: int = DEFAULT_BATCH, budget: resources.Budget | None = None) -> Dataset:
    """overrides maps a file path or basename to a format name.

    Records stream from each parser in batches: flows go to Parquet (partitioned by sensor
    and day) under ``workdir`` and are de-duplicated with DuckDB; other Zeek streams are
    spooled to JSONL. ``skew_seconds`` is the clock-skew tolerance used to recognise the same
    session seen by two sensors (None disables cross-sensor matching).
    """
    overrides = overrides or {}
    store = Store(workdir, budget=budget)
    try:
        return _load(store, paths, overrides, skew_seconds, batch_size)
    except Exception as exc:
        store.close()
        friendly = resources.explain(exc, store.budget)
        if friendly is not None:
            raise friendly from exc
        raise


def _load(store, paths, overrides, skew_seconds, batch_size) -> Dataset:
    ds = Dataset(store=store)
    writer = FlowWriter(store, batch_size)
    zeek_spool = EventSpool(store, "zeek_events", ot=False)
    ot_spool = EventSpool(store, "ot_events", ot=True)
    raw_findings: list[Finding] = []
    threats: dict[tuple, ThreatEvent] = {}
    for fid, path in enumerate(paths):
        name = os.path.basename(path)
        fmt = overrides.get(path) or overrides.get(name) or detect(path)
        if fmt not in FORMATS:
            raise UserError(f"{name}: unknown format '{fmt}' (choose from {', '.join(FORMATS)})")
        kind, parser = FORMATS[fmt]
        sensor = _sensor(fmt)
        stats = ParseStats(file=name, fmt=fmt)
        kept = n_threats = 0
        try:
            for r in parser(path, stats):
                r.source = name
                kept += 1
                if kind == "findings":
                    raw_findings.append(r)
                elif isinstance(r, Flow):
                    writer.add(r, sensor, fid)
                elif isinstance(r, ThreatEvent):
                    n_threats += 1
                    threats[r.key()] = r      # first position, last record wins (as before)
                elif isinstance(r, ZeekEvent):
                    zeek_spool.add(r)        # OT events are Zeek events too (as before)
                    if isinstance(r, OTEvent):
                        ot_spool.add(r)
        except Exception as exc:  # a broken file should not sink the whole run
            if resources.explain(exc, store.budget) is not None:
                raise                    # out of memory or disk: stop, don't report a "broken file"
            # Records parsed before the error (e.g. a truncated .gz) are kept.
            stats.note(f"file could not be parsed: {exc}"
                       + (f" (kept {kept} record(s) read before the error)" if kept else ""))
        stats.kept = kept
        if n_threats:
            stats.note(f"{n_threats} IPS/IDS alert(s) used as exploitation evidence")
        ds.stats.append(stats)
    writer.flush()
    zeek_spool.close()
    ot_spool.close()
    ds.zeek_events, ds.ot_events = zeek_spool, ot_spool

    # Exact duplicates are removed; a session seen by two sensors (e.g. Zeek and the
    # firewall) is counted once. Both steps run in DuckDB over the Parquet batches.
    ds.duplicate_flows, ds.cross_sensor_duplicates = store.finalize_flows(skew_seconds)
    ds.flows = FlowView(store)
    ds.threats = sorted(threats.values(), key=lambda t: (t.ts is None, t.ts))

    # Overlapping scans: keep one finding per host/port/plugin, preferring the richer record.
    best: dict[tuple, Finding] = {}
    for f in raw_findings:
        ds.scanned_hosts.setdefault(f.host_ip, {"hostname": "", "os": ""})
        h = ds.scanned_hosts[f.host_ip]
        h["hostname"] = h["hostname"] or f.hostname
        h["os"] = h["os"] or f.os
        if f.scanner_ip:
            ds.scanner_ips.add(f.scanner_ip)
        cur = best.get(f.key())
        if cur is None:
            best[f.key()] = f
        else:
            ds.duplicate_findings += 1
            # Keep every scan's time: each scan gets its own window (not one span over the gap between them).
            times = sorted(set(_scan_times(cur) + _scan_times(f)), key=lambda t: t[0])
            if (f.exploit_available, f.cvss or 0) > (cur.exploit_available, cur.cvss or 0):
                best[f.key()] = cur = f
            cur.scan_times = times
            if times:
                cur.scan_start, cur.scan_end = times[-1]          # the latest scan, for display
    for f in best.values():
        f.hostname = f.hostname or ds.scanned_hosts[f.host_ip]["hostname"]
        f.os = f.os or ds.scanned_hosts[f.host_ip]["os"]
    ds.findings = sorted(best.values(), key=lambda f: (-f.severity, f.host_ip, f.port))
    return ds
