"""Size DuckDB to the machine and keep one large analysis from taking the machine down.

Everything here is read once per analysis and turned into a ``Budget``:

- memory: the machine's RAM, or the container's cgroup limit when that is lower (cgroup v1 and
  v2, nested groups included). DuckDB gets 60% of it by default, lowered if the machine is
  already busy, and never more than a hard ceiling that keeps at least 25% (and at least
  1.5 GiB) for the OS, Python and the report stage.
- threads: the CPUs this process may use (affinity and cgroup CPU quota), and no more than one
  per GiB of DuckDB memory, because each thread needs its own working memory for sorts.
- spill: DuckDB writes to the run's working directory beyond its memory limit; that spill is
  capped at 80% of the disk's free space so it cannot fill the disk.
- concurrency: analyses take a slot; the default is one at a time, and the memory budget is
  split between slots, so two uploads can never each claim 60% of RAM.

Overrides (all clamped to the safe ceiling, with a warning when clamped):
  VULNSCOPE_DUCKDB_MEMORY    e.g. 8GB, 6GiB, 512MB or 50%  (of usable RAM)
  VULNSCOPE_DUCKDB_THREADS   e.g. 4
  VULNSCOPE_DUCKDB_MAX_TEMP  e.g. 200GB or 50%             (of free disk)
  VULNSCOPE_MAX_JOBS         analyses allowed at once (default 1)
"""
from __future__ import annotations

import errno
import math
import os
import re
import shutil
import subprocess
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass

GiB = 1024 ** 3
MiB = 1024 ** 2

AUTO_FRACTION = 0.60          # default DuckDB share of usable RAM
AVAILABLE_FRACTION = 0.80     # ...but no more than this share of what is free right now
RESERVE_FRACTION = 0.25       # always left for the OS, Python and the report stage
RESERVE_MIN = int(1.5 * GiB)
MIN_MEMORY = 256 * MiB        # below this DuckDB cannot do useful work
BYTES_PER_THREAD = 1 * GiB    # DuckDB guidance: 1-4 GB per thread for sorts and windows
TEMP_FRACTION = 0.80          # share of free disk DuckDB may spill into
TEMP_MIN = 1 * GiB

_UNITS = {"": 1, "b": 1, "k": 1000, "kb": 1000, "m": 1000 ** 2, "mb": 1000 ** 2, "g": 1000 ** 3,
          "gb": 1000 ** 3, "t": 1000 ** 4, "tb": 1000 ** 4, "kib": 1024, "mib": MiB, "gib": GiB,
          "tib": 1024 ** 4}


class ResourceError(ValueError):
    """A run was refused or stopped to protect the machine. Subclasses ValueError so the CLI and
    the upload page show the message to the user instead of a traceback."""


class BusyError(ResourceError):
    pass


def parse_size(text: str, whole: int | None = None) -> int:
    """'8GB', '6 GiB', '512mb', '1.5g' -> bytes; '50%' -> that share of ``whole``."""
    s = str(text).strip().lower().replace(" ", "")
    if s.endswith("%"):
        if whole is None:
            raise ValueError(f"'{text}': a percentage is not allowed here")
        pct = float(s[:-1])
        if not 0 < pct <= 100:
            raise ValueError(f"'{text}': percentage must be between 0 and 100")
        return int(whole * pct / 100)
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([a-z]*)", s)
    if not m or m[2] not in _UNITS:
        raise ValueError(f"'{text}' is not a size; use a value like 8GB, 6GiB or 512MB")
    return int(float(m[1]) * _UNITS[m[2]])


def fmt_size(n: int) -> str:
    return f"{n / GiB:.1f} GiB" if n >= GiB else f"{n / MiB:.0f} MiB"


# -- detection ---------------------------------------------------------------------------------
def _read(path: str) -> str | None:
    try:
        with open(path, encoding="ascii") as fh:
            return fh.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _int(text: str | None) -> int | None:
    try:
        return int(text) if text is not None else None
    except ValueError:
        return None


def physical_memory() -> int | None:
    try:
        n = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        if n > 0:
            return n
    except (AttributeError, ValueError, OSError):
        pass
    if sys.platform == "darwin":
        return _int(_sysctl("hw.memsize"))
    return None


def _sysctl(name: str) -> str | None:
    try:
        out = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _cgroup_dirs(controller: str, root: str = "/sys/fs/cgroup",
                 proc_cgroup: str = "/proc/self/cgroup") -> list[str]:
    """Candidate cgroup directories for this process, innermost first, each followed by its
    ancestors. Covers v2 (unified), v1, and containers where the group is mounted at the root."""
    text = _read(proc_cgroup) or ""
    rel_v2 = rel_v1 = None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        if parts[0] == "0" and parts[1] == "":
            rel_v2 = parts[2]
        elif controller in parts[1].split(","):
            rel_v1 = parts[2]
    bases = []
    v1_root = os.path.join(root, controller)
    if rel_v1 is not None and os.path.isdir(v1_root):
        bases.append((v1_root, rel_v1))
    if rel_v2 is not None:
        for r in (root, os.path.join(root, "unified")):
            if os.path.exists(os.path.join(r, "cgroup.controllers")):
                bases.append((r, rel_v2))
    dirs: list[str] = []
    for base, rel in bases:
        rel = rel.strip("/")
        while True:
            d = os.path.join(base, rel) if rel else base
            if os.path.isdir(d) and d not in dirs:
                dirs.append(d)
            if not rel:
                break
            rel = os.path.dirname(rel)
    return dirs


def cgroup_memory(root: str = "/sys/fs/cgroup", proc_cgroup: str = "/proc/self/cgroup",
                  ) -> tuple[int | None, int | None]:
    """(limit, usage) of the tightest memory cgroup around this process, or (None, None).
    Usage excludes reclaimable page cache (inactive_file), like the kernel does before OOM."""
    best: tuple[int, int | None] | None = None
    for d in _cgroup_dirs("memory", root, proc_cgroup):
        limit = _int(_read(os.path.join(d, "memory.max")))            # v2 ('max' -> None)
        usage_file, stat_key = "memory.current", "inactive_file"
        if limit is None:
            limit = _int(_read(os.path.join(d, "memory.limit_in_bytes")))   # v1
            usage_file, stat_key = "memory.usage_in_bytes", "total_inactive_file"
        if limit is None or limit <= 0 or limit >= 1 << 60:
            continue
        usage = _int(_read(os.path.join(d, usage_file)))
        if usage is not None:
            for line in (_read(os.path.join(d, "memory.stat")) or "").splitlines():
                k, _, v = line.partition(" ")
                if k == stat_key and v.isdigit():
                    usage = max(0, usage - int(v))
        if best is None or limit < best[0]:
            best = (limit, usage)
    return best if best else (None, None)


def system_available_memory() -> int | None:
    """Memory the OS could hand out now without swapping."""
    meminfo = _read("/proc/meminfo")
    if meminfo:
        for line in meminfo.splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        page = re.search(r"page size of (\d+) bytes", out)
        pages = dict(re.findall(r"^Pages (free|inactive|speculative|purgeable):\s+(\d+)\.", out, re.M))
        if page and pages:
            return int(page[1]) * sum(int(v) for v in pages.values())
    return None


def cpu_count(root: str = "/sys/fs/cgroup", proc_cgroup: str = "/proc/self/cgroup") -> int:
    try:
        n = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        n = os.cpu_count() or 1
    for d in _cgroup_dirs("cpu", root, proc_cgroup):
        quota = period = None
        v2 = _read(os.path.join(d, "cpu.max"))
        if v2:
            q, _, p = v2.partition(" ")
            quota, period = _int(q), _int(p)
        else:
            quota = _int(_read(os.path.join(d, "cpu.cfs_quota_us")))
            period = _int(_read(os.path.join(d, "cpu.cfs_period_us")))
        if quota and period and quota > 0:
            n = min(n, max(1, math.ceil(quota / period)))
    return max(1, n)


@dataclass
class Machine:
    total: int                 # RAM this process may use: physical, or the cgroup limit if lower
    available: int | None      # what is free right now
    cpus: int
    cgroup_limited: bool = False

    @classmethod
    def detect(cls) -> "Machine":
        phys = physical_memory() or 4 * GiB          # conservative guess if nothing can be read
        avail = system_available_memory()
        limit, usage = cgroup_memory()
        limited = limit is not None and limit < phys
        total = limit if limited else phys
        if limited and usage is not None:
            in_group = max(0, limit - usage)
            avail = min(avail, in_group) if avail is not None else in_group
        return cls(total=total, available=avail, cpus=cpu_count(), cgroup_limited=limited)


# -- budget -----------------------------------------------------------------------------------
@dataclass
class Budget:
    memory: int                # DuckDB memory_limit for one analysis
    threads: int
    max_temp: int | None       # DuckDB max_temp_directory_size (None: DuckDB's own default)
    ceiling: int               # most memory any one analysis may be given
    machine: Machine
    source: str                # "auto", "VULNSCOPE_DUCKDB_MEMORY", or "argument"
    warnings: list[str]

    def describe(self) -> str:
        where = "container limit" if self.machine.cgroup_limited else "RAM"
        temp = f", spill up to {fmt_size(self.max_temp)}" if self.max_temp else ""
        return (f"DuckDB memory {fmt_size(self.memory)} ({self.source}; {fmt_size(self.machine.total)} "
                f"{where}, safe ceiling {fmt_size(self.ceiling)}), {self.threads} thread"
                f"{'s' if self.threads != 1 else ''}{temp}")


def max_jobs() -> int:
    raw = os.environ.get("VULNSCOPE_MAX_JOBS", "").strip()
    try:
        return max(1, int(raw)) if raw else 1
    except ValueError:
        return 1


def plan(memory_limit: str | None = None, workdir: str | None = None, *,
         machine: Machine | None = None, env: dict | None = None, jobs: int | None = None) -> Budget:
    """Decide DuckDB's memory, threads and spill cap for one analysis."""
    env = os.environ if env is None else env
    m = machine or Machine.detect()
    jobs = jobs or max_jobs()
    warnings: list[str] = []

    reserve = max(RESERVE_MIN, int(m.total * RESERVE_FRACTION))
    ceiling = max(MIN_MEMORY, (m.total - reserve) // jobs)

    requested = memory_limit or env.get("VULNSCOPE_DUCKDB_MEMORY") or ""
    source = ("argument" if memory_limit else "VULNSCOPE_DUCKDB_MEMORY") if requested else "auto"
    if requested:
        try:
            memory = parse_size(requested, whole=m.total - reserve)
        except ValueError as exc:
            warnings.append(f"Ignoring VULNSCOPE_DUCKDB_MEMORY: {exc}.")
            memory, source = 0, "auto"
        else:
            if memory > ceiling:
                warnings.append(f"Requested DuckDB memory {requested} is more than this machine can spare; "
                                f"using {fmt_size(ceiling)} so the OS keeps {fmt_size(reserve)}.")
                memory = ceiling
            elif m.available is not None and memory > m.available:
                warnings.append(f"Requested DuckDB memory {requested} is more than is free right now "
                                f"({fmt_size(m.available)}); the run may swap or fail.")
    if source == "auto":
        memory = int(m.total * AUTO_FRACTION) // jobs
        if m.available is not None and memory > m.available * AVAILABLE_FRACTION:
            lower = int(m.available * AVAILABLE_FRACTION)
            warnings.append(f"Only {fmt_size(m.available)} is free right now; giving DuckDB "
                            f"{fmt_size(max(MIN_MEMORY, lower))} instead of {fmt_size(memory)}.")
            memory = lower
        memory = min(memory, ceiling)
    memory = max(MIN_MEMORY, memory)

    threads = max(1, min(m.cpus, memory // BYTES_PER_THREAD))
    raw_threads = env.get("VULNSCOPE_DUCKDB_THREADS", "").strip()
    if raw_threads:
        try:
            threads = max(1, min(int(raw_threads), m.cpus))
        except ValueError:
            warnings.append(f"Ignoring VULNSCOPE_DUCKDB_THREADS={raw_threads!r}: not a number.")

    max_temp = None
    free = _free_disk(workdir)
    if free is not None:
        safe = max(TEMP_MIN, int(free * TEMP_FRACTION))
        max_temp = safe
        raw_temp = env.get("VULNSCOPE_DUCKDB_MAX_TEMP", "").strip()
        if raw_temp:
            try:
                want = parse_size(raw_temp, whole=free)
                if want > safe:
                    warnings.append(f"VULNSCOPE_DUCKDB_MAX_TEMP={raw_temp} is more than 80% of the free disk; "
                                    f"capping spill at {fmt_size(safe)}.")
                max_temp = min(want, safe)
            except ValueError as exc:
                warnings.append(f"Ignoring VULNSCOPE_DUCKDB_MAX_TEMP: {exc}.")
    return Budget(memory=memory, threads=threads, max_temp=max_temp, ceiling=ceiling, machine=m,
                  source=source, warnings=warnings)


def _free_disk(path: str | None) -> int | None:
    import tempfile
    p = path or tempfile.gettempdir()
    while p and not os.path.exists(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    try:
        return shutil.disk_usage(p or ".").free
    except OSError:
        return None


# -- concurrency ------------------------------------------------------------------------------
_slots_lock = threading.Lock()
_slots_in_use = 0


def busy() -> bool:
    """True when every analysis slot is taken (checked before accepting a large upload)."""
    with _slots_lock:
        return _slots_in_use >= max_jobs()


@contextmanager
def job_slot():
    """Hold one analysis slot for the duration of a run; refuse at once when all are taken.

    Refusing (rather than queueing) keeps the upload page honest: a queued request would sit
    with no progress for as long as the running analysis takes."""
    global _slots_in_use
    limit = max_jobs()
    with _slots_lock:
        if _slots_in_use >= limit:
            raise BusyError("Another analysis is already running on this machine. Wait for it to finish "
                            "and try again (VULNSCOPE_MAX_JOBS sets how many may run at once; each one "
                            "gets an equal share of the memory budget).")
        _slots_in_use += 1
    try:
        yield
    finally:
        with _slots_lock:
            _slots_in_use -= 1


# -- friendly errors --------------------------------------------------------------------------
def explain(exc: BaseException, budget: Budget | None) -> ResourceError | None:
    """Turn a DuckDB out-of-memory or out-of-disk failure into an actionable message."""
    import duckdb
    text = str(exc)
    low = text.lower()
    # Checked first: DuckDB reports a full spill area as an "Out of Memory Error" too.
    if (isinstance(exc, OSError) and exc.errno == errno.ENOSPC
            or "max_temp_directory_size" in low or "no space left" in low
            or "could not write" in low and "temp" in low):
        cap = f" (spill cap {fmt_size(budget.max_temp)})" if budget and budget.max_temp else ""
        return ResourceError("The analysis ran out of disk space for temporary files" + cap + ". Free space "
                             "or point --workdir / VULNSCOPE_WORKDIR at a larger disk.")
    if isinstance(exc, getattr(duckdb, "OutOfMemoryException", ())) or "out of memory" in low:
        if budget is None:
            return ResourceError(f"The analysis ran out of memory: {text}")
        more = (f" You can raise VULNSCOPE_DUCKDB_MEMORY up to {fmt_size(budget.ceiling)} on this machine."
                if budget.memory < budget.ceiling * 0.95 else
                " This is already the most this machine can safely give; run on a machine with more RAM, "
                "or split the input into smaller folders (for example one per day).")
        return ResourceError(f"The analysis needed more than the {fmt_size(budget.memory)} of memory "
                             f"allotted to DuckDB and was stopped before it could destabilise the machine."
                             + more)
    return None
