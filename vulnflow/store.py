"""Disk-backed storage for large telemetry sets.

Parsers stream records into this module in batches. Flows are written to Parquet
partitioned by sensor and day inside a local working directory, then de-duplicated
and sorted with DuckDB SQL into a single on-disk table that the correlator queries.
Zeek and OT events are spooled to JSONL. Nothing here holds the whole input in memory.
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import tempfile
import weakref
from datetime import datetime, timedelta, timezone
from itertools import islice

import duckdb

from . import resources
from .schema import Flow, OTEvent, ZeekEvent

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_BATCH = 100_000
DEFAULT_SKEW_SECONDS = 2.0
# When two different sensors record the same session, keep the record from the sensor that
# knows the most about it: the firewall knows the policy action and zones, Zeek the byte counts.
SENSOR_RANK = {"paloalto": 0, "zeek": 1, "suricata": 2, "generic": 3}

FLOW_COLUMNS = ["ord", "ts_us", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "action",
                "established", "bytes_out", "bytes_in", "app", "src_zone", "dst_zone", "source",
                "sensor", "fid", "day"]
_CSV_TYPES = {"ord": "BIGINT", "ts_us": "BIGINT", "src_ip": "VARCHAR", "dst_ip": "VARCHAR",
              "src_port": "INTEGER", "dst_port": "INTEGER", "proto": "VARCHAR", "action": "VARCHAR",
              "established": "BOOLEAN", "bytes_out": "BIGINT", "bytes_in": "BIGINT", "app": "VARCHAR",
              "src_zone": "VARCHAR", "dst_zone": "VARCHAR", "source": "VARCHAR", "sensor": "VARCHAR",
              "fid": "INTEGER", "day": "VARCHAR"}
# Columns read back into Flow objects, in Flow field order.
FLOW_SELECT = ("ts, src_ip, dst_ip, dst_port, proto, src_port, action, established, "
               "bytes_out, bytes_in, app, src_zone, dst_zone, source")


def _us(ts: datetime | None) -> int | None:
    if ts is None:
        return None
    delta = ts - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def utc(ts: datetime | None) -> datetime | None:
    """DuckDB TIMESTAMP values come back naive; they are always UTC here."""
    return ts.replace(tzinfo=timezone.utc) if ts is not None and ts.tzinfo is None else ts


def naive(ts: datetime | None) -> datetime | None:
    """Aware UTC datetime -> naive UTC, for binding to TIMESTAMP parameters."""
    return ts.astimezone(timezone.utc).replace(tzinfo=None) if ts is not None and ts.tzinfo else ts


def row_to_flow(r) -> Flow:
    return Flow(utc(r[0]), r[1], r[2], r[3], r[4], src_port=r[5], action=r[6], established=r[7],
                bytes_out=r[8], bytes_in=r[9], app=r[10], src_zone=r[11], dst_zone=r[12], source=r[13])


class Store:
    """One working directory + DuckDB database per analysis run."""

    def __init__(self, workdir: str | None = None, memory_limit: str | None = None,
                 budget: resources.Budget | None = None):
        """DuckDB's memory, threads and spill cap are sized to this machine (see resources.py);
        ``memory_limit`` or $VULNSCOPE_DUCKDB_MEMORY override the memory, clamped to a safe ceiling."""
        base = workdir or os.environ.get("VULNSCOPE_WORKDIR") or None
        if base:
            os.makedirs(base, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="vulnscope-work-", dir=base)
        self.budget = budget or resources.plan(memory_limit, self.dir)
        self.con = duckdb.connect(os.path.join(self.dir, "work.duckdb"))
        tmp = os.path.join(self.dir, "duckdb_tmp")
        os.makedirs(tmp, exist_ok=True)
        self.con.execute(f"SET temp_directory = '{_q(tmp)}'")
        self.con.execute(f"SET memory_limit = '{self.budget.memory // resources.MiB}MiB'")
        self.con.execute(f"SET threads = {int(self.budget.threads)}")
        if self.budget.max_temp:
            self.con.execute(f"SET max_temp_directory_size = '{self.budget.max_temp // resources.MiB}MiB'")
        self.con.execute("SET preserve_insertion_order = false")
        self.parquet_dir = os.path.join(self.dir, "flows_parquet")
        self._batches = 0
        self._finalizer = weakref.finalize(self, _cleanup, self.con, self.dir)

    def close(self):
        self._finalizer()

    # -- bulk loading -------------------------------------------------------
    def _write_csv(self, rows, name: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(rows)
        return path

    def _read_csv_sql(self, path: str, columns: dict[str, str]) -> str:
        cols = ", ".join(f"'{k}': '{v}'" for k, v in columns.items())
        return (f"read_csv('{_q(path)}', columns={{{cols}}}, header=false, delim=',', quote='\"', "
                f"escape='\"', nullstr='', auto_detect=false, strict_mode=false)")

    def write_flow_batch(self, rows: list[tuple]):
        """Append one batch of flow rows (FLOW_COLUMNS order) as Parquet partitions."""
        if not rows:
            return
        self._batches += 1
        path = self._write_csv(rows, f"batch_{self._batches}.csv")
        try:
            # Empty strings are read back as NULL by nullstr=''; restore them for text columns.
            text = {"app", "src_zone", "dst_zone", "source"}
            select = ", ".join(f"coalesce({c}, '') AS {c}" if c in text else c for c in FLOW_COLUMNS)
            self.con.execute(
                f"COPY (SELECT {select} FROM {self._read_csv_sql(path, _CSV_TYPES)}) "
                f"TO '{_q(self.parquet_dir)}' (FORMAT parquet, PARTITION_BY (sensor, day), "
                f"OVERWRITE_OR_IGNORE true, FILENAME_PATTERN 'batch{self._batches}_{{i}}')")
        finally:
            os.remove(path)

    def finalize_flows(self, skew_seconds: float | None = DEFAULT_SKEW_SECONDS) -> tuple[int, int]:
        """Build the clean ``flows`` table from the Parquet partitions.

        1. Exact duplicates (same time, 5-tuple and action) keep their first occurrence.
        2. The same session recorded by two different sensors (same 5-tuple, start times within
           ``skew_seconds``) is kept once, from the higher-ranked sensor. Two sensors of the same
           kind in different input files (e.g. two Zeek taps) count too: when they agree on the
           action, the most complete record (completed session, then most bytes) is kept.
        Returns (exact duplicates removed, cross-sensor duplicates removed).
        """
        con = self.con
        if not self._batches:
            con.execute("CREATE OR REPLACE TABLE flows (seq BIGINT, ts TIMESTAMP, src_ip VARCHAR, "
                        "dst_ip VARCHAR, src_port INTEGER, dst_port INTEGER, proto VARCHAR, "
                        "action VARCHAR, established BOOLEAN, bytes_out BIGINT, bytes_in BIGINT, "
                        "app VARCHAR, src_zone VARCHAR, dst_zone VARCHAR, source VARCHAR, sensor VARCHAR)")
            return 0, 0
        rank = " ".join(f"WHEN '{k}' THEN {v}" for k, v in SENSOR_RANK.items())
        glob = _q(os.path.join(self.parquet_dir, "**", "*.parquet"))
        con.execute(f"""
            CREATE OR REPLACE TABLE flows_exact AS
            SELECT * EXCLUDE (ts_us, day), make_timestamp(ts_us) AS ts,
                   CASE sensor {rank} ELSE 9 END AS sensor_rank
            FROM read_parquet('{glob}', hive_partitioning = true, hive_types_autocast = false)
            QUALIFY row_number() OVER (PARTITION BY ts_us, src_ip, src_port, dst_ip, dst_port, proto, action
                                       ORDER BY ord) = 1""")
        total = con.execute(f"SELECT count(*) FROM read_parquet('{glob}')").fetchone()[0]
        kept = con.execute("SELECT count(*) FROM flows_exact").fetchone()[0]
        exact = total - kept
        if skew_seconds is not None and skew_seconds >= 0:
            con.execute(f"""
                CREATE OR REPLACE TEMP TABLE cross_dups AS
                SELECT DISTINCT a.ord FROM flows_exact a JOIN flows_exact b
                  ON a.src_ip = b.src_ip AND a.dst_ip = b.dst_ip AND a.src_port = b.src_port
                 AND a.dst_port = b.dst_port AND a.proto = b.proto
                WHERE (b.sensor_rank < a.sensor_rank
                       OR (b.sensor_rank = a.sensor_rank AND b.fid <> a.fid AND b.action = a.action
                           -- same kind of sensor: keep the most complete record (a tap that saw the
                           -- whole session beats one that saw only the SYN), then the one read first
                           AND (b.established AND NOT a.established
                                OR (b.established = a.established
                                    AND (b.bytes_out + b.bytes_in > a.bytes_out + a.bytes_in
                                         OR (b.bytes_out + b.bytes_in = a.bytes_out + a.bytes_in
                                             AND b.ord < a.ord))))))
                  AND abs(epoch_us(a.ts) - epoch_us(b.ts)) <= {int(skew_seconds * 1_000_000)}""")
        else:
            con.execute("CREATE OR REPLACE TEMP TABLE cross_dups (ord BIGINT)")
        cross = con.execute("SELECT count(*) FROM cross_dups").fetchone()[0]
        con.execute("""
            CREATE OR REPLACE TABLE flows AS
            SELECT row_number() OVER (ORDER BY ts NULLS LAST, ord) AS seq,
                   ts, src_ip, dst_ip, src_port, dst_port, proto, action, established,
                   bytes_out, bytes_in, app, src_zone, dst_zone, source, sensor
            FROM flows_exact ANTI JOIN cross_dups USING (ord)""")
        con.execute("DROP TABLE flows_exact; DROP TABLE cross_dups")
        shutil.rmtree(self.parquet_dir, ignore_errors=True)
        return exact, cross

    def load_flow_list(self, flows: list[Flow]):
        """Load an in-memory list (tests, small callers) as-is: no de-duplication."""
        writer = FlowWriter(self)
        for f in flows:
            writer.add(f, "list")
        writer.flush()
        self.finalize_flows(skew_seconds=None)

    def insert_rows(self, table: str, columns: dict[str, str], rows) -> None:
        """Create ``table`` and bulk-load rows through a CSV file (fast, needs no numpy/arrow)."""
        cols = ", ".join(f"{k} {v}" for k, v in columns.items())
        self.con.execute(f"CREATE OR REPLACE TABLE {table} ({cols})")
        rows = list(rows)
        if not rows:
            return
        self._batches += 1
        path = self._write_csv(rows, f"{table}_{self._batches}.csv")
        try:
            self.con.execute(f"INSERT INTO {table} SELECT * FROM {self._read_csv_sql(path, columns)}")
        finally:
            os.remove(path)


class FlowWriter:
    """Buffers flows and writes one Parquet batch per ``batch_size`` rows."""

    def __init__(self, store: Store, batch_size: int = DEFAULT_BATCH):
        self.store, self.batch_size, self.rows, self.ord = store, batch_size, [], 0
        self._days: dict[int, str] = {}

    def add(self, f: Flow, sensor: str, fid: int = 0):
        """``fid`` numbers the input file, so sessions repeated by a second sensor of the same
        kind (another Zeek tap) can be told apart from records inside one file."""
        us = _us(f.ts)
        if us is None:
            day = "untimed"
        else:
            d = us // 86_400_000_000
            day = self._days.get(d)
            if day is None:
                day = self._days[d] = (EPOCH + timedelta(days=d)).strftime("%Y-%m-%d")
        self.rows.append((self.ord, us, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto, f.action,
                          f.established, f.bytes_out or 0, f.bytes_in or 0, f.app, f.src_zone,
                          f.dst_zone, f.source, sensor, fid, day))
        self.ord += 1
        if len(self.rows) >= self.batch_size:
            self.flush()

    def flush(self):
        self.store.write_flow_batch(self.rows)
        self.rows = []


class FlowView:
    """Read-only, sequence-like view of the clean flows table, in time order."""

    def __init__(self, store: Store):
        self.store = store
        self._len = None

    def __len__(self):
        if self._len is None:
            self._len = self.store.con.execute("SELECT count(*) FROM flows").fetchone()[0]
        return self._len

    def __bool__(self):
        return len(self) > 0

    def __iter__(self):
        cur = self.store.con.cursor()
        cur.execute(f"SELECT {FLOW_SELECT} FROM flows ORDER BY seq")
        while True:
            rows = cur.fetchmany(10_000)
            if not rows:
                break
            for r in rows:
                yield row_to_flow(r)
        cur.close()

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(self)[i]
        n = len(self)
        if i < 0:
            i += n
        if not 0 <= i < n:
            raise IndexError(i)
        r = self.store.con.execute(f"SELECT {FLOW_SELECT} FROM flows WHERE seq = ?", [i + 1]).fetchone()
        return row_to_flow(r)

    def __eq__(self, other):
        if isinstance(other, (list, FlowView)):
            return len(self) == len(other) and list(self) == list(other)
        return NotImplemented

    __hash__ = None


class EventSpool:
    """Append-only JSONL spool of Zeek / OT events with a sequence-like read view."""

    def __init__(self, store: Store, name: str, ot: bool):
        self.path = os.path.join(store.dir, f"{name}.jsonl")
        self.ot = ot
        self._fh = open(self.path, "w", encoding="utf-8")
        self._len = 0

    def add(self, e: ZeekEvent):
        row = {"ts": _us(e.ts), "stream": e.stream, "uid": e.uid, "src_ip": e.src_ip,
               "dst_ip": e.dst_ip, "source": e.source, "fields": e.fields}
        if self.ot:
            row.update(protocol=e.protocol, operation=e.operation, direction=e.direction)
        self._fh.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
        self._len += 1

    def close(self):
        if not self._fh.closed:
            self._fh.close()

    def __len__(self):
        return self._len

    def __bool__(self):
        return self._len > 0

    def __iter__(self):
        self.close()
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                ts = EPOCH + timedelta(microseconds=r["ts"]) if r["ts"] is not None else None
                common = dict(ts=ts, stream=r["stream"], uid=r["uid"], src_ip=r["src_ip"],
                              dst_ip=r["dst_ip"], fields=r["fields"], source=r["source"])
                if self.ot:
                    yield OTEvent(**common, protocol=r["protocol"], operation=r["operation"],
                                  direction=r["direction"])
                else:
                    yield ZeekEvent(**common)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(self)[i]
        if i < 0:
            i += self._len
        if not 0 <= i < self._len:
            raise IndexError(i)
        return next(islice(iter(self), i, None))


def _q(s: str) -> str:
    return str(s).replace("'", "''")


def _cleanup(con, path):
    try:
        con.close()
    except Exception:
        pass
    shutil.rmtree(path, ignore_errors=True)
