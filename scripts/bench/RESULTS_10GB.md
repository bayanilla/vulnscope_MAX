# vulnscope_MAX at 50 GB of Zeek logs (2026-11-05)

`main` of bayanilla/vulnscope_MAX (831f560), unchanged app code. Folder input, working directory
set with `VULNSCOPE_WORKDIR` (same as `--workdir`). Machine: 4 vCPU, 15 GiB RAM, 30 GB free disk,
Python 3.13, DuckDB 1.5.6. Synthetic Zeek `conn`/`dns` + Palo Alto from `scripts/bench/gen_logs.py`,
seed 7, defaults except `--gz 1.0` (every hourly file gzipped, like an archived Zeek export) so the
input takes about a quarter of its size on disk. Telemetry only, no scan file. Raw JSON is in
[`results/`](results/) (`g1z`, `g5_mem4`, `g10_*`).

**50 GB was not run.** It does not fit this machine on two counts: the working directory needs
about 1.3 GB of disk per GB of logs (about 65 GB at 50 GB, against 30 GB free), and the dedup step
needs DuckDB memory that grows with the input (more than 4 GB at 10 GB). 10 GB is the largest size
that fit in RAM. The 50 GB row below is extrapolated from 1, 5 and 10 GB.

## Summary

- **The default settings fail at 5 GB.** Normalize stops with a DuckDB `Out of Memory Error` in the
  exact-duplicate step (`store.py:134`, the `row_number() OVER (PARTITION BY ts_us, 5-tuple, action)`
  window). DuckDB's limit is 1 GB by default (`DEFAULT_MEMORY_LIMIT`) and this window does not spill
  to disk. A user running 5 GB with defaults gets a crash after 10 minutes of parsing.
- **Raising `VULNSCOPE_DUCKDB_MEMORY` gets further, but only so far.** 5 GB works with 4GB. 10 GB
  fails with 4GB and works with 10GB, peaking at 10.8 GiB for the process. At 50 GB the same
  step would need roughly 25 to 50 GB of DuckDB memory, so a 64 GB machine, unless the dedup is
  done per day partition (see "What would make 50 GB work").
- **Parsing is flat and linear.** 0.37 GiB RSS at every size and about 113 s per GB on one core
  (about 9 MB/s of uncompressed logs). Gzipped input parses as fast as plain text (1 GB: 108 s gz vs
  113 s mixed). At 50 GB parsing alone is about 95 minutes.
- **Normalize and correlate grow faster than linearly.** Doubling 5 to 10 GB made normalize 2.7x
  slower and correlate 2.5x slower.
- **Counts stay exact.** At 10 GB the tool kept 42,080,687 sessions, which equals the generator's
  ground truth, after removing 1,346,937 exact duplicates and 25,251,523 cross-sensor copies.
- **The report stage was skipped** (`--skip-report`). It still builds `explorer.html` in memory and
  was already OOM-killed at 1 GB in the earlier run, so it would fail at every size here.

## Results

| Logs (uncompressed / on disk) | DuckDB limit | Parse | Normalize (dedup) | Correlate | Total (no report) | Peak RSS | Workdir peak | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 GB / 0.25 GB | 1GB (default) | 108 s | 13 s | 12 s | 2.2 min | 1.38 GiB | 1.28 GiB | OK |
| 5 GB / 1.24 GB | 1GB (default) | ~560 s | failed | — | — | — | — | DuckDB out of memory in exact dedup |
| 5 GB / 1.24 GB | 4GB | 560 s | 74 s | 47 s | 11.3 min | 4.57 GiB | 7.05 GiB | OK |
| 10 GB / 2.48 GB | 4GB | 1,123 s | failed | — | — | 4.15 GiB | 13.9 GiB | DuckDB out of memory in exact dedup |
| 10 GB / 2.48 GB | 10GB | 1,135 s | 200 s | 118 s | 24.2 min | 10.84 GiB | 12.5 GiB | OK |
| **50 GB / ~12.4 GB (extrapolated)** | ~25–50 GB | ~95 min | ~35 min | ~15–20 min | **~2.5 h** | **~30–55 GiB** | **~65 GB** | Needs a 64 GB RAM machine and ~80 GB free disk |

Peak RSS per stage: parse stays at 0.37 GiB; the normalize peak is DuckDB (dedup); correlate peaked
at 0.92, 2.78 and 5.92 GiB at 1, 5 and 10 GB. Workdir after normalize (the DuckDB file and the DNS
spool) is 0.85, 4.2 and 8.4 GiB; the peak is during dedup, when the Parquet batches, DuckDB's spill
and the new tables exist together.

1 GB with mixed plain/gz input (the earlier benchmark's layout) took 113 s parse, 14 s normalize
and 11 s correlate, with the same 1.39 GiB peak and 1.29 GiB workdir.

### Extrapolation method

Parse is linear (measured). Normalize and correlate use the growth seen between 5 and 10 GB
(exponents 1.44 and 1.32) carried to 50 GB; they could be slower if DuckDB spills more at that size.
Workdir disk is linear at about 1.3 GB per GB of logs. DuckDB memory: more than 1 GB was needed at
5 GB, more than 4 GB at 10 GB, and 10 GB was enough, which suggests 0.5 to 1 GB per GB of logs.

### Where the disk goes (1 GB, sampled every 4 s)

During parse: `flows_parquet/` (190 MB per GB) and `zeek_events.jsonl` (540 MB per GB, the DNS
records spooled as JSON, about 3.5x their log size). During dedup DuckDB adds its spill
(`duckdb_tmp/`, about 390 MB) and `work.duckdb` (about 330 MB). Parquet is deleted after dedup. The
whole workdir is removed when the run ends.

## What would make 50 GB work

These are suggestions; no app code was changed.

1. **Dedup per day.** Run the exact-duplicate window and the cross-sensor join one `day` partition
   at a time (with the 2 s skew window crossing midnight). Memory would then depend on the busiest
   day, not on the whole input, and the default 1GB limit would likely hold at any size.
2. **Pick the DuckDB memory limit from the machine** (for example 60% of RAM) instead of a fixed 1GB,
   and tell the user "dedup needs more memory" instead of a raw DuckDB traceback.
3. **Store DNS events in Parquet** instead of JSONL. That is the largest part of the workdir.
4. **Parse in parallel.** Parsing is one core at ~9 MB/s; four workers would cut 95 minutes to about
   25 at 50 GB.
5. The Explorer page still has to read results on demand before any run above about 250 MB can
   produce a report.

## How it was run

```bash
python3 scripts/bench/gen_logs.py /data/g10 --size 10G --seed 7 --gz 1.0
VULNSCOPE_DUCKDB_MEMORY=10GB python3 scripts/bench/bench_pipeline.py /data/g10 -o /data/out \
    --json g10.json --workdir /data/wd --skip-report --rss-limit 13G
```

`--workdir` (records workdir size per stage) and `--skip-report` were added to
`bench_pipeline.py` for this run, along with recording a failed stage in the JSON. Only the
benchmark harness changed.
