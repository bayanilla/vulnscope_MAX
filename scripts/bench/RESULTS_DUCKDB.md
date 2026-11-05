# Streaming + DuckDB pipeline results (2026-11-05)

Branch `claude/project-thread-x0rn3x` in vulnscope_MAX, measured with this harness on the same
kind of machine as [`RESULTS.md`](RESULTS.md) (4 vCPU, 15 GiB RAM, Python 3.13, DuckDB 2.0).
Inputs come from `gen_logs.py` with default settings and seed 7, so they match the baseline sets.
Telemetry only. The temp directory was set with `VULNSCOPE_WORKDIR`.

| Logs | Version | Sessions (true count) | Parse + normalize | Correlate | Report | Total | Peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 250 MB | main 945d374 (same machine) | 1,515,338 (1,027,810) | 56 s, 1.53 GiB | 601 s, 1.39 GiB | 102 s, 4.67 GiB | 12.7 min | 5.77 GiB |
| 250 MB | this branch | **1,027,810** (1,027,810) | 65 s, 0.73 GiB | **7 s**, 0.58 GiB | 103 s, 3.86 GiB | 2.9 min | 4.79 GiB |
| 1 GB | main (from RESULTS.md) | 6.37 M (4,208,334) | 125 s, 6.36 GiB | 1,580 s, 5.62 GiB | OOM-killed | >28 min | >13.3 GiB |
| 1 GB | this branch | **4,208,334** (4,208,334) | 259 s, 1.16 GiB | **22 s**, 0.84 GiB | OOM-killed (Explorer page) | — | >12 GiB in report |

What changed:

- Session counts now match the generator's ground truth exactly. Cross-sensor matching removed
  615,975 (250 MB) and 2,525,034 (1 GB) Zeek copies of firewall sessions; exact duplicates are
  removed as before.
- Palo Alto `.gz` files are read (130,940 rows at 250 MB and 371,171 at 1 GB were lost before).
- Load and correlate memory is now flat at about 1 GiB, because flows live in Parquet and DuckDB
  (1 GB DuckDB memory limit, spilling to the working directory). Correlate is about 80x faster at
  250 MB and 70x faster at 1 GB; the quadratic `network_leads` loop is a single SQL join.
- Parsing is still single-threaded Python, at roughly 4 MB/s on this machine. On the same machine
  main parsed 250 MB in 56 s, versus 65 s here, and this branch parses the `.gz` firewall rows main
  dropped.

Still open: the report stage builds `explorer.html` in memory, with every host's full peer
and attacker lists. That page is about 2x the input, is blank in browsers above roughly 250 MB, and
is now the only stage that grows with input size. At 1 GB the kernel killed it. The Explorer reading
from the results on demand is the next planned step.
