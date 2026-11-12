# Configured limits

Numeric bounds in one place. Each row names where the value is set; change it there.

| Boundary | Limit | Meaning | Set in |
| --- | ---: | --- | --- |
| Upload size | 1,024 MB | per upload; `serve --max-upload-mb` | `vulnflow/web/server.py` |
| Upload chunk | 64 KB | uploads stream to disk in chunks | `vulnflow/multipart.py` |
| `.gz` expansion | 200× | of compressed size, minimum 256 MB; `VULNSCOPE_MAX_GZ_BYTES` | `vulnflow/parsers/_util.py` |
| Parser batch | 100,000 | records per Parquet batch | `vulnflow/store.py` |
| De-duplication skew | 2 s | cross-sensor match window; `--dedup-skew` | `vulnflow/store.py` |
| Scan window | 7 days | telemetry before/after a host's scan; `--scan-window-days` | `vulnflow/cli.py` |
| Blast-radius depth | 2 hops | `--hops` | `vulnflow/cli.py` |
| Large upload | 20 MB | upload size counted as a post-contact lead | `vulnflow/correlate.py` |
| DuckDB memory | 60% | of usable RAM, ≤80% of free RAM, keeping 25% (≥1.5 GiB); `VULNSCOPE_DUCKDB_MEMORY` | `vulnflow/resources.py` |
| DuckDB threads | 1 per GiB | of DuckDB memory, up to usable CPUs; `VULNSCOPE_DUCKDB_THREADS` | `vulnflow/resources.py` |
| DuckDB spill | 80% | of the working disk's free space; `VULNSCOPE_DUCKDB_MAX_TEMP` | `vulnflow/resources.py` |
| Concurrent analyses | 1 | per process; `VULNSCOPE_MAX_JOBS` | `vulnflow/resources.py` |
| Article previews | 60 | pages per run, 800 KB each | `vulnflow/article_preview.py` |
| Article briefs | 20 | articles per run, 18,000 characters each | `vulnflow/article_brief.py` |
| Assistant context | 150 | findings for hosted providers; 10 for `local` | `vulnflow/llm.py` |
| Assistant history | 20 | conversation turns kept | `vulnflow/llm.py` |
| Hostile activity diagram | 40 | nodes | `vulnflow/diagram.py` |
| Explorer focus | 24 / 400 | labeled / drawn peers per side | `vulnflow/static/explorer.js` |
| Explorer IP list | 8 / 20 | preview rows / rows per page | `vulnflow/static/explorer.js` |
| Explorer overview | 2,000 / 200 / 48 | hosts (riskiest) / risky paths / outside addresses drawn | `vulnflow/explore.py`, `vulnflow/static/explorer.js` |
| Attack paths | 9 | ranked lines | `vulnflow/static/attackpaths.js` |
| Timeline | 20,000 | flows drawn; 200 alerts, 400 IOC lookups | `vulnflow/explore.py` |
| Branding name | 40 | characters before "VulnScope" | `vulnflow/branding.py` |
| Branding logo | 512 KB, 2,048 px | file size, longest side | `vulnflow/branding.py` |
| Branding unlock | 30 min, 5 attempts | unlock lifetime; free attempts before a doubling lockout | `vulnflow/web/branding_page.py` |
| Report network name | 60 | characters | `vulnflow/runname.py` |
| Compare upload | 64 MB | IOC CSVs added on the Compare page | `vulnflow/web/compare_page.py` |
| Compare hosts | 12 / 1,000 | related hosts per report drawn on the page / per CSV cell (`comparison.json` has all) | `vulnflow/compare.py` |
| Compare folder search | 4 levels | how deep `vulnflow compare FOLDER` looks for report folders | `vulnflow/compare.py` |
| Earlier comparisons | 12 | listed on the Compare page (all are kept) | `vulnflow/web/compare_page.py` |
