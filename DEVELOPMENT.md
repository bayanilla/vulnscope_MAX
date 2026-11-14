# Development and verification

Run from this directory with Python 3.10+ and DuckDB installed:

```sh
python3 -m pip install -r requirements.txt
python3 -m vulnflow serve
```

Verification uses synthetic data and never needs a model, an API key or network access. Run:

```sh
python3 -m unittest discover -s tests
```

`tests/test_pcap.py` runs Zeek when it is installed and skips those cases otherwise.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to `main`:

- **Repository hygiene**: `scripts/check_repo.py` fails on local branding (`branding.json`, `.vulnscope/`),
  `.env` files, packet captures, executables and archives (by name and by their first bytes), private or
  API keys, files over 5 MB, and images outside `screenshots/`, `vulnflow/static/` and `example_output/`.
  Run it before committing, or install it as a pre-commit hook (the script's header shows how).
- **Tests**: the suite above on Python 3.10 (the oldest supported) and 3.13 (the Docker image's).
- **Explorer pages**: `scripts/smoke/explorer_smoke.py --samples WORK` analyzes the bundled samples, an
  edge case (IOCs with no article link) and the two-company comparison, opens each `explorer.html` in
  headless Chromium and walks 3D, a focused host, Flat, Attack paths and Timeline. It fails on any page
  error, when 3D draws fewer hosts than the data holds, or when the Timeline draws fewer flows than it
  has. Screenshots of every view are kept with the run. Locally: `pip install playwright` and
  `python -m playwright install chromium` first (about 3 minutes).
- **Docker image**: builds the image (linux/amd64), checks Zeek and DuckDB are inside, analyzes the
  Gootloader sample in the container and checks the upload page answers.
- **Accuracy on Brim sample data**: `scripts/accuracy/run.sh` downloads Brim's public captures and
  logs (9 PCAPs from brimcap and Zui, the WRCCDC 2018 Zeek logs as TSV and JSON, a Zui JSON export),
  runs the image on each, runs Suricata on one capture, and compares every count with ground truth
  that `scripts/accuracy/groundtruth.py` computes from the raw logs without any VulnScope code (the
  PCAPs get their reference logs from a separate Zeek). The files are pinned to exact upstream commits
  and checked against the SHA-256 hashes in `brim_manifest.txt`; they are downloaded on the CI machine
  only and never committed or put in the image. None of them contains malware: the captures are
  ordinary web browsing and the WRCCDC data is Zeek logs, which hold no file contents. Run it locally
  with `scripts/accuracy/run.sh /tmp/brim-data /tmp/brim-work` (needs Docker; about 10 minutes).

It needs no secrets, API key or model. A PR shows a green check or a red cross for each job; the
failing step's log is one click away under **Details**.

| Test file | Covers |
| --- | --- |
| `test_workflow.py` | Parsing, normalization, correlation, scoring and reports end to end; the bundled samples; the Docker entry point |
| `test_scale.py`, `test_resources.py` | Streaming, Parquet/DuckDB de-duplication, memory/thread/disk sizing |
| `test_pcap.py`, `test_filebeat.py` | Packet capture conversion; Filebeat CSV/NDJSON back to Zeek |
| `test_capture_accuracy.py` | Mid-stream sessions, answered pings, broadcasts, capture loss, Zui/Brim exports, Suricata mid-stream flows |
| `test_explore.py`, `test_visual.py` | Explorer data, drawing limits, HTML output |
| `test_security.py`, `test_multipart.py` | Host/Origin/CSRF checks on every state-changing route (DNS rebinding), API-key endpoint rules and the unfamiliar-endpoint warning, Browse confinement, upload parsing, `.gz` limits |
| `test_scanners.py` | Hosts vs probed-only addresses, scanner detection, `known_scanners.csv`, probed ranges, firewall blocks, the one-way sensor warning |
| `test_llm.py`, `test_offline_assistant.py` | Provider adapters, redaction, grounding; the built-in assistant |
| `test_article_brief.py`, `test_radar.py` | Article briefs and Radar lookups with stubbed services |
| `test_branding.py` | Branding page, password lock, logo validation |
| `test_saved.py`, `test_report_name.py` | Reopening a saved report; report names, networks and timestamped run folders |
| `test_compare.py` | Compare reports: counts per report and network, the re-hunt over saved data, the all-networks Explorer (islands, shared-item highlights, fair trimming), command line and page, the two-company sample |
| `test_web_errors.py` | Which analysis errors the upload page shows, and which go to the server console |

## Samples

`python3 -m vulnflow samples` rewrites the sample folders: scan-backed, telemetry-only, the 4,324-host
on-prem + AWS sample, Gootloader (`vulnflow/sample_gootloader.py`) and the two-company Compare sample
(`vulnflow/sample_compare.py`). `python3 -m vulnflow compare-sample` analyzes the Compare sample's
seven sites into an upload page's data folder and compares them. All sample data is fabricated. See
[samples/README.md](samples/README.md). Use `samples/` and `example_output/` for interface testing
only. Tests check that each generated sample matches its checked-in folder byte for byte.

## Benchmarks

`scripts/bench/` generates synthetic Zeek + Palo Alto log sets of a target size and measures time
and peak memory for the pipeline, uploads and folder runs. Run one benchmark at a time. See
[scripts/bench/README.md](scripts/bench/README.md) and the results in
[RESULTS_DUCKDB.md](scripts/bench/RESULTS_DUCKDB.md).

## Docker

```sh
docker compose build                                   # or: docker build -t vulnscope-max .
docker compose run --rm vulnscope analyze /opt/vulnscope/samples/gootloader_seo_poisoning -o /runs/demo
scripts/docker/offline-bundle.sh linux/arm64           # air-gapped bundle; see ARCHITECTURE.md
```

The image must use the same Python as the Zeek base (Debian trixie, Python 3.13), since DuckDB is
a compiled wheel. Both linux/amd64 and linux/arm64 builds are supported.

## Local data that must stay local

Never commit private inputs, credentials, unredacted exports or local branding; `scripts/check_repo.py`
enforces the mechanical part in CI. `.gitignore`
excludes `.env`, `vulnscope-out/`, `vulnflow_runs/`, `.vulnscope/` and `branding.json`; keep test
branding in `~/.vulnscope` (or `$VULNSCOPE_HOME`), not in the repository. Never print or log a
configured API key or the Branding password while debugging.
