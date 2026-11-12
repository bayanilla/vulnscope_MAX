# Múcaro VulnScope

**Network telemetry and vulnerability scans, correlated into reports for system owners.**

VulnScope reads network telemetry (Zeek, Palo Alto, Suricata, flow exports, packet captures)
and optional Nessus results, then writes an **executive summary**, a **technical report** and an
interactive **Explorer** of the hosts involved. When scan findings are present, it correlates
vulnerable services with observed reachability and investigation leads. With telemetry alone, it
reports observed connections, IPS/IDS alerts and exact IOC matches, and marks vulnerability status
as **unknown**.

**Proof of concept.** VulnScope is a local investigation aid for analysts. It reads files you
already have; it never scans, probes or contacts the hosts and addresses in your data. Scores and
indicators come from fixed, documented rules. An AI model is used only if you choose one for the
optional Security Assistant or article briefs. Reports prioritize investigation; they do not
confirm a compromise, establish exposure on their own, or replace host forensics.

The command-line package is `vulnflow`. VulnScope Explorer is the interactive network view.
This repository (MAX) is the scaled version for multi-GB inputs; it streams parsers into Parquet
and correlates with DuckDB.

## Contents

- [Start VulnScope](#start-vulnscope)
- [Analyze your logs and scans](#analyze-your-logs-and-scans)
- [Explore hosts](#explore-hosts)
- [Ask the Security Assistant](#ask-the-security-assistant)
- [Interpret and validate the report](#interpret-and-validate-the-report)
- [Save and share results](#save-and-share-results)
- [Compare reports](#compare-reports)
- [Branding and themes](#branding-and-themes)
- [Privacy and practical limits](#privacy-and-practical-limits)
- [Further documentation](#further-documentation)

## Start VulnScope

### With Docker (Linux, macOS, Windows, air-gapped networks)

One image holds VulnScope, DuckDB and [Zeek](https://zeek.org) for linux/amd64 and linux/arm64
(Intel/AMD PCs, servers and Apple silicon Macs), so packet captures work out of the box. You need
Docker Desktop on macOS and Windows, or Docker Engine with the Compose plugin on Linux.

```sh
git clone https://github.com/bayanilla/vulnscope_max.git
cd vulnscope_max
cp .env.example .env          # optional: set VULNSCOPE_DATA, VULNSCOPE_RUNS, port, memory
docker compose up -d          # builds once, then starts the upload page
```

Open **http://127.0.0.1:8080/**. Results go to `VULNSCOPE_RUNS` (default `./vulnscope-out`).
Stop it with `docker compose down`. For enclaves with no internet, build an offline bundle on a
connected computer and load it on the other side; see
[Air-gapped networks](ARCHITECTURE.md#air-gapped-networks-and-enclaves).

### With Python

With Python 3.10 or later, install the one dependency, [DuckDB](https://duckdb.org), in the same
Python you will run VulnScope with (activate your virtual environment first, or use the interpreter
in VS Code's status bar):

```sh
python3 -m pip install -r requirements.txt
python3 -m vulnflow serve            # upload page on http://127.0.0.1:8080/
```

`start_upload_page.py` does the same from VS Code's Run button and opens the browser. Without the
install step VulnScope stops with `ModuleNotFoundError: No module named 'duckdb'`. Packet captures
also need Zeek (`brew install zeek`, a Linux package, or `VULNSCOPE_ZEEK=/path/to/zeek`).

### Try it without your own data

`example_output/` holds a finished synthetic 250-host run: open `explorer.html`,
`executive_summary.html` or `technical_report.html` in your browser. Four bundled samples can be
analyzed from the upload page (select the folder, then **Analyze folder**) or the command line:

```sh
python3 -m vulnflow analyze samples/scan_and_telemetry \
    --article-preview-cache samples/scan_and_telemetry/article_previews.json -o example_output
python3 -m vulnflow analyze samples/telemetry_only -o telemetry_output        # no scan, includes OT
python3 -m vulnflow analyze samples/hosts_onprem_and_aws -o hosts_output       # 4,324 hosts, on-prem + AWS
python3 -m vulnflow analyze samples/gootloader_seo_poisoning -o gootloader_output
```

All sample data is fabricated. See [the sample guide](samples/README.md) and the
[screenshot gallery](screenshots/README.md). Already using vulnScope PRO? Read
[the upgrade notes](UPGRADE.md).

## Analyze your logs and scans

1. On the upload page, enter a folder path on the computer running the server, or click
   **Browse…**, then **Analyze folder**. Every file in it and its subfolders is read where it sits;
   nothing is copied. Formats are detected by content, so any mix of files works. You can instead
   upload telemetry and scan files under **Analyze files** (up to 1 GB per upload by default).
2. Optionally list your internal networks. The default is RFC 1918, CGNAT, loopback, link-local and
   ULA ranges.
3. Optionally open **Report details** to give the run a name, the **network** or site the data
   comes from, and a description. They appear at the top of the reports and in the Explorer, the
   run folder is named after the report, and [Compare reports](#compare-reports) counts reports with
   the same network as one network.
4. While the run works, the page shows your logo (or the Múcaro mark) turning slowly with an
   elapsed timer. One analysis runs at a time; a second is refused with a message.
5. The results page links the reports, the Explorer and the Security Assistant.

From the command line the same run is:

```sh
python3 -m vulnflow analyze /path/to/case -o out --internal-net 10.0.0.0/8
python3 -m vulnflow analyze /path/to/case -o out --name "Plant 3 November" --network-name "Plant 3"
python3 -m vulnflow explore ~/Documents/case-logs        # analyze and open the Explorer
```

**Browse.** On a Mac running natively, **Browse…** opens the system's Choose Folder dialog. In
Docker, Compose shares your home folder **read-only** and Browse walks it like a file picker
(`/Users/you` on macOS, `/home/you` on Linux, `/host` for `C:\Users\you` on Windows; pasted
Windows paths are translated). Picking a folder fills in the path and moves focus to
**Analyze folder**. A **/data** button switches to the `VULNSCOPE_DATA` folder. To share an
evidence drive instead, or only one inbox folder for locked-down sites, set `VULNSCOPE_BROWSE` in
`.env`; see [Docker folders](ARCHITECTURE.md#docker-container).

**What it reads.** Zeek logs (TSV or JSON), Palo Alto TRAFFIC/THREAT, Suricata EVE, generic flow
CSVs (nfdump, AWS VPC Flow Logs, SIEM exports), Nessus `.nessus` or CSV, and:

- **Packet captures.** `.pcap`/`.pcapng` files, plain or `.gz`, are run through Zeek into a
  temporary folder, analyzed as Zeek logs, then deleted. Each capture is listed in the input table
  with the Zeek version and logs produced; a capture Zeek can't read is reported and the run
  continues.
- **Zeek logs shipped by Filebeat.** A Kibana Discover CSV or NDJSON export of Filebeat's Zeek
  module is turned back into Zeek records, reversing the ECS field renames. To get clean Zeek logs
  for another tool: `python3 -m vulnflow filebeat-to-zeek kibana_export.csv -o zeek_logs/`.
- **IOC CSV.** A typed `type,indicator[,source_url]` file (`ip`, `domain`, `url`, `hash`, `cve`,
  `package`) in the folder, uploaded, or passed with `--ioc-csv`. Exact matches are reported.
- **Network map.** An optional `network_map.csv` (`cidr,name,type`) marks cloud networks such as
  AWS VPCs. Without it nothing changes.

[Methods](METHODS.md#inputs-and-normalization) lists every format, how it is detected, and what
each source can and cannot contribute. Force a format with `--format file.csv=paloalto` if
detection guesses wrong.

**Large inputs.** Inputs are streamed, written to Parquet by sensor and day, and de-duplicated
with DuckDB. DuckDB sizes its memory and threads to the machine and spills to disk beyond that;
plan for free disk of about the size of the uncompressed logs. `--workdir` (or
`VULNSCOPE_WORKDIR`) moves the temporary files. See
[Large inputs](ARCHITECTURE.md#large-inputs-and-resource-sizing) for sizing and overrides.

## Explore hosts

`explorer.html` is written with every run. It is a single offline file with three.js bundled
inside. The view switcher offers:

- **3D** (default where WebGL works). Each subnet is a platform and each host a pillar whose
  height is its risk score (outside exposure without a scan). Risky paths and the most significant
  outside addresses, on an arc overhead, are drawn. It opens on the Low view, turning slowly left.
  Drag to rotate, right-drag or Shift-drag to pan, scroll to zoom.
- **Flat** (or the 2 key, remembered; `explorer.html?2d` always opens flat).
- **Attack paths**, the most likely ways in drawn like a transit map (internet origin, entry,
  first and second pivot). **Simulate fix** is a what-if that shows how much path risk fixing or
  isolating one host would remove; nothing on the network changes.
- **Timeline** (I key, or `explorer.html#timeline`), a tunnel through time where every flow is a
  chord at the moment it happened, with alerts as rings and IOC lookups as pink dots.

Click a host, or pick it from the host list (grouped by subnet, riskiest first; **By subnet**
switches to a flat list), and the camera flies to it. The left side shows outside addresses that
exchanged traffic with it; the right side shows internal peers with an estimated likelihood that
a compromise could spread there. The panel lists every recorded IP with session counts and
connection tuples. **Focus** pivots to a peer; Esc or **← All hosts** goes back. The **?** at the
right of the top buttons explains the current view. Deep links work:
`explorer.html#host=10.0.1.10`.

Drawing limits keep large runs responsive; [Methods](METHODS.md#explorer-drawing-and-sampling)
explains what is drawn and how the likelihood is estimated.

## Ask the Security Assistant

Out of the box the Security Assistant is **Built-in (offline, no AI)**: it answers questions and
writes a brief from the run's own results with fixed rules and templates, and sends nothing
anywhere. Ask about a host, CVE, plugin, outside IP or IOC, or about priorities, callbacks, lateral
movement and coverage gaps; answers include ready-to-paste Zeek and Palo Alto filters.

To use a model instead, open **Security Assistant settings** and pick a provider:

| Provider | What it is | Key |
| --- | --- | --- |
| `offline` (default) | Built-in rules and templates, no AI model, nothing sent | none |
| `anthropic` | Claude via the Anthropic SDK (`pip install anthropic`) | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI's API or an OpenAI-hosted gateway | `OPENAI_API_KEY` |
| `local` | Any OpenAI-compatible server you run (Ollama, vLLM, LM Studio, llama.cpp) | usually none |

No vendor is preselected. With a hosted provider, correlated results (not raw logs) leave your
network; **Redact IPs and hostnames** replaces them with tokens and refuses to send if any survive.
The same commands work from the terminal (`brief`, `ask`, `analyze --llm`); see
[Methods](METHODS.md#security-assistant) for flags and safeguards.

**Article briefs.** When IOC matches carry source article links and you have chosen OpenAI,
**Generate article briefs with OpenAI** on the results page summarizes each article with Múcaro's
article prompt. Nothing is sent until you click it.

## Interpret and validate the report

Treat the report as a list of precise questions for system owners and responders:

> These hosts have these findings, and these sessions reached the vulnerable services in this
> window. Is that exposure intended? Did the host do anything afterwards that we can confirm on
> the host itself?

Every scored finding carries a priority (P1 act now to P4 routine) and a plain-English rationale
built from CVSS, exploit availability, observed exposure and blast radius. Indicators are graded
so the reports never overstate them:

- **Lead, not confirmed.** Worth investigating: a return connection to an outside address that
  reached the vulnerable service, new lateral connections or large uploads afterwards, or an
  unblocked IPS/IDS alert.
- **Likely exploitation.** An unblocked alert on the vulnerable service **and** follow-on behavior
  from the host. Reports ask for incident response and host forensics; they never state a
  compromise as confirmed.

**Worked example:** analyze the bundled Gootloader sample and open `hr-ws-07` (10.20.10.27) in the
Explorer. Follow its download, the beacon to an outside address and the SMB and RDP sessions to
the domain controllers in the Timeline. Give the
host owner the finding, the session tuples and times, and the suggested Zeek or Palo Alto filter.
They can confirm on the host (EDR, memory, logs) whether the activity happened and whether the
service should be reachable.

Absence of traffic means "not observed by these sensors". Scanned hosts never seen on the wire,
and active servers never scanned, are listed as coverage gaps rather than scored as safe. An IOC
match is a lead for review, not proof of compromise.

## Save and share results

Each run writes to its output folder (`vulnflow_runs/<id>/out/` on the upload page):

- **Executive summary** and **technical report**, as Markdown and standalone HTML.
- **Explorer**: `explorer.html`, a single offline file.
- **CSV and JSON:** `correlated_findings.csv` for ticketing; `results.json` for automation.
- **Normalized inputs:** `normalized/flows.csv`, `findings.csv`, `threats.csv` (IPS/IDS alerts),
  `zeek_events.jsonl`, `ot_events.jsonl`. [Compare reports](#compare-reports) searches them again.
- **Hostile activity diagram** as `hostile_activity.svg`.
- **Security Assistant** brief and an audit log of every question and answer (`ai_chat_log.md`),
  when used.
- **Print or save PDF** from your browser; the HTML reports print cleanly.

The HTML files work offline and embed the branding, theme, matched IOC source links and any
article overviews they were made with. Live lookups such as Cloudflare Radar are offered only when
the page is served by the upload page. Runs are kept until you delete them from the data folder.

**Reopen a saved report:** on the upload page, choose a completed report's output folder (the one
with `results.json` and `explorer.html`). The button changes to **Open report**; the summaries,
technical report, Explorer and Timeline are redrawn with the current version and branding, the
raw-data files are served from that folder, and nothing is reanalyzed or changed. `results.json`
alone keeps the report data but not the traffic the Explorer is drawn from, so keep
`explorer.html` with it. A `results.json` written by a newer VulnScope is refused.

## Compare reports

**Compare reports** (linked from the upload page and every results page) shows which IOCs and
vulnerabilities appear in more than one saved report, and in how many networks.

1. Tick the reports to compare. The list holds every run saved by this upload page, newest first.
   To include a report saved somewhere else, open it on the upload page first (**Open report**).
2. Check each report's **Network**. It comes from Report details; change it here for this
   comparison if needed (your browser remembers the change). Reports with the same network count
   as one network.
3. Leave **Look for every IOC matched in any chosen report in all of them** ticked, and optionally
   add an IOC CSV, to search each report's saved data again: an indicator learned after a report
   was made, or matched in only one report, is found in the others too.
4. Click **Compare**. The comparison has IOC, Vulnerability and Report tabs. Each row shows how
   many reports, networks and hosts it was seen in, and one square per report, oldest first:
   filled when the analysis found it, striped when only the new search did. Click a row for the
   hosts in each report.

Comparisons are saved in the data folder under `comparisons/<time>/` with `ioc_overlap.csv`,
`vulnerability_overlap.csv` (one row per item and report) and `comparison.json`, and are listed
under **Earlier comparisons**. The reports themselves are not changed. From the command line:

```sh
python3 -m vulnflow compare vulnflow_runs/ -o compare_out --ioc-csv new_iocs.csv
python3 -m vulnflow compare nov/out dec/out --network "dec/out=Plant 3"   # set a report's network
```

Vulnerabilities are matched by Nessus plugin and IOCs by indicator, never by internal address,
since the same private address in two networks is two different machines. A report and its
reopened copy count once. Reports made before this version didn't save their IPS/IDS alerts, so
an IP seen only in an alert isn't found again in them; the comparison says so. See
[Comparing reports](METHODS.md#comparing-reports) for the rules.

## Branding and themes

**Branding** (linked from the upload page) replaces the name before "VulnScope" and adds a small
PNG, JPEG, GIF or WebP logo (up to 512 KB; SVG is refused) at Small or Medium size. The upload
page, command line, reports and Explorer all use it, and the logo turns during Analyze. Branding is
saved per user in `~/.vulnscope/branding.json` (or `$VULNSCOPE_HOME`; in Docker, inside the runs
folder). It is password protected; set a different password with
`python3 -m vulnflow branding-password` and the `VULNSCOPE_BRANDING_PASSWORD_HASH` it prints.
Branding is local to your computer and is never part of the repository.

The upload page, settings, results and reports share a theme picker: SOC Dark, Olive Drab, Matrix,
High Contrast and Light. The browser remembers the choice.

## Privacy and practical limits

| Consideration | What to expect |
| --- | --- |
| Target contact | VulnScope never scans, probes or resolves hosts, IPs or domains found in your data. Zeek reads captures offline. |
| Outbound connections | Only four, each tied to a feature: IOC **article previews** (fetches matched source article pages, on by default when the IOC CSV has links), **Cloudflare Radar** (only with a token, only when you click), the **Security Assistant** with a hosted or network model, and **article briefs** (OpenAI, only when you click). |
| `VULNSCOPE_OFFLINE=1` | Turns off article previews only. It does not block Radar, a chosen AI provider or article briefs; leave those unconfigured on an air-gapped system. Docker defaults to `0`. |
| Upload page access | No login, and it can read any folder your account (or the container) can. It listens on `127.0.0.1` and refuses other host names. For remote use, see [Upload page security](ARCHITECTURE.md#upload-page-security). |
| API keys | Held in the server's memory only; never written to disk, logs or reports. Cleared when the server stops. |
| Memory and disk | DuckDB takes up to about 60% of RAM (or the container limit) and spills to disk. Roughly 1 GB of DuckDB memory per GB of Zeek logs for de-duplication; free disk of about the uncompressed log size. Docker Desktop's VM memory cap also applies. |
| Input size | 1 GB per upload by default; folders are read in place with no size cap. A `.gz` may expand to 200× its size (minimum 256 MB). |
| Concurrency | One analysis at a time per process unless `VULNSCOPE_MAX_JOBS` is raised. |
| Local retention | Run folders and reports stay on disk, readable by your account only, until you delete them. Temporary Parquet/DuckDB/Zeek files are deleted when the run ends. |
| Deployment | Intended for local use. A shared server needs `--allow-remote` behind your SSO proxy and its own security review. |

Review sensitive inputs before sharing an export. VulnScope does not encrypt reports.
[Configured limits](docs/LIMITS.md) lists every numeric bound.

## Further documentation

- [Methods, inputs, and interpretation limits](METHODS.md): supported formats, correlation and
  scoring, Explorer estimates, outbound network use, and what VulnScope cannot establish.
- [Architecture](ARCHITECTURE.md): pipeline and module responsibilities, large-input design,
  Docker container, offline bundle, and upload page security.
- [Development and verification](DEVELOPMENT.md): tests, benchmarks, Docker builds and samples.
- [Local API](API.md): the upload page's HTTP routes.
- [Upgrading from vulnScope PRO](UPGRADE.md).
- [Configured limits](docs/LIMITS.md): numeric bounds in one table.

## License

MIT. See [LICENSE](LICENSE). The Múcaro browser tab icon retains its original MIT attribution in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
