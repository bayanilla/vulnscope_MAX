# Múcaro VulnScope

The command-line package remains `vulnflow` for existing workflows. VulnScope Explorer is the
interactive network view within Múcaro VulnScope.

Upload network telemetry and optional Nessus results. The workflow cleans and normalizes them
and writes an **executive summary** and a **technical report** for system owners. When scan
findings are present, it correlates vulnerable services with observed reachability and
investigation leads.

With network telemetry alone, VulnScope reports observed connections, IPS/IDS alerts and exact IOC
matches. It marks vulnerability status as **unknown** and does not assign CVSS scores or vulnerability
priorities. A scan with no parsed findings is treated the same way. At least one parsed network session
or IPS/IDS alert is required; an empty folder or scan-only input is rejected.

Python 3.10+ with one dependency, [DuckDB](https://duckdb.org): `pip install -r requirements.txt`.
The optional Security Assistant needs `pip install anthropic` only if you choose Anthropic.

### Large inputs

Inputs are streamed, not loaded into memory. Each parser yields records in batches; network
sessions are written to Parquet files partitioned by sensor and day in a temporary working
directory, then sorted, de-duplicated and correlated with DuckDB SQL. Zeek and Palo Alto files
can be plain or `.gz`. The working directory is deleted when the run ends.

- `--workdir DIR` (or `VULNSCOPE_WORKDIR`) puts the temporary Parquet/DuckDB files on a disk with
  room for them; plan for roughly the size of the uncompressed session logs. The upload page uses
  its run folder.
- DuckDB sizes itself to the machine. It gets 60% of the RAM (or of the container's cgroup memory
  limit, when lower), less if the machine is already busy, and never more than a ceiling that keeps
  25% (at least 1.5 GiB) for the OS and the rest of the app. Threads follow the CPUs the process may
  use, one per GiB of DuckDB memory at most. Beyond its memory limit DuckDB spills to the working
  directory, capped at 80% of that disk's free space. Each run prints the values it chose.
- Overrides, all clamped to those safe ceilings: `VULNSCOPE_DUCKDB_MEMORY` (`8GB`, `6GiB`, or `50%`
  of usable RAM), `VULNSCOPE_DUCKDB_THREADS`, `VULNSCOPE_DUCKDB_MAX_TEMP` (`200GB` or `50%` of free
  disk). Roughly, de-duplication needs about 1 GB of DuckDB memory per GB of Zeek logs.
- One analysis runs at a time per process; the upload page refuses a second one with a message
  rather than letting two runs each claim the memory budget. `VULNSCOPE_MAX_JOBS=N` allows N at once
  and splits the budget between them. A run that needs more memory or disk than it was given stops
  with a message saying which limit it hit and how far it can be raised.
- The same session recorded by two sensors (for example Zeek and the firewall) is counted once:
  records with the same 5-tuple whose start times are within `--dedup-skew` seconds (default 2) are
  counted once, keeping the firewall record. Use `--dedup-skew -1` to turn this off.
- Each host's findings are compared with telemetry from `--scan-window-days` (default 7) before
  the host's Nessus scan start to the same number of days after it ends. `0` uses all telemetry;
  findings without a scan time always use all telemetry.

Browse the [screenshot gallery](screenshots/README.md) for the upload workflow, reports, Explorer, and Security Assistant.

## Quick start

**Want to see the indicators immediately?** The download includes a ready-made, synthetic
250-host demo with 28 exact IOC matches from five articles on five hosts. Open
`example_output/explorer.html` in your browser, or open
`example_output/executive_summary.html` and `example_output/technical_report.html`.
Click an indicator to see its saved article overview and source link. These pages work as
local files; GitHub's source preview does not run the interactive HTML. AI-generated article
briefs require a user-provided OpenAI key and the separate generation step below.

**Install once before the first run.** Nothing installs automatically. Run this from the repository
folder, in the same Python you will run VulnScope with. If you use a virtual environment, activate it
first. If you start the upload page with VS Code's Run button on `start_upload_page.py`, use the
interpreter shown in VS Code's status bar. Without this step the tool stops with
`ModuleNotFoundError: No module named 'duckdb'`.

```bash
python3 -m pip install -r requirements.txt     # installs DuckDB
```

```bash
# 1. Analyze the bundled 250-host demo with scan findings and 28 source-linked IOC matches
python3 -m vulnflow analyze samples/scan_and_telemetry \
    --article-preview-cache samples/scan_and_telemetry/article_previews.json -o example_output

# Or analyze the same network traffic without vulnerability scans
python3 -m vulnflow analyze samples/telemetry_only -o telemetry_output

# Or a larger 4,324-host company whose network extends into AWS (scan, firewall, Zeek, VPC Flow Logs)
python3 -m vulnflow analyze samples/hosts_onprem_and_aws -o hosts_output

# 2. Run on real data (files or recursively scanned folders, any mix of formats)
python3 -m vulnflow analyze /path/to/log-bundle -o out \
    --internal-net 10.0.0.0/8 --internal-net 172.16.0.0/12

# Telemetry-only analysis also works without a Nessus file
python3 -m vulnflow analyze /path/to/network-logs -o network-out

# Optional: add a typed IOC CSV, with optional source links
python3 -m vulnflow analyze /path/to/log-bundle -o out \
    --ioc-csv /path/to/indicators.csv

# 3. Point it at a folder and open the interactive host explorer in your browser
python3 -m vulnflow explore ~/Documents/case-logs            # add --host 10.0.1.10 to open on one host

# 4. Or start the upload page for system owners
python3 -m vulnflow serve --port 8080          # http://127.0.0.1:8080/
```

Run tests with `python3 -m unittest discover -s tests` (no model or network needed).

### Upload page security

- The upload page can read any folder your account can, so it listens on `127.0.0.1` only and
  answers only requests addressed to `127.0.0.1`, `localhost` or `[::1]` (this blocks DNS-rebinding
  attacks from websites open in the same browser). Every form and API call needs the page's CSRF token.
- To reach it from another machine, pass `--host 0.0.0.0 --allow-remote`. The server then prints a
  one-time link with a random access token, and every visitor needs that link. Traffic is plain
  HTTP, so prefer an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 host`) on untrusted networks.
- A saved API key is reused only for the same provider and endpoint URL; changing the endpoint
  asks for the key again. Keys are never sent over plain HTTP to another machine.
- Run folders and reports are created readable by your account only. Runs are kept until you
  delete them from the `--data-dir` folder.
- A `.gz` input may expand to at most 200 times its size (minimum 256 MB). Set
  `VULNSCOPE_MAX_GZ_BYTES` to raise the limit for unusually compressible logs.

For the same demo in the upload page, select `samples/scan_and_telemetry` under **Analyze files with
Múcaro VulnScope** and click **Analyze folder**. Select `samples/telemetry_only` to inspect the
network records without a vulnerability scan. The latter includes flow, firewall, NetFlow, Zeek
connection, DNS, notice, and Modbus records from a small synthetic OT segment. Select
`samples/hosts_onprem_and_aws` for a larger 4,324-host estate: an on-prem site plus two AWS VPCs,
with a Nessus scan of every host, Palo Alto and Zeek traffic, and AWS VPC Flow Logs. See
[the sample guide](samples/README.md).

### IOC CSV matches

Add a typed IOC CSV with `--ioc-csv`, include it in an analyzed folder, or upload it with telemetry
on the local upload page. Use `type,indicator` or `indicatorType,indicator` as the column headers;
supported types are `ip`, `domain`, `url`, `hash`, `cve`, and `package`. Optional `source_url` or
`articleUrls` columns add source links. For example:

```csv
type,indicator,source_url
ip,203.0.113.45,https://research.example/report
domain,example.test,
```

VulnScope compares exact IPs in network sessions and IDS/IPS alerts,
CVEs in scan findings, and domains, URLs, hashes, and packages in matching Zeek event fields. Matched
indicators appear in the executive report, technical report, and host Explorer. Click one in the HTML
pages to open its details and any source links. The links are saved in the standalone output. For matched source articles, VulnScope reads the
public page's title and description or lead paragraphs and saves a short overview alongside the
link. This is a source preview, not a Múcaro AI Brief. Use `--no-article-preview` to skip fetching,
or `--article-preview-cache /path/to/previews.json` to reuse saved overviews offline. If a page
cannot be read, its link remains available. An IOC match is a lead for review, not confirmation
of compromise. The legacy `--ioc-archive` flag remains available for existing scripts.

### Cloudflare Radar demo lookups

The local upload server can look up a matched public IPv4 address or domain on demand. Set
`CLOUDFLARE_RADAR_API_TOKEN` in the server's environment before starting `python3 -m vulnflow serve`,
using a Cloudflare custom token with **Account > Radar > Read** permission. Open a served executive
report, technical report, or Explorer, select an IP or domain IOC match, then click **Check Cloudflare
Radar** in its details panel. The server calls Radar; the token is not included in the browser page
or saved output. Opening the standalone HTML file offline does not offer live lookups.

The IP lookup shows ASN and location metadata; the domain lookup shows available popularity rank and
categories. These are context for investigation, not evidence of malicious activity and do not change
VulnScope's scores. The bundled demo indicators are synthetic, so use a real public indicator for a
meaningful live lookup. A Radar Read token does not grant access to Cloudflare's separate URL Scanner
or Threat Intelligence APIs. Confirm Cloudflare's terms for the intended evaluation and deployment.

### Múcaro article AI briefs

On the local upload page, open **Security Assistant settings**, choose OpenAI, and enter your model and
OpenAI API key. After analyzing a run with IOC matches that include source article links, choose **Generate article briefs
with OpenAI** on its results page. VulnScope reads each unique matched source article, sends its
text through a bundled copy of Múcaro's article prompt and structured output schema, and saves
the resulting brief in `results.json` and the standalone executive, technical, and Explorer HTML
pages. Click a matched indicator to see a concise AI brief, action list, and the full article link.
The whole-report Security Assistant brief remains a separate feature. No article is sent until you
explicitly generate its brief. The API key remains in the local server's memory, while generated
briefs stay with the report after the server stops. Unreadable articles retain their original
short overview and source link. A matched IP is a source lead, not proof that a host is compromised.

For an existing command-line output folder, run:

```bash
python3 -m vulnflow article-briefs out --llm-provider openai --llm-model gpt-4.1-mini
```

The command prompts for the API key in a terminal if it is not in `OPENAI_API_KEY`.
Article briefs need exact IOCs from source text, so IP/hostname redaction must be off for this action.

See [the synthetic Múcaro sample](samples/README.md) for the repeatable 250-host case with
source-linked indicators.

## Supported inputs (auto-detected)

| Kind | Format | Notes |
|---|---|---|
| Telemetry | Zeek `conn.log` (TSV or JSON) | `conn_state` decides completed vs. rejected sessions. |
| Alerts | Zeek `notice.log` (TSV or JSON) | Notices become IPS/IDS alerts used as exploitation evidence. |
| Context | Other Zeek streams (TSV or JSON, including `.log.gz`) | `#path` identifies TSV streams; JSON uses `_path` or the filename. DNS, HTTP, SMTP, files, custom streams and others are preserved in `normalized/zeek_events.jsonl` with typed TSV fields and per-stream counts. They do not create extra connection sessions. |
| Industrial telemetry | Zeek Modbus, DNP3, BACnet, S7, EtherNet/IP, CIP, OPC UA logs | Core Zeek logs and installed Zeek package streams are preserved in `normalized/ot_events.jsonl` with protocol, operation, source/destination and direction when available. Observed operations do not become threat alerts automatically. |
| Telemetry + alerts | Palo Alto TRAFFIC and THREAT logs | Web UI / Panorama CSV export (header row) or raw syslog CSV in PAN-OS field order. THREAT rows become alerts; blocked/reset ones count as mitigation, not evidence. Zones `untrust/outside/internet/external/wan` count as external. Timestamps are assumed UTC. |
| Telemetry + alerts | Suricata EVE JSON | `flow` events become sessions, `alert` events become alerts. |
| Telemetry | Generic flow CSV / TSV / space-delimited | nfdump CSV, AWS VPC flow logs, SIEM exports. Columns are matched by common names (`src_ip`, `sa`, `srcaddr`, ...). |
| Scan | Nessus `.nessus` (v2 XML) | Preferred: carries exploit availability and Metasploit flags. |
| Scan | Nessus CSV export | One row per CVE is merged per host/port/plugin. |

### Optional network map (on-prem vs. cloud)

To tell cloud hosts such as AWS VPCs apart from on-prem ones, add a `network_map.csv` to the input
folder (or pass `--network-map FILE`). It is optional: without it nothing changes.

```csv
cidr,name,type
10.40.0.0/16,HQ on-prem,on-prem
10.60.0.0/16,AWS prod (us-east-2),aws
```

The most specific range wins. Types `aws`, `azure`, `gcp`, `oci` and `cloud` are drawn as cloud
networks in the Explorer (dashed white ring and label on the subnet, a badge on each host), and a
network filter appears above the host list. The reports add a Networks table and each host's
network. The file is not read as telemetry; a malformed line stops the run with its line number.

Force a format with `--format file.csv=paloalto` if detection guesses wrong.

## Pipeline

1. **Normalize** (`vulnflow/parsers`, `normalize.py`): supported sources become `Flow`, `ThreatEvent`,
   `Finding`, or a stream-specific Zeek/industrial event (`schema.py`). IPs are validated and canonicalized, protocol numbers mapped,
   timestamps converted to UTC, malformed rows dropped and counted, exact duplicate sessions removed,
   and overlapping scan findings merged.
2. **Correlate** (`correlate.py`), for each vulnerability:
   - **Exposure**: completed sessions to the vulnerable port, split by internet vs. internal sources,
     plus blocked and attempted connections. Host-level (port 0) findings use overall host activity.
   - **Blast radius**: graph walk (default 2 hops) over completed internal sessions from the host,
     flagging reachable hosts that themselves have High/Critical findings and use of SMB/RDP/SSH/WinRM/DB ports.
   - **Indicators**, graded in two levels so the reports never overstate them:
     - *Lead* (worth investigating, not proof): a return connection from the host to an outside address
       that reached the vulnerable service, new lateral connections or >20 MB uploads after that contact,
       an unblocked IPS/IDS alert on the vulnerable service, or a flagged host newly connecting to another
       host's vulnerable service (possible spread).
     - *Corroborated*: an unblocked alert on the vulnerable service **and** post-contact behaviour from the
       host itself. Reports call this "likely exploitation" and ask for incident response and host
       forensics; they never state a compromise as confirmed, because network logs cannot prove one.
       Without THREAT/notice/EVE alerts, nothing gets past "lead".
   - **Score** = `CVSS x 10 x Exploit x Exposure x BlastRadius` (x1.25 corroborated, x1.1 leads), capped at 100,
     mapped to P1 (act now) through P4 (routine). Every score carries a plain-English rationale.
   - **Coverage**: scanned hosts never seen on the wire, and active servers that were never scanned.
3. **Report** (`report.py`): writes to the output folder:
   - `executive_summary.md/.html` for leadership
   - `technical_report.md/.html` for system owners and admins (data quality, method, per-host evidence, remediation)
   - `correlated_findings.csv` for ticketing, `results.json` for automation
   - `hostile_activity.svg`, the hostile activity diagram as a standalone image

   The HTML reports add a visual layer on top of the Markdown: priority badges and evidence tags
   ("Likely exploitation" vs "Lead, not confirmed"), number tiles and a priority bar, the hostile activity
   diagram (ported from vulnPath: outside sources, the vulnerable services they hit, return connections and
   new lateral paths), a sortable and filterable findings table linked to the diagram (click a host or a row
   to focus), a written-out score breakdown per finding, and a blast-radius map per host. Everything is
   inline SVG, CSS and a little JavaScript, follows the selected theme, and prints cleanly.
   - `normalized/flows.csv`, `normalized/findings.csv`, `normalized/zeek_events.jsonl`,
     `normalized/ot_events.jsonl` for cleaned inputs and preserved Zeek stream records
   - `ai_analyst_brief.md/.html` and `ai_chat_log.md` when the Security Assistant is used

## Host explorer

`explorer.html` is written with every run (and opened for you by `vulnflow explore`). It is a single
offline file: no network access; its one library, three.js, is bundled inside it. With a scan, the overview groups scored hosts by /24 and colours
them by worst severity. Without a scan, it groups observed internal hosts and marks vulnerability status
unknown. Click a host, or pick it from the list on the left, and the camera flies to it:

- **Left: north/south.** Every outside address in the firewall or Zeek logs that exchanged traffic with
  the host, in either direction, colour-coded as an unblocked IPS alert, a session that reached a
  vulnerable port, a session that reached the host, the host connecting out (violet), or a blocked or
  failed attempt.
- **Right: east/west.** Every internal host it has traffic to or from, including failed attempts (dashed
  grey, "no session"). Hosts with completed sessions carry an estimated likelihood that a compromise of
  the selected host could spread there, plus the next hop beyond them.
- The first 24 on each side are drawn large and labelled; up to 400 per side are drawn in the graph.
  The panel can reach every recorded IP, including addresses beyond the graph's drawing limit.
- **Panel:** total counts and eight preview rows per side. Search or sort the complete outside and
  internal IP lists; **Show all** opens pages of 20. Expand an IP row for session counts, reasons,
  and up to six distinct recorded connection tuples per
  direction: source/originator IP and port → destination/responder IP and port, transport protocol,
  and application label when the log provides one. `?` means a port was not logged. Industrial Zeek
  records show their operation and message side separately; they are not extra sessions. Scan-backed
  runs also show the reasons behind each estimate and the host's Nessus findings. Use **Focus** in an
  internal peer's details to pivot to that host; Esc goes back.

The selected-host panel stays to the right of the chart on desktop and intermediate widths. On
phone-sized screens (520px or narrower), it moves below the chart to keep the details readable.

Use the host list or `/` to find a host. L toggles labels and M toggles motion.
The **?** at the right end of the top buttons opens a short note on what the current view shows (Flat, 3D, a
selected host, or Attack paths). It opens by itself for 20 seconds when the page loads or the view
changes, then folds back into the ?; click it or press ? to open or close it again.

**3D view.** Where the browser supports WebGL, the Explorer opens in a 3D view built with three.js.
In the overview each subnet is a platform on one plane and each host is a pillar whose height is its
risk score (outside exposure without a scan). Traffic between subnets is bundled beneath the plane, only
risky host paths are drawn (admin protocols, or completed sessions into P1 and flagged hosts), and the
most significant outside addresses sit on an arc overhead with beams to the hosts they reached. Subnet
totals count every host, including any beyond the drawing limit. The overview opens on the Low view and
turns slowly to the left; the turn stops as soon as you move the camera, pick a view or open a host, and
**Reset** (R) or **Spin** starts it again (it never runs with **Motion** off). Drag (or swipe sideways on
a trackpad) to pan, right-drag or Shift-drag to rotate and tilt, scroll or pinch to zoom, and use the
rotate / Top / Tilted / Low / Reset buttons (Q, E, T, Y, U, R) for set views. Hover a subnet for its
totals and click it to zoom in. **Flat** (or the 2 key) switches to the flat view, and that choice is
remembered; `explorer.html?2d` always opens flat. Drawing is capped at
2,000 hosts, 200 risky paths and 48 outside addresses, so very large log sets stay smooth; **Motion**
turns the animated traffic off.
Deep links work: `explorer.html#host=10.0.1.10`.

**Timeline view.** **Timeline** in the view switcher (or the I key, or `explorer.html#timeline`) draws the
same traffic as a tunnel through time: time runs left to right, each subnet is a lane around the wall and
the internet is the band on top, and every flow is a chord at the moment it happened. That shows the order
of events: first contact, an IPS alert (a ring around the tunnel), the callback out, IOC domain lookups (pink
dots) and anything that repeats on a schedule. Pink chords touch an alert or IOC address, cyan come in from
the internet, violet go out to it, orange go straight between subnets, and grey were blocked. The side panel
lights up a 6, 12 or 24 hour window (shorter for short captures) and lists its counts and events; click an
event or ring to open that host. Up to 20,000 flows are drawn. Larger runs keep every blocked flow and every
flow to or from an alert or IOC address (up to half of that) and fill the rest with a fixed random sample,
and the view says so. The camera behaves like the 3D view: drag to rotate, right-drag or Shift-drag to pan,
scroll to zoom, and the slow turn stops as soon as you move it. Esc goes back.
See the [Explorer Security Assistant screenshot](screenshots/security_assistant.jpg).

**How the blast-radius likelihood is estimated.** It is a heuristic for triage, not a measurement:
`p = reach x weakness`. Reach is 1.0 when the selected host opened completed sessions to the peer, 0.35
when only the peer connects in, and 0 otherwise. Weakness is the strongest of: a vulnerability on a port
the selected host already uses (CVSS/10, x1.0 with a public exploit, x0.55 without), any other High or
Critical finding (CVSS/10 x0.45 with exploit, x0.25 without), an admin or lateral-movement protocol in
use (0.5), or a 0.1 baseline. Unscanned peers get at least 0.3 because their exposure is unknown. Bands:
High at 0.6 or more, Medium at 0.35 or more, otherwise Low. For possible onward connections, the estimate
multiplies the two steps. Treat every line as a lead to check, not as confirmed compromise.

## Upload page

**Analyze a folder in place.** The top of the page takes a folder path on the computer running the server
(for example `~/Documents/case-logs`). Every file in it and its subfolders is read where it sits, with
nothing copied or uploaded; hidden files are skipped. From the command line the same thing is
`python3 -m vulnflow analyze ~/Documents/case-logs -o report`. **Browse...** next to the path opens the Mac's own Choose Folder
dialog (on other systems, a folder list in the page), so nobody has to type the path.

`python3 -m vulnflow serve` serves a page with a folder picker, optional separate telemetry and scan files, and an
optional internal-networks box. Each run gets a random ID under `vulnflow_runs/<id>/` with its inputs
and reports. It binds to 127.0.0.1 by default and has no authentication, so put it behind your SSO
proxy before exposing it to other users.

The upload page, AI settings, results page, and newly generated HTML reports share a theme picker.
It offers SOC Dark, Olive Drab, Matrix, High Contrast, and Light. The browser remembers
the choice locally. The standalone reports embed the matching signal, map, or soft-gradient
background treatment, so they work offline. High Contrast uses a plain black background.

Uploads are streamed to disk in 64 KB chunks, so memory use stays flat whatever the file size. The default
limit is 1 GB per upload; change it with `serve --max-upload-mb N`.

## Security Assistant (built-in offline, or any AI provider)

Out of the box the Security Assistant runs **offline**: the built-in assistant ("Built-in (offline, no AI)")
answers questions and writes the brief from the run's own results with fixed rules, so it needs no model,
no key and no network (details below). Optionally, an LLM can read the correlated results, write an **analyst brief** (what matters, what to do first,
likely attack paths, how to validate each top finding with example Zeek / Palo Alto filters, where the
scoring may be wrong, questions for system owners), and answer **follow-up questions**. The core
pipeline never depends on it, and **no AI vendor is preselected**: nothing is sent to any model until the
analyst picks a provider.

| Provider | What it is | Key |
|---|---|---|
| `offline` (default) | Built-in assistant: rules and templates over the results, no AI model, nothing sent | none |
| `anthropic` | Claude via the official Anthropic SDK (`pip install anthropic`) | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI's API, or an OpenAI-hosted gateway via `--llm-base-url` | `OPENAI_API_KEY` |
| `local` | Any OpenAI-compatible server you run: Ollama, vLLM, LM Studio, llama.cpp | usually none |

**On the upload page**, open **Security Assistant settings** (linked on the upload page and every results page),
pick a provider, enter the model and API key, and save. The key is held in the server's memory only:
it is never written to disk, logged, or shown again (only its last four characters), and it is forgotten
when the server stops. "Use the built-in assistant and forget key" clears it and goes back to offline. Each results page then offers
**Generate Security Assistant brief** and a chat box for questions.

**From the command line**, the built-in offline assistant is used unless you choose a provider. If it needs a key and none is set in the
environment, you are prompted for it without echo (keys are not accepted as command-line arguments, so they
stay out of shell history):

```bash
python3 -m vulnflow analyze samples/scan_and_telemetry -o out --llm --llm-provider openai --llm-model <model>
python3 -m vulnflow brief out --llm-provider anthropic                  # model defaults to claude-opus-5-5
python3 -m vulnflow ask out --llm-provider local --llm-model llama3.1  # interactive Q&A, Ollama default URL
python3 -m vulnflow ask out --once "How do I confirm the web01 return connection in Zeek?" --llm-provider openai --llm-model <model>
python3 -m vulnflow serve --redact      # choose provider and key in the browser
```

| Setting | Flag | Environment variable |
|---|---|---|
| Provider (default `offline`) | `--llm-provider offline\|anthropic\|openai\|local` | `VULNFLOW_LLM_PROVIDER` |
| Model | `--llm-model` (required for `openai`) | `VULNFLOW_LLM_MODEL` |
| Endpoint | `--llm-base-url` | `VULNFLOW_LLM_BASE_URL` |
| API key | prompted, or the settings page | `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, or `VULNFLOW_LLM_API_KEY` |
| Redact IPs and hostnames | `--redact` or the settings checkbox | `VULNFLOW_LLM_REDACT=1` |

How it is kept honest and safe:

- **Grounded.** The model gets the correlated results (scores, exposure evidence, blast radius,
  indicators, coverage), never raw logs, and must cite host and plugin/CVE for each claim and say when
  the data does not answer a question. The local provider starts with the summary and top ten findings
  to fit smaller models; a question naming a host, CVE or plugin adds matching finding details. Hosted
  providers keep the broader context. The instructions are the same for every provider.
- **Untrusted data.** Hostnames, application names and plugin output can be attacker-influenced. They are
  wrapped as data, the model is told never to follow instructions inside them, it has no tools, and its
  output is HTML-escaped on the page.
- **Data handling.** With a hosted provider, results leave your network for that vendor. `--redact` swaps
  every IP and hostname for a token everywhere in the text, including free-text fields such as Nessus
  synopsis and plugin output (IPv4, IPv6, internal FQDNs and scanned short names; public reference sites
  such as vendor advisories stay readable). Before anything is sent, the outgoing text is checked again and
  the request is refused if any address or known hostname survived. Answers are mapped back locally; `local` keeps everything on your
  hardware. The results page states where data goes.
- **Browser safety.** Settings and brief forms carry a per-server token and cross-origin posts are refused,
  so another website open in the same browser cannot change the provider or read results through it.
- **Audit trail.** Every question and answer is appended to `ai_chat_log.md` in the run folder.
- **Provider details.** Anthropic: results sit in a cached system prompt so follow-ups are cheap, and
  `fallbacks: "default"` retries a request a safety classifier declines on Anthropic's recommended fallback
  model. OpenAI: uses `max_completion_tokens` and default temperature so reasoning models work. Refusals or
  content filtering from any provider come back as a clear error.
- **Built-in offline assistant (default).** With no provider chosen, the Security Assistant still works:
  `offline` (shown as "Built-in (offline, no AI)") explains a run from its own results with fixed rules and
  templates, so nothing is sent anywhere and no key is needed. Ask about a host (IP or name), CVE, plugin ID,
  outside IP or IOC value, or about priorities, internet exposure, outbound callbacks, lateral movement and
  attack paths, IOC matches, coverage gaps and scoring; it also writes the brief. Answers include ready-to-paste
  Zeek and Palo Alto filters. It can't reason beyond the data, so pick a model for open-ended questions.
  `--llm-provider mock` still works as an older name for it.

## Tuning

- `--internal-net CIDR` (repeatable): what counts as "inside". Default is RFC1918, CGNAT, loopback, link-local, ULA.
- `--hops N`: blast-radius depth.
- `--min-severity 0-4`: lowest Nessus severity to score (default 1, Low).
- Weights live at the top of `correlate.py` (`LATERAL_PORTS`, `EXTERNAL_ZONES`, `EXFIL_BYTES`, `BROAD_REACH`).

## Known limits

- Hosts are joined by IP. Scans run by hostname only, or DHCP churn during the telemetry window, reduce matches; NAT'd
  firewall logs should be exported with pre-NAT addresses.
- Industrial protocol support reads exported Zeek logs, including logs produced by installed ICS analyzers.
  Raw packet captures and vendor-specific historian/PLC exports need an upstream decoder or a source-specific parser.
  Zeek events outside `conn` and `notice`, including OT operations, are preserved as context and counted but do not
  affect vulnerability scores yet.
- Absence of traffic means "not observed by these sensors", which is why unseen hosts are scored as unknown rather than safe.
- "Likely exploitation" still needs confirmation on the host (EDR, memory, logs). Treat the output as a
  way to prioritise investigation, not as a final verdict.
- Natural next steps: use Zeek `dns.log` for hostname-to-IP mapping, file evidence from `files.log`,
  and a Splunk/Elastic export target.

## License

MIT. See [LICENSE](LICENSE). The Múcaro browser tab icon retains its original
MIT attribution in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
