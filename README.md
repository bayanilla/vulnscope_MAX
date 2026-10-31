# Múcaro VulnScope

The command-line package remains `vulnflow` for existing workflows. VulnScope Explorer is the
interactive network view within Múcaro VulnScope.

Upload network telemetry and Nessus results. The workflow cleans and normalizes them,
works out which vulnerable services are actually reachable and from where, how far a
compromise could spread, and whether traffic already looks like exploitation. It then
writes an **executive summary** and a **technical report** for system owners.

Pure Python 3.10+ standard library. Nothing to install for the core workflow; the optional
AI analyst needs `pip install anthropic` only if you choose Anthropic.

## Quick start

**Want to see the indicators immediately?** The download includes a ready-made, synthetic
250-host demo with 28 exact Múcaro archive matches from five articles on five hosts. Open
`example_output/explorer.html` in your browser, or open
`example_output/executive_summary.html` and `example_output/technical_report.html`.
Click an indicator to see its saved article overview and source link. These pages work as
local files; GitHub's source preview does not run the interactive HTML. AI-generated article
briefs require a user-provided OpenAI key and the separate generation step below.

```bash
# 1. Analyze the bundled 250-host demo with 28 source-linked IOC matches
python3 -m vulnflow analyze samples \
    --article-preview-cache samples/article_previews.json -o example_output

# 2. Run on real data (files or recursively scanned folders, any mix of formats)
python3 -m vulnflow analyze /path/to/log-bundle -o out \
    --internal-net 10.0.0.0/8 --internal-net 172.16.0.0/12

# Optional: add a Múcaro IOC Archive CSV export for source-article links
python3 -m vulnflow analyze /path/to/log-bundle -o out \
    --ioc-archive /path/to/mucaro-60-day-ioc-archive.csv

# 3. Point it at a folder and open the interactive host explorer in your browser
python3 -m vulnflow explore ~/Documents/case-logs            # add --host 10.0.1.10 to open on one host

# 4. Or start the upload page for system owners
python3 -m vulnflow serve --port 8080          # http://127.0.0.1:8080/
```

Run tests with `python3 -m unittest discover -s tests` (no model or network needed).

For the same demo in the upload page, select the `samples` folder under **Analyze files with
Múcaro VulnScope** and click **Analyze folder**. The folder already contains its telemetry, scan,
and Múcaro IOC Archive CSV. See [the sample guide](samples/README.md) for the synthetic scenario.

### Múcaro IOC Archive links

Export the **IOC Archive** as CSV in Múcaro, selecting the 60-day window and the desired filters. Add
that CSV with `--ioc-archive`, include it in an analyzed folder, or upload it with telemetry and a Nessus
scan on the local upload page. VulnScope compares exact IPs in network sessions and IDS/IPS alerts,
CVEs in scan findings, and domains, URLs, hashes, and packages in matching Zeek event fields. Matched
indicators appear in the executive report, technical report, and host Explorer. Click one in the HTML
pages to open its source article links. The links are saved in the standalone output, so the popup
does not depend on Múcaro's feed remaining live. For matched source articles, VulnScope reads the
public page's title and description or lead paragraphs and saves a short overview alongside the
link. This is a source preview, not a Múcaro AI Brief. Use `--no-article-preview` to skip fetching,
or `--article-preview-cache /path/to/previews.json` to reuse saved overviews offline. If a page
cannot be read, its link remains available. An IOC match is a lead for review, not confirmation
of compromise. This import uses a CSV snapshot; automated API retrieval is a separate step.

### Múcaro article AI briefs

On the local upload page, open **AI analyst settings**, choose OpenAI, and enter your model and
OpenAI API key. After analyzing a run with Múcaro archive matches, choose **Generate article briefs
with OpenAI** on its results page. VulnScope reads each unique matched source article, sends its
text through a bundled copy of Múcaro's article prompt and structured output schema, and saves
the resulting brief in `results.json` and the standalone executive, technical, and Explorer HTML
pages. Click a matched indicator to see a concise AI brief, action list, and the full article link.
The whole-report AI analyst brief remains a separate feature. No article is sent until you
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
   - `ai_analyst_brief.md/.html` and `ai_chat_log.md` when the AI analyst is used

## Host explorer

`explorer.html` is written with every run (and opened for you by `vulnflow explore`). It is a single
offline file: no network, no libraries. The overview groups every Nessus-scanned host by /24, coloured by
worst severity. Click a host, or pick it from the list on the left, and the camera flies to it:

- **Left: north/south.** Every outside address in the firewall or Zeek logs that exchanged traffic with
  the host, in either direction, colour-coded as an unblocked IPS alert, a session that reached a
  vulnerable port, a session that reached the host, the host connecting out (violet), or a blocked or
  failed attempt.
- **Right: east/west.** Every internal host it has traffic to or from, including failed attempts (dashed
  grey, "no session"). Hosts with completed sessions carry an estimated likelihood that a compromise of
  the selected host could spread there, plus the next hop beyond them.
- The first 24 on each side are drawn large and labelled; the rest are packed in a block further out
  (hover for details) and all of them are listed in the panel.
- **Panel:** the same lists with session counts, ports and the reasons behind each estimate, plus the
  host's Nessus findings. Click any internal peer to pivot to it; Esc goes back.

Fly-Through flies to the next P1/P2 host on each click (Shift+click goes back); it never moves on its own. L toggles labels, M toggles motion, `/` searches.
Deep links work: `explorer.html#host=10.0.1.10`.

**How the blast-radius likelihood is estimated.** It is a heuristic for triage, not a measurement:
`p = reach x weakness`. Reach is 1.0 when the selected host opened completed sessions to the peer, 0.35
when only the peer connects in, and 0 otherwise. Weakness is the strongest of: a vulnerability on a port
the selected host already uses (CVSS/10, x1.0 with a public exploit, x0.55 without), any other High or
Critical finding (CVSS/10 x0.45 with exploit, x0.25 without), an admin or lateral-movement protocol in
use (0.5), or a 0.1 baseline. Unscanned peers get at least 0.3 because their exposure is unknown. Bands:
High at 0.6 or more, Medium at 0.35 or more, otherwise Low. Two hops out multiplies the two steps. Treat
every line as a lead to check, not as confirmed compromise.

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
It offers Mucaro's SOC Dark, Nord Calm, High Contrast, Light, Classic Windows, Matrix,
Mac OS X Aqua, and Windows 2000 styles. The browser remembers the choice locally.

Uploads are streamed to disk in 64 KB chunks, so memory use stays flat whatever the file size. The default
limit is 1 GB per upload; change it with `serve --max-upload-mb N`.

## AI analyst (optional, vendor-neutral)

An LLM can read the correlated results, write an **analyst brief** (what matters, what to do first,
likely attack paths, how to validate each top finding with example Zeek / Palo Alto filters, where the
scoring may be wrong, questions for system owners), and answer **follow-up questions**. The core
pipeline never depends on it, and **no vendor is preselected**: nothing is sent to any model until the
analyst picks a provider.

| Provider | What it is | Key |
|---|---|---|
| `anthropic` | Claude via the official Anthropic SDK (`pip install anthropic`) | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI's API, or an OpenAI-hosted gateway via `--llm-base-url` | `OPENAI_API_KEY` |
| `local` | Any OpenAI-compatible server you run: Ollama, vLLM, LM Studio, llama.cpp | usually none |

**On the upload page**, open **AI analyst settings** (linked on the upload page and every results page),
pick a provider, enter the model and API key, and save. The key is held in the server's memory only:
it is never written to disk, logged, or shown again (only its last four characters), and it is forgotten
when the server stops. "Turn off AI and forget key" clears it. Each results page then offers
**Generate AI analyst brief** and a chat box for questions.

**From the command line**, choose the provider explicitly. If it needs a key and none is set in the
environment, you are prompted for it without echo (keys are not accepted as command-line arguments, so they
stay out of shell history):

```bash
python3 -m vulnflow analyze samples -o out --llm --llm-provider openai --llm-model <model>
python3 -m vulnflow brief out --llm-provider anthropic                  # model defaults to claude-opus-5-5
python3 -m vulnflow ask out --llm-provider local --llm-model llama3.1  # interactive Q&A, Ollama default URL
python3 -m vulnflow ask out --once "How do I confirm the web01 return connection in Zeek?" --llm-provider openai --llm-model <model>
python3 -m vulnflow serve --redact      # choose provider and key in the browser
```

| Setting | Flag | Environment variable |
|---|---|---|
| Provider (no default) | `--llm-provider anthropic\|openai\|local` | `VULNFLOW_LLM_PROVIDER` |
| Model | `--llm-model` (required for `openai`) | `VULNFLOW_LLM_MODEL` |
| Endpoint | `--llm-base-url` | `VULNFLOW_LLM_BASE_URL` |
| API key | prompted, or the settings page | `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, or `VULNFLOW_LLM_API_KEY` |
| Redact IPs and hostnames | `--redact` or the settings checkbox | `VULNFLOW_LLM_REDACT=1` |

How it is kept honest and safe:

- **Grounded.** The model gets the correlated results (scores, exposure evidence, blast radius,
  indicators, coverage), never raw logs, and must cite host and plugin/CVE for each claim and say when
  the data does not answer a question. A question naming a host, CVE or plugin pulls that finding's full
  record into the prompt. The same prompt is used for every provider.
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
- `--llm-provider mock` is an offline stand-in used by the tests and for demos without a model.

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
