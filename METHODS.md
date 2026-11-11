# VulnScope methods, inputs, and limits

This reference explains the evidence behind a VulnScope report. It is intended for analysts who
need to judge a result's scope and limitations before acting on it.

## Evidence categories

| Category | VulnScope records | It does not establish |
| --- | --- | --- |
| Network session | A sensor (Zeek, firewall, Suricata, flow export) logged traffic between two addresses, with its time, ports and outcome. | That the traffic was malicious, or that unlogged traffic did not happen. |
| IPS/IDS alert | A Palo Alto THREAT row, Zeek notice or Suricata alert, and whether it was blocked. | That the attack succeeded. Blocked and reset alerts count as mitigation, not evidence. |
| Scan finding | Nessus reported a vulnerability on a host, port and plugin, with CVSS and exploit flags. | That the vulnerability is reachable or was exploited. |
| IOC match | An exact IP, domain, URL, hash, CVE or package from your IOC CSV appeared in the data. | Compromise, attribution, or that the source article is correct. |
| Lead | A pattern worth investigating, such as a return connection after an outside contact. | Exploitation. |
| Likely exploitation | An unblocked alert on the vulnerable service **and** follow-on behavior from the host. | A confirmed compromise. Network logs cannot prove one. |
| Estimate | A score, priority, blast-radius likelihood or attack-path rank computed by fixed rules. | A probability, a measurement, or a verdict. |
| Analyst assessment | A conclusion an analyst draws from this evidence and host-side records. | A conclusion made or endorsed by VulnScope. |

At least one parsed network session or IPS/IDS alert is required; an empty folder or scan-only
input is rejected. With telemetry alone, or a scan with no parsed findings, vulnerability status
is **unknown** and no CVSS scores or vulnerability priorities are assigned.

## Inputs and normalization

Files are recognized by their contents in any folder or upload, recursively; hidden files are
skipped. Zeek and Palo Alto files can be plain or `.gz`.

| Kind | Format | Notes |
| --- | --- | --- |
| Telemetry | Zeek `conn.log` (TSV or JSON) | `conn_state` decides completed vs. failed sessions. `REJ` (the host answered with a reset) is reported as *refused by the host*, not as a firewall block; only firewall/IPS logs report blocks. |
| Alerts | Zeek `notice.log` (TSV or JSON) | Notices become IPS/IDS alerts used as exploitation evidence. |
| Context | Other Zeek streams (TSV or JSON, including `.log.gz`) | `#path` identifies TSV streams; JSON uses `_path` or the filename. DNS, HTTP, SMTP, files, custom streams and others are preserved in `normalized/zeek_events.jsonl` with typed fields and per-stream counts. They do not create extra sessions. |
| Industrial telemetry | Zeek Modbus, DNP3, BACnet, S7, EtherNet/IP, CIP, OPC UA logs | Preserved in `normalized/ot_events.jsonl` with protocol, operation, endpoints and direction when available. Observed operations do not become alerts automatically. |
| Telemetry + alerts | Palo Alto TRAFFIC and THREAT logs | Web UI / Panorama CSV export (header row) or raw syslog CSV in PAN-OS field order. Zones `untrust/outside/internet/external/wan` count as external. Timestamps are assumed UTC. |
| Telemetry + alerts | Suricata EVE JSON | `flow` events become sessions, `alert` events become alerts. |
| Telemetry | Generic flow CSV / TSV / space-delimited | nfdump CSV, AWS VPC Flow Logs, SIEM exports. Columns are matched by common names (`src_ip`, `sa`, `srcaddr`, ...). |
| Telemetry + alerts + context | Zeek logs shipped by Filebeat / Elastic Agent: Kibana Discover CSV or NDJSON (`elasticdump`, `_search` hits, Filebeat file output), plain or `.gz` | Rows with `event.dataset: zeek.*` are turned back into Zeek records; other modules' rows are skipped. See below. |
| Packets | `.pcap` / `.pcapng` (plain or `.gz`) | Converted with Zeek, then read as Zeek logs. See below. |
| Scan | Nessus `.nessus` (v2 XML) | Preferred: carries exploit availability and Metasploit flags. |
| Scan | Nessus CSV export | One row per CVE is merged per host/port/plugin. |

Normalization validates and canonicalizes IPs, maps protocol numbers, converts timestamps to UTC,
drops and counts malformed rows, removes exact duplicate sessions and merges overlapping scan
findings. The technical report's data-quality section lists every input, its detected format and
its counts.

**Cross-sensor de-duplication.** The same session recorded by two sensors (for example Zeek and the
firewall) is counted once: records with the same 5-tuple whose start times are within
`--dedup-skew` seconds (default 2) are merged, keeping the firewall record. The same applies to two
sensors of the same kind in different files (for example two Zeek taps that both see a session):
records with the same 5-tuple and firewall action are kept once, preferring the record that saw
the completed session (an asymmetric tap may only see the SYN). `--dedup-skew -1`
turns this off.

**Scan window.** Each host's findings are compared with telemetry from `--scan-window-days`
(default 7) before the host's Nessus scan start to the same number of days after it ends. `0` uses
all telemetry; findings without a scan time always use all telemetry.

### Packet captures

VulnScope runs `zeek -C -r <capture> local` on each capture into a temporary folder, analyzes the
`conn`, `dns`, `http` and other logs Zeek writes, then deletes them. Each capture appears in the
input table with the Zeek version and the logs it produced. OT protocols are decoded only when the
matching Zeek analyzers are installed. The Docker image includes Zeek; without it, install Zeek or
set `VULNSCOPE_ZEEK`. You can also convert ahead of time:
`mkdir out && cd out && zeek -C -r ../capture.pcap local`. For captures larger than the upload
limit, use **Analyze folder** or the command line, which read files in place.

### Zeek logs from Filebeat

Filebeat's Zeek module renames each field to ECS (`id.orig_h` → `source.ip`, `uid` →
`zeek.session_id`, `conn_state` → `zeek.connection.state`, `ts` → `@timestamp`, ...) and adds its own
(`agent.*`, `host.*`, geo, `related.ip`, `tags`). VulnScope reverses the renames per log type, using
the rename table from the Filebeat module itself. When a row still holds the raw Zeek line
(`event.original`, which Filebeat keeps for `dns`, `intel`, `ntp` and `signature`, or for every log
with "preserve original event" on), that line is used as is. A plain Filebeat `log`/`filestream`
input on Zeek's JSON logs, where the whole record is one JSON string in the `message` column, is
also read; the log type then comes from `_path`, `log.file.path` or the record's fields.

What cannot come back: Filebeat drops `orig_bytes`, `resp_bytes` and `tunnel_parents` from
conn.log, so byte counts use `orig_ip_bytes`/`resp_ip_bytes` (which include IP/TCP headers), and
`actions` from notice.log. A Kibana CSV keeps the formatting Kibana shows: times to the millisecond
(read as UTC; set Kibana's `dateFormat:tz` to UTC before exporting) and byte fields such as `1.2KB`
rounded. Export NDJSON when exact values matter.

### IOC CSV

Use `type,indicator` or `indicatorType,indicator` as the header; supported types are `ip`,
`domain`, `url`, `hash`, `cve` and `package`. Optional `source_url` or `articleUrls` columns add
source links.

```csv
type,indicator,source_url
ip,203.0.113.45,https://research.example/report
domain,example.test,
```

VulnScope compares exact IPs in sessions and alerts, CVEs in scan findings, and domains, URLs,
hashes and packages in matching Zeek event fields. Matches appear in both reports and the
Explorer. For matched source links, it reads the public page's title and description or lead
paragraphs and saves a short overview (a source preview, not an AI brief); see
[outbound network use](#privacy-and-outbound-network-use). `--no-article-preview` skips fetching;
`--article-preview-cache previews.json` reuses saved overviews offline. The legacy `--ioc-archive`
flag remains available.

### Network map

A `network_map.csv` in the input folder (or `--network-map FILE`) names ranges and marks cloud
networks:

```csv
cidr,name,type
10.40.0.0/16,HQ on-prem,on-prem
10.60.0.0/16,AWS prod (us-east-2),aws
```

The most specific range wins. Types `aws`, `azure`, `gcp`, `oci` and `cloud` are drawn as cloud
networks in the Explorer (dashed ring and label on the subnet, a badge on each host), and a
network filter appears above the host list. Reports add a Networks table and each host's network.
The file is not read as telemetry; a malformed line stops the run with its line number. Without
the file, output is unchanged.

## Correlation and scoring

For each vulnerability:

- **Exposure:** completed sessions to the vulnerable port, split by internet and internal sources,
  plus blocked (firewall/IPS), refused (host reset) and attempted connections. Host-level (port 0) findings use overall host activity.
- **Blast radius:** a graph walk (default 2 hops, `--hops`) over completed internal sessions from
  the host, flagging reachable hosts that themselves have High/Critical findings and use of
  SMB/RDP/SSH/WinRM/database ports.
- **Indicators**, graded in two levels:
  - *Lead:* a return connection from the host to an outside address that reached the vulnerable
    service; new lateral connections or uploads over 20 MB after that contact; an unblocked
    IPS/IDS alert on the vulnerable service; or a flagged host newly connecting to another host's
    vulnerable service (possible spread).
  - *Corroborated:* an unblocked alert on the vulnerable service **and** post-contact behavior from
    the host itself. Reports call this "likely exploitation". Without THREAT, notice or EVE alerts,
    nothing gets past "lead".
- **Score** = `CVSS × 10 × Exploit × Exposure × BlastRadius` (×1.25 corroborated, ×1.1 leads),
  capped at 100, mapped to P1 (act now) through P4 (routine). Every score carries a plain-English
  rationale and a written-out breakdown in the HTML report.
- **Coverage:** scanned hosts never seen on the wire, and active servers that were never scanned.

Tuning: `--internal-net CIDR` (repeatable) sets what counts as inside; `--min-severity 0-4` sets the
lowest Nessus severity scored (default 1, Low). Weights live at the top of `vulnflow/correlate.py`
(`LATERAL_PORTS`, `EXTERNAL_ZONES`, `EXFIL_BYTES`, `BROAD_REACH`).

## Explorer drawing and sampling

**Blast-radius likelihood** is a triage heuristic, not a measurement: `p = reach × weakness`.
Reach is 1.0 when the selected host opened completed sessions to the peer, 0.35 when only the peer
connects in, and 0 otherwise. Weakness is the strongest of: a vulnerability on a port the selected
host already uses (CVSS/10, ×1.0 with a public exploit, ×0.55 without), any other High or Critical
finding (CVSS/10 ×0.45 with exploit, ×0.25 without), an admin or lateral-movement protocol in use
(0.5), or a 0.1 baseline. Unscanned peers get at least 0.3 because their exposure is unknown.
Bands: High at 0.6 or more, Medium at 0.35 or more, otherwise Low. Onward connections multiply the
two steps.

**Attack paths** rank chains (internet origin, entry, first pivot, second pivot) built from the
same Explorer data; up to nine are drawn. **Simulate fix** assumes a host is fully fixed or
isolated, so no path passes through it; patching one CVE may cut fewer paths.

**Drawing limits.** In host focus, the first 24 peers per side are drawn large and labeled, and up
to 400 per side are drawn; the panel reaches every recorded IP. The 3D overview draws at most
2,000 hosts (the riskiest), 200 risky paths and 48 outside addresses; subnet totals still count
every host. The Timeline draws up to 20,000 flows; larger runs keep every blocked flow and every
flow to or from an alert or IOC address (up to half of that) and fill the rest with a fixed random
sample, and the view says so.

## Security Assistant

| Setting | Flag | Environment variable |
| --- | --- | --- |
| Provider (default `offline`) | `--llm-provider offline\|anthropic\|openai\|local` | `VULNFLOW_LLM_PROVIDER` |
| Model | `--llm-model` (required for `openai`) | `VULNFLOW_LLM_MODEL` |
| Endpoint | `--llm-base-url` | `VULNFLOW_LLM_BASE_URL` |
| API key | prompted without echo, or the settings page | `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, or `VULNFLOW_LLM_API_KEY` |
| Redact IPs and hostnames | `--redact` or the settings checkbox | `VULNFLOW_LLM_REDACT=1` |

```sh
python3 -m vulnflow analyze samples/scan_and_telemetry -o out --llm --llm-provider openai --llm-model <model>
python3 -m vulnflow brief out --llm-provider anthropic
python3 -m vulnflow ask out --llm-provider local --llm-model llama3.1
python3 -m vulnflow ask out --once "How do I confirm the web01 return connection in Zeek?"
python3 -m vulnflow article-briefs out --llm-provider openai --llm-model gpt-4.1-mini
```

- **Grounded.** A model gets the correlated results, never raw logs, and must cite host and
  plugin/CVE for each claim and say when the data does not answer a question. The `local`
  provider starts with the summary and top ten findings to fit smaller models.
- **Untrusted data.** Hostnames, application names and plugin output can be attacker-influenced.
  They are wrapped as data, the model is told never to follow instructions inside them, it has no
  tools, and its output is HTML-escaped.
- **Redaction.** `--redact` swaps every IP and hostname for a token everywhere in the text,
  including Nessus free text. The outgoing text is checked again and the request is refused if any
  address or known hostname survived. Answers are mapped back locally. Article briefs need exact
  IOCs, so redaction must be off for them.
- **Audit trail.** Every question and answer is appended to `ai_chat_log.md` in the run folder.
- **Built-in offline assistant.** `offline` (older name `mock`) uses fixed rules and templates over
  the results. It can't reason beyond the data; choose a model for open-ended questions.

## Processing limits

| Area | Current behavior |
| --- | --- |
| DuckDB memory | 60% of usable RAM (or cgroup limit), less if the machine is busy, keeping 25% (at least 1.5 GiB) free |
| DuckDB spill | Up to 80% of the working directory's free disk |
| Concurrency | One analysis per process (`VULNSCOPE_MAX_JOBS` to change) |
| Upload | 1 GB per upload (`serve --max-upload-mb`) |
| Compressed input | A `.gz` may expand to 200× its size, minimum 256 MB (`VULNSCOPE_MAX_GZ_BYTES`) |
| Article previews | 60 pages per run, 800 KB each |
| Article briefs | 20 articles per run, 18,000 characters each |
| Explorer | 2,000 hosts, 200 risky paths, 48 outside addresses in the 3D overview; 400 peers per side in focus |
| Timeline | 20,000 flows drawn |

A run that needs more memory or disk than it was given stops with a message naming the limit it
hit and how far it can be raised. [Configured limits](docs/LIMITS.md) lists every bound and where
it is set.

## Privacy and outbound network use

**A local interface does not make every feature offline.** VulnScope never contacts the hosts,
IPs or domains in your data: there are no DNS, reverse-DNS, WHOIS or geolocation lookups, no CVE
feed downloads and no update checks. Zeek reads captures offline. The only outbound connections are:

| Feature | When | What is sent | Stopped by `VULNSCOPE_OFFLINE=1` |
| --- | --- | --- | --- |
| IOC article previews | On by default, when matched IOCs carry source links | A request for each matched source article page (private addresses are refused) | **Yes** |
| Cloudflare Radar | Only with `CLOUDFLARE_RADAR_API_TOKEN` set, and only when you click **Check Cloudflare Radar** | The one IP or domain you selected, to `api.cloudflare.com` | No |
| Security Assistant | Only after you choose a non-offline provider | Correlated results, including IPs and hostnames unless redacted | No |
| Article briefs | Only when you click **Generate article briefs with OpenAI** | Each article page is fetched and its text sent to OpenAI | No |

`VULNSCOPE_OFFLINE=1` therefore turns off article previews only. On an air-gapped system, also
leave the Radar token unset and keep the Security Assistant on the built-in offline provider (or
a model on your own network via `local`). Docker's `.env.example` defaults to `VULNSCOPE_OFFLINE=0`.

API keys and the Radar token are held in server memory or the environment; they are never written
to reports, logs or the browser page. The theme choice is stored in the browser. Exports remain
wherever you save them and are not encrypted by VulnScope.

## Sources

| Source | VulnScope use |
| --- | --- |
| [Zeek](https://zeek.org) | Decodes packet captures locally into logs; bundled in the Docker image. |
| [DuckDB](https://duckdb.org) | Local SQL engine for de-duplication and correlation. |
| [Filebeat Zeek module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-zeek.html) | Field rename table used to restore Zeek records. |
| [Cloudflare Radar API](https://developers.cloudflare.com/radar/) | Optional ASN, location, rank and category context for one selected indicator. |
| IOC source articles | Public pages named in your IOC CSV, for previews and optional briefs. |
| Anthropic, OpenAI, or your own model server | Optional Security Assistant and article briefs. |

Radar results are context for investigation, not evidence of malicious activity, and do not change
scores. A Radar Read token does not grant access to Cloudflare's URL Scanner or Threat Intelligence
APIs. Confirm each service's terms for your evaluation and deployment.

## What VulnScope cannot establish

VulnScope cannot establish that a host is compromised, that a vulnerability was exploited, who an
attacker is, or that a host or service is safe. Network logs show what these sensors saw:

- Absence of traffic means "not observed by these sensors", which is why unseen hosts are scored as
  unknown rather than safe.
- Hosts are joined by IP. Scans run by hostname only, or DHCP churn during the telemetry window,
  reduce matches; NAT'd firewall logs should be exported with pre-NAT addresses.
- Zeek events outside `conn` and `notice`, including OT operations, are preserved and counted but do
  not affect scores yet. Vendor historian/PLC exports need a source-specific parser.
- "Likely exploitation" still needs confirmation on the host (EDR, memory, logs).
- Natural next steps: use Zeek `dns.log` for hostname-to-IP mapping, file evidence from
  `files.log`, and a Splunk/Elastic export target.
