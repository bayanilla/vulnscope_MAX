# Múcaro VulnScope synthetic sample

Choose one of the folders directly under `samples/`:

- `scan_and_telemetry/` contains the 250-host network telemetry, Nessus and CSV scan findings,
  five fabricated IOC storylines, and an IOC CSV that links exact matches to source articles.
- `telemetry_only/` contains the same network records without scan or IOC files: a generic flow CSV,
  Palo Alto firewall traffic and IPS alerts, NetFlow, Zeek connection, DNS, and Modbus logs, and a
  Zeek notice. Vulnerability status is therefore unknown, while connections and alerts remain visible.
- `hosts_onprem_and_aws/` is a separate, larger example: 4,324 hosts at a fictional company whose
  on-prem network extends into AWS. It has a Nessus scan of every host, Palo Alto firewall traffic
  and IPS alerts, a Zeek connection log, and AWS VPC Flow Logs for two VPCs. See
  [the host sample](#the-4324-host-sample-on-prem-and-aws) below.
- `gootloader_seo_poisoning/` replays one published intrusion, from a poisoned search result to the
  domain controllers, as Zeek, Suricata, Palo Alto and Nessus data for a fictional 115-host company.
  See [the Gootloader sample](#the-gootloader-sample-seo-poisoning-to-domain-control) below.
- `compare_two_companies/` is for **Compare reports**: six more sites of two fictional companies, one
  of them the Gootloader sample's company. `python3 -m vulnflow compare-sample` analyzes them as seven
  named reports and compares them. See [the Compare sample](#the-compare-sample-two-companies-seven-sites) below.

On the upload page, choose either subfolder under **Analyze files with Múcaro VulnScope** and click
**Analyze folder**. The scan-backed folder's executive report, technical report, and Explorer show
28 matched indicators across five source articles. Click a matched indicator to see its article
overview and full source link.

The repository also includes prebuilt reports in `example_output/`. Open
`example_output/explorer.html` locally to explore the same scenario immediately. GitHub's source
preview does not run the interactive HTML.

## Scenario

This combines the existing 250-host sample with fabricated events on five of its hosts. A web server
receives a synthetic exploitation alert, then contacts addresses reported in [Sansec's StyleSmuggler
research](https://sansec.io/research/stylesmuggler-0day), including a large outbound transfer to a
reported C2 address. A Linux server matches indicators from [Unit 42's Linux campaign
research](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/), and a Windows
workstation matches [Microsoft's RedFlick research](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/).
Another Windows host has DNS matches from [Microsoft's remote management abuse
research](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/),
and a second workstation matches delivery indicators from [Cisco Talos's Antino
research](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/).
The original web01 exploitation and outbound-upload storyline remains in the baseline sample.

### Small OT segment

Five of the 250 scanned hosts form a synthetic packaging line in `10.10.6.0/24`: an operator HMI
(`10.10.6.10`), engineering workstation (`10.10.6.11`), historian (`10.10.6.12`), and two PLCs
(`10.10.6.13` and `10.10.6.14`). Routine Zeek connections show the HMI polling the PLCs over
Modbus TCP and sending data to the historian; `modbus.log` records four read operations. An existing
VPN-pool laptop (`10.10.7.46`, `eng-lt01`) is the fictional engineer's remote machine. The firewall
traffic log records two allowed RDP sessions from that laptop to the OT engineering workstation
under the fictional `GlobalProtect-Engineer-VPN` policy, from the VPN zone to the OT zone. This is
legitimate remote engineering access and does not itself suggest compromise. The laptop and
workstation also make two and three outbound HTTPS sessions, respectively, to the same reserved
example address
`198.51.100.77`. In the fictional story the laptop is the presumed initial foothold; the shared
external contact is a **C2-like investigation lead**, not proof that either host was compromised.
There is no suspicious PLC-control action or observed physical process change in the sample.
Both sample folders contain this network telemetry; only `scan_and_telemetry/` contains the scan.

| Demo host | Exact IOC matches | Source article |
| --- | ---: | --- |
| web02 (10.10.1.11) | 7 | Sansec StyleSmuggler |
| mon01 (10.10.2.42) | 7 | Unit 42 Linux campaign |
| ws-048 (10.10.3.48) | 6 | Microsoft RedFlick |
| fs01 (10.10.2.25) | 4 | Microsoft remote management abuse |
| ws-049 (10.10.3.49) | 4 | Cisco Talos Antino |

The bundled `scan_and_telemetry/ioc_indicators.csv` is a **28-indicator, source-reviewed sample** with article links.
It keeps this demo reproducible. The
telemetry, scan result, and large transfer are fictional: the source articles do not document activity
on these demo hosts, and a large transfer is an investigation lead rather than proof of exfiltration.

```sh
python3 -m vulnflow analyze samples/scan_and_telemetry \
  --article-preview-cache samples/scan_and_telemetry/article_previews.json \
  -o example_output

python3 -m vulnflow analyze samples/telemetry_only -o telemetry_output
```

The scan-backed result has 250 scanned hosts and 28 exact IOC matches across five source articles.
The telemetry-only result keeps the same observed connections and alerts, but has no vulnerability
findings or scores. The web server is a clearly labeled synthetic corroborated-exploitation scenario.
Source links and short overviews
are saved in the executive report, technical report, and VulnScope Explorer. In Explorer, cyan rings
mark linked IP traffic nodes. Domain matches appear as cyan `D` markers above the selected host;
their dashed lines represent observed DNS queries, not confirmed connections. Click either marker to
open the saved article overview.

The bundled `scan_and_telemetry/article_previews.json` provides short source overviews for repeatable offline command-line
runs. The upload page fetches available overviews when it analyzes the folder; if a source cannot be
read, its full article link still appears. Exported IOC associations should be reviewed against each
source article before using them to make a security claim.

## The 4,324-host sample (on-prem and AWS)

`hosts_onprem_and_aws/` is generated by `vulnflow/sample_hosts.py` and is unrelated to the 250-host
story above. Every name and address is fictional; outside addresses come from reserved
documentation and benchmarking ranges plus a few service-provider ranges.

| Where | Hosts | What is there |
| --- | ---: | --- |
| On-prem `10.40.0.0/16` (`hq.example`) | 3,911 | Domain controllers, DNS, DHCP, two PAN-OS firewalls, Cisco switches, Wi-Fi controllers; 360 servers (VMware ESXi and vCenter, SQL, Oracle, file, print, backup, monitoring, SIEM, Git, on-prem Kubernetes); 2,400 Windows desktops, 400 Macs, 120 Linux developer machines; 300 VoIP phones, 60 printers, 80 Wi-Fi access points, 90 cameras, 72 building devices (badge readers, HVAC, UPS, lobby screens) |
| AWS prod VPC `10.60.0.0/16` (us-east-2) | 280 | Web, API, worker and batch EC2 instances, EKS nodes, bastions, RDS, ElastiCache and MSK endpoints |
| AWS dev VPC `10.61.0.0/16` (us-west-2) | 133 | Developer instances, EKS nodes, CI runners, AD domain controllers, a bastion and sandbox instances |

The AWS VPCs connect to the office over a site-to-site VPN that ends on the firewall's `aws` zone, so
office-to-cloud traffic appears in the firewall log and traffic inside AWS appears in
`aws_vpcflow_prod_us-east-2.log` and `aws_vpcflow_dev_us-west-2.log` (default version 2 flow log
format). All 4,324 hosts are in `estate_scan.nessus` and in the network logs, so a run reports
4,324 scanned hosts, all of them seen.

`network_map.csv` names the three ranges (HQ on-prem, AWS prod, AWS dev). It is optional; the
Explorer uses it to mark the AWS subnets and hosts and the reports add a Networks table. Remove it
to see the same run without network names.

Fictional investigation leads in the data:

- `fw01` (GlobalProtect, CVE-2024-3400 in the scan) receives four exploit attempts that the IPS resets.
- `web-prod-07` in AWS (Log4Shell on 443 in the scan) is reached by `203.0.113.66`, then connects
  back to it on port 4444 and later sends it about 46 MB. There is no IPS in AWS, so this is a lead
  to investigate, not corroborated exploitation.
- `sbx-dev-03` has SSH open to the internet; a burst of attempts arrives and three are accepted.
- Some desktops reach the OpenSLP service on ESXi hosts that the scan flags for CVE-2021-21974.

The Explorer draws at most 2,000 hosts. With this sample it draws the riskiest 2,000 of the hosts with
findings (hosts with leads first, then by priority and score); subnet totals still count every host.

```sh
python3 -m vulnflow analyze samples/hosts_onprem_and_aws -o hosts_output
```

## The Gootloader sample (SEO poisoning to domain control)

`gootloader_seo_poisoning/` is generated by `vulnflow/sample_gootloader.py`. It replays the intrusion in
The DFIR Report's [SEO Poisoning to Domain Control: The Gootloader Saga Continues](https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/)
(2024-02-26) against a fictional company, `ridgeline.example`: nine servers in `10.20.0.0/24`, 100
workstations in `10.20.10.0/24` and six printers. Times follow the report's relative timeline; the dates,
host names, the user and every internal address are invented.

| When (UTC) | What the data shows |
| --- | --- |
| 26 Oct 14:02 | `hr-ws-07` (10.20.10.27) searches, then downloads a zip over HTTPS from a fictional poisoned blog. |
| 14:04 to 23:02 | Gootloader polls ten compromised WordPress sites (`/xmlrpc.php`) every 35 to 55 minutes: DNS, TLS and two plain-HTTP sites answering 405. |
| 23:02 | The weaponized server `46.28.105.94` answers 200 with the payload; the firewall alerts. |
| 23:04 | Cobalt Strike HTTPS beacon to `91.215.85.143:443` (22-second sleep, 37% jitter). |
| 23:12 to 23:17 | LDAP (389, 3268) to both domain controllers, then a burst of port-445 probes. |
| 23:22 to 23:51 | Remote service (svcctl) and a beacon `.exe` copied over SMB to `dc01` (twice: Defender blocks the first), `dc02`, `fs01` and `sql01`; Zeek `files.log` has the report's beacon hashes. `dc01` starts its own HTTPS beacon. |
| 27 Oct 00:35 | SystemBC SOCKS5 tunnel to `91.92.136.20:4001`, then RDP through it to `dc01`. |
| 00:52 to 01:20 | Advanced IP Scanner sweep from `dc01`; the attacker opens `IT$\Passwords.xlsx` on `fs01`. |
| 01:18 to 01:30 | WinRM, then RDP, to `backup01`; `s5.ps1` copied over SMB; SystemBC and a beacon start there. |
| 02:00 to 06:00 | Quiet: the beacons slow to every five minutes. |
| 06:05 to 11:05 | Hands-on review of the file share and backup settings over RDP, then the activity stops. |

Files: Zeek `conn.log`, `dns.log`, `http.log`, `ssl.log` (a sample of the beacon sessions, with the
report's JA3/JA3S) and `files.log`; Suricata `suricata_eve.json` with the ET signature names the report
lists (the signature ids are local placeholders); Palo Alto `paloalto_traffic.csv` with traffic and
threat rows (Start Time filled in, so each alert keeps its own time); `domain_scan.nessus`; and
`ioc_indicators.csv`, the report's published domains, URLs, addresses and file hashes with a link to the
report. Outside addresses are documentation and benchmarking ranges, except the three the report
publishes as indicators, which appear in the traffic so they match. Which server received which beacon
file is fictional. The network data cannot show what happened inside a host (registry payloads,
`getsystem`, LSASS access); the report covers that.

```sh
python3 -m vulnflow analyze samples/gootloader_seo_poisoning \
  --article-preview-cache samples/gootloader_seo_poisoning/article_previews.json -o gootloader_output
```

The run reports 115 scanned hosts, 23 IDS/IPS alerts and 25 IOC matches (ten domains, three addresses
and the twelve hashes of the four beacons). In the Explorer, `hr-ws-07` carries the IOC matches and its
beacon; the domain controllers, `fs01`, `sql01` and `backup01` are leads because alerts fired on SMB
services the scan flags. The Timeline shows nine hours of Gootloader polling, the burst of alerts at the
payload and the steady beacon traffic after it.

## The Compare sample (two companies, seven sites)

`compare_two_companies/` is generated by `vulnflow/sample_compare.py`. It gives **Compare reports**
something to find: two fictional companies, one report per site, with indicators and vulnerabilities
that show up at more than one site and in both companies. One command analyzes the seven sites into
the upload page's data folder, names each report and sets its network, and saves a comparison of all
seven:

```sh
python3 -m vulnflow compare-sample                       # into vulnflow_runs/, the upload page's default
python3 -m vulnflow compare-sample --data-dir my_runs    # the folder you pass to serve --data-dir
docker compose run --rm vulnscope compare-sample         # Docker: the runs folder the upload page uses
```

It takes a few seconds and never goes online. On the upload page, **Compare reports** then lists the
seven reports, ready to tick for a comparison of your own, and the saved comparison under **Earlier
comparisons**. Run it again and it says the reports are already there; `--again` adds another set.

| Report (network) | Folder | What happens (26 to 27 Oct 2026, UTC) |
| --- | --- | --- |
| Ridgeline HQ (Ridgeline) | `gootloader_seo_poisoning/` | The Gootloader sample, unchanged. |
| Ridgeline Denver office (Ridgeline) | `ridgeline_denver/` | `dc01`'s Advanced IP Scanner sweep reaches the office over the site VPN. On 27 Oct at 07:20 the attacker opens RDP from `dc01` to `den-fs01`, copies the same Cobalt Strike beacon over SMB (Suricata alerts, the report's hashes in `files.log`), and `den-fs01` calls the report's C2 `91.215.85.143` through the office's own internet line until the activity stops at 11:05. |
| Ridgeline Tampa office (Ridgeline) | `ridgeline_tampa/` | Only the sweep. |
| Corvane HQ (Corvane) | `corvane_hq/` | 01:40 port sweep and content discovery on the public servers; 02:10 brute force of the partner portal; 02:16 a credential works and user lists, email lists and application data are pulled (38.5 MB in the largest session), admin accounts and an API token created; the token is used every few hours until 27 Oct 10:00. |
| Corvane Phoenix plant (Corvane) | `corvane_phoenix/` | 03:05 VPN login with a leaked group password; a port scan, a password spray on the file server, directory lookups and RDP tries, then hours of file reads; back on 27 Oct 01:10 for more files. |
| Corvane Austin design center (Corvane) | `corvane_austin/` | 04:55 VPN login; a port scan, Jenkins probed (an IPS alert for CVE-2024-23897), SSH to the build server, source code cloned from GitLab, tools fetched from the staging server; back on 27 Oct 06:30 for more code. Separately, at 16:20 a user looking for an agreement template lands on two Gootloader sites, which the firewall blocks. |
| Corvane Dresden service center (Corvane) | `corvane_dresden/` | The group password was changed here: only failed VPN logins, on both days. |

Each site folder has Zeek `conn.log` and `dns.log` (Corvane HQ, Austin and Denver also `ssl.log`,
Denver `files.log`), Palo Alto traffic and threat rows, a Nessus scan, an IOC CSV and its article
previews; the Ridgeline offices also have Suricata alerts. The IOC CSV holds both reports' indicators, as a service provider's one
feed for every client would, except in Dresden, whose list (like the Gootloader sample's own) is from
before Unit 42's report.

**Where it comes from.** Ridgeline's head office is the Gootloader sample; the two branches and
everything in them are invented, since The DFIR Report describes one site. Corvane, a semiconductor
equipment supplier, follows Unit 42's
[Attackers Use Autonomous AI to Target Semiconductor, Defense and Civil Society Sectors](https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/)
(2026-11-12): CL-STA-1238 ran a customized fork of the open-source Cairn AI penetration-testing
framework, whose agents brute-forced a production credential on one semiconductor company's
partner-integration application, pulled data and user and email lists, and created administrator
accounts and a persistent API token, and whose task for a semiconductor equipment supplier carried
VPN gateway addresses, group names and shared group passwords for several sites. The report publishes
two addresses and no other indicators: the Cairn server `154.44.31.4` and the staging and attack-egress
node `82.29.129.54`. Here every attack session comes from `82.29.129.54`; `154.44.31.4` is only in the
IOC list. Which site saw what, the times, the volumes and the bursts of machine-paced requests are
invented. Internal addresses overlap on purpose: both head offices put their servers in
`10.20.0.0/24`, and Compare never matches internal addresses.

**What the comparison shows.** 7 reports from 2 networks; 7 of 26 IOCs and 9 of 21 vulnerabilities
are in more than one report.

- `82.29.129.54` in all four Corvane reports: the public servers at HQ, the VPN gateways in Phoenix
  and Austin, and Austin's build server. In Dresden only the re-hunt finds it (34 failed VPN
  logins), since that report was analyzed without the indicator.
- `my-little-kitchen.com` and `pocketofpreschool.com` in both companies: Ridgeline HQ's `hr-ws-07`
  and Austin's `aus-ws-14`. Corvane HQ's `eng-ws-07` has the same address as `hr-ws-07`, 10.20.10.27,
  and is not counted with it.
- `91.215.85.143` and the beacon's three hashes in Ridgeline HQ and Denver.
- IKE Aggressive Mode on the three Corvane site VPN gateways; SMB signing, Microsoft Edge and the
  Print Spooler at every site, in both companies.

On **Open all networks in the Explorer**, SMB signing alone lights up 340 of the 424 hosts, so pick
`82.29.129.54` or a Gootloader domain under **Shared items** to see one item's hosts in every network.
Each report also opens on its own: Corvane HQ's leads are `www01` and `partners01`, Phoenix's is
`phx-fs01`, Austin's is `build01`, and Dresden has none.
