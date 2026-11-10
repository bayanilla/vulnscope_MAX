# Múcaro VulnScope synthetic sample

Choose one of the three folders directly under `samples/`:

- `scan_and_telemetry/` contains the 250-host network telemetry, Nessus and CSV scan findings,
  five fabricated IOC storylines, and an IOC CSV that links exact matches to source articles.
- `telemetry_only/` contains the same network records without scan or IOC files: a generic flow CSV,
  Palo Alto firewall traffic and IPS alerts, NetFlow, Zeek connection, DNS, and Modbus logs, and a
  Zeek notice. Vulnerability status is therefore unknown, while connections and alerts remain visible.
- `hosts_onprem_and_aws/` is a separate, larger example: 4,324 hosts at a fictional company whose
  on-prem network extends into AWS. It has a Nessus scan of every host, Palo Alto firewall traffic
  and IPS alerts, a Zeek connection log, and AWS VPC Flow Logs for two VPCs. See
  [the host sample](#the-4324-host-sample-on-prem-and-aws) below.

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
