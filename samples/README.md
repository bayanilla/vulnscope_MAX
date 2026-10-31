# Múcaro VulnScope synthetic sample

This one folder contains the 250-host sample telemetry and scan, five fabricated IOC storylines,
and the Múcaro IOC Archive CSV that links exact matches to source articles. On the upload page,
choose `samples` under **Analyze files with Múcaro VulnScope** and click **Analyze folder**.
The resulting executive report, technical report, and Explorer show 28 matched indicators across
five source articles. Click a matched indicator to see its article overview and full source link.

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

| Demo host | Exact archive matches | Source article |
| --- | ---: | --- |
| web02 (10.10.1.11) | 7 | Sansec StyleSmuggler |
| mon01 (10.10.2.42) | 7 | Unit 42 Linux campaign |
| ws-048 (10.10.3.48) | 6 | Microsoft RedFlick |
| fs01 (10.10.2.25) | 4 | Microsoft remote management abuse |
| ws-049 (10.10.3.49) | 4 | Cisco Talos Antino |

The bundled `mucaro_ioc_archive.csv` is a **28-indicator, source-reviewed subset** of the supplied
60-day Múcaro export. It keeps this demo reproducible after the live 60-day window rotates. The
telemetry, scan result, and large transfer are fictional: the source articles do not document activity
on these demo hosts, and a large transfer is an investigation lead rather than proof of exfiltration.

```sh
python3 -m vulnflow analyze samples \
  --article-preview-cache samples/article_previews.json \
  -o example_output
```

The result has 250 scanned hosts and 28 exact IOC matches across five source articles. The web server
is a clearly labeled synthetic corroborated-exploitation scenario. Source links and short overviews
are saved in the executive report, technical report, and VulnScope Explorer. In Explorer, cyan rings
mark linked IP traffic nodes. Domain matches appear as cyan `D` markers above the selected host;
their dashed lines represent observed DNS queries, not confirmed connections. Click either marker to
open the saved article overview.

The bundled `article_previews.json` provides short source overviews for repeatable offline command-line
runs. The upload page fetches available overviews when it analyzes the folder; if a source cannot be
read, its full article link still appears. Exported IOC associations should be reviewed against each
source article before using them to make a security claim.
