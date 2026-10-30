# Múcaro VulnScope synthetic demos

## 250-host, three-article demo

This combines the existing 250-host sample with fabricated events on three of its hosts. A web server
receives a synthetic exploitation alert, then contacts addresses reported in [Sansec's StyleSmuggler
research](https://sansec.io/research/stylesmuggler-0day), including a large outbound transfer to a
reported C2 address. A Linux server matches indicators from [Unit 42's Linux campaign
research](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/), and a Windows
workstation matches [Microsoft's RedFlick research](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/).
The original web01 exploitation and outbound-upload storyline remains in the baseline sample.

The bundled `large_mucaro_archive.csv` is a **14-indicator, source-reviewed subset** of the supplied
60-day Múcaro export. It keeps this demo reproducible after the live 60-day window rotates. The
telemetry, scan result, and large transfer are fictional: the source articles do not document activity
on these demo hosts, and a large transfer is an investigation lead rather than proof of exfiltration.

```sh
python3 -m vulnflow analyze samples demo/large_mucaro_case \
  --ioc-archive demo/large_mucaro_archive.csv \
  --article-preview-cache demo/article_previews.json \
  -o demo/large_mucaro_output
```

The result has 250 scanned hosts and 14 exact IOC matches across three source articles. The web server
is a clearly labeled synthetic corroborated-exploitation scenario. Source links and short overviews
are saved in the executive report, technical report, and VulnScope Explorer.

## Two-host quick demo

The `mucaro_case/` folder contains **fabricated network events and inventory records** for two fictitious hosts. It demonstrates exact IOC matching, source article links, and short article previews in Múcaro VulnScope. An IOC match is an investigative lead; these events do not establish a real intrusion or attribution.

The bundled `mucaro_archive_subset.csv` keeps the 12 matched records from the user's 60-day Múcaro IOC Archive export, so this demo can be regenerated without the full export. The matched records link to two Sansec reports, [StyleSmuggler](https://sansec.io/research/stylesmuggler) and [StyleSmuggler 0day](https://sansec.io/research/stylesmuggler-0day), plus [SentinelOne's TraderTraitor research](https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/). No article text is copied into the synthetic telemetry.

Run the demo with the bundled archive subset, or replace it with a current full Múcaro export:

```sh
python3 -m vulnflow analyze demo/mucaro_case \
  --ioc-archive demo/mucaro_archive_subset.csv \
  --article-preview-cache demo/article_previews.json \
  -o demo/mucaro_case_output
```

The command creates standalone executive and technical reports, an Explorer, and a `results.json` snapshot. The three short, source-reviewed overviews used by this demo in `demo/article_previews.json` keep it repeatable offline; other matched article previews are fetched only when network access is available. If a source cannot be read, the drawer still shows the article link and says the preview is unavailable. Exported IOC associations should be reviewed against the source article before using them to make a security claim.
