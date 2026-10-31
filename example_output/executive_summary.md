# Múcaro VulnScope: Executive Summary

Prepared 2026-10-31. Network activity analysed from 2026-10-12T00:01:19Z to 2026-10-18T03:11:38Z.

## Bottom line

**Likely exploitation on web01.corp.example (10.10.1.10), web02.corp.example (10.10.1.11).** An IPS/IDS alert on a vulnerable service and the host's own traffic afterwards point the same way. Start incident response; host forensics is needed to confirm a compromise.

A flagged system later made new connections to vulnerable services on 2 other systems (fs01.corp.example (10.10.2.25), ws-031.corp.example (10.10.3.31)). If the first system is compromised, these are the likely next targets.

22 vulnerabilities on 21 systems need action now (Priority 1).

7 vulnerable services on 6 systems are being reached from the internet; 1 of them have a publicly available exploit.

Of 448 vulnerabilities reported by the scanner, 48 sit on services with no observed traffic and can be scheduled rather than rushed.

4 active servers seen on the network were not in the scan, so their risk is unknown.

28 observed indicators matched the imported Múcaro IOC Archive. Review the source reports and surrounding telemetry; a match alone does not confirm malicious activity.

## Key numbers

| Measure | Value |
|---|---|
| Systems scanned | 250 |
| Systems with vulnerabilities (Low and above) | 250 |
| Network sessions analysed | 9,782 |
| Priority 1 / 2 / 3 / 4 findings | 22 / 129 / 249 / 48 |
| Vulnerable services reached from the internet | 7 |
| Exploitable vulnerabilities with observed traffic | 28 |
| Systems with corroborated evidence / to investigate / possible next targets | 2 / 0 / 2 |
| Active servers missing from the scan | 4 |
| Múcaro IOC Archive matches | 28 |

## Top risks

1. **web01.corp.example (10.10.1.10)**: Apache 2.4.49 < 2.4.51 Path Traversal and RCE (CVE-2021-41773, CVE-2021-42013). Vulnerable service reached from the internet; public exploit exists; compromise could spread to 6 connected systems; **IPS alert and host traffic both point to exploitation**. Risk score 100/100, P1 - act now.
2. **web02.corp.example (10.10.1.11)**: Synthetic Magento StyleSmuggler finding (CVE-2026-75650). Vulnerable service reached from the internet; compromise could spread to 5 connected systems; **IPS alert and host traffic both point to exploitation**. Risk score 100/100, P1 - act now.
3. **app01.corp.example (10.10.1.20)**: Apache Tomcat AJP Connector Request Injection (Ghostcat) (CVE-2020-1938). Vulnerable service reached internally; public exploit exists; compromise could spread to 2 connected systems. Risk score 100/100, P1 - act now.
4. **app02.corp.example (10.10.2.30)**: Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (CVE-2021-44228). Vulnerable service reached internally by many hosts; public exploit exists; compromise could spread to 4 connected systems. Risk score 100/100, P1 - act now.
5. **app03.corp.example (10.10.2.31)**: Apache Log4j < 2.15.0 Remote Code Execution (Log4Shell) (CVE-2021-44228). Vulnerable service reached internally by many hosts; public exploit exists; compromise could spread to 2 connected systems. Risk score 100/100, P1 - act now.

## Recommended actions

1. **Start incident response for web01.corp.example (10.10.1.10), web02.corp.example (10.10.1.11).** Preserve logs and memory, confirm on the host, contain, then patch. Patching alone will not remove an attacker. Include fs01.corp.example (10.10.2.25), ws-031.corp.example (10.10.3.31) in the scope.
2. **Patch or shield high-risk internet-facing services within 48 hours**: web01.corp.example (10.10.1.10), web02.corp.example (10.10.1.11). If a patch cannot go in, restrict access at the firewall.
3. **Limit how far a breach can spread.** 120 high-priority systems can reach other vulnerable systems directly; restrict admin protocols (SMB, RDP, SSH) between these segments.
4. **Fix 145 internally reachable high-priority vulnerabilities** in the current patch cycle; they are the next step for an attacker already inside.
5. **Close the scan gap.** Add the 4 unscanned active servers to the scan scope so their exposure can be assessed.
6. **Schedule the remaining findings** through normal patching, and switch off services that no one is using.

## How confident is this?

The assessment combines the vulnerability scan with 9,782 observed network sessions. 249 of 250 scanned systems appeared in the network data. A system with no observed traffic is scored as "unknown" rather than safe. Telemetry only shows what the sensors could see, so absence of traffic is not proof that a service is unreachable.

Full evidence for every finding is in the technical report.

## Múcaro IOC matches

Exact matches to the imported IOC Archive are leads for review, not proof of malicious activity.

| Indicator | Type | Related hosts | Observed in | Source articles |
|---|---|---|---|---|
| 247.cdnflare.xyz | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| adsaw.cfd | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| adswre.cfd | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| beraskencur.site | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| bunstar.harej.si | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| byveo.org | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| checkout-cdn.com | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| groy.cc | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| magento.ink | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| microsoft-flash.com | domain | 10.10.3.49 | 1 dns event | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| my-662ylt3w.pages.dev | domain | 10.10.3.49 | 1 dns event | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| ntp.timesync.to | domain | 10.10.1.11 | 1 dns event | https://sansec.io/research/stylesmuggler-0day |
| secure-dns-hub.com | domain | 10.10.3.48 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| solidmonpe.com | domain | 10.10.2.42 | 1 dns event | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| trews.cfd | domain | 10.10.2.25 | 1 dns event | https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/ |
| wps-cn.com | domain | 10.10.3.49 | 1 dns event | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| 103.160.59.97 | ip | 10.10.3.48 | 2 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 103.245.231.248 | ip | 10.10.3.48 | 1 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 103.27.110.220 | ip | 10.10.3.49 | 1 network session | https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/ |
| 104.194.158.65 | ip | 10.10.2.42 | 2 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 104.248.131.53 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 109.224.53.140 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 138.68.244.146 | ip | 10.10.2.42 | 1 network session | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 185.157.160.251 | ip | 10.10.1.11 | 2 network session | https://sansec.io/research/stylesmuggler-0day |
| 2.57.241.246 | ip | 10.10.3.48 | 1 network session | https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/ |
| 209.141.43.95 | ip | 10.10.1.11 | 1 network session | https://sansec.io/research/stylesmuggler-0day |
| 209.73.130.148 | ip | 10.10.1.11 | 1 IDS/IPS alert, 2 network session | https://sansec.io/research/stylesmuggler-0day |
| 99.84.67.186 | ip | 10.10.1.11 | 3 network session | https://sansec.io/research/stylesmuggler-0day |
